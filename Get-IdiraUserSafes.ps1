<#
.SYNOPSIS
    Lists every Safe (name + description) that a given Idira PAM end user is a
    member of, either directly or through Vault / Active Directory group membership.

.DESCRIPTION
    Works with self-hosted Idira PAM (formerly CyberArk PAM; PVWA REST API, v14.6 and later).

      1. Logs on to the PVWA REST API (Idira Vault, LDAP or RADIUS authentication)
      2. Works out which groups the target user belongs to:
           - Vault:  Idira Vault group membership from the Users API (groupsMembership)
           - AD:     nested AD security group membership (tokenGroups) queried directly
                     from Active Directory. No RSAT / ActiveDirectory module needed.
      3. Gets all Safes, then the members of each Safe
      4. Matches the user's name and group names against each Safe's members
      5. Logs off in a 'finally' block, so the session is closed even if the script fails

    PERMISSIONS NEEDED BY THE ACCOUNT RUNNING THE SCRIPT
      - It must be able to see all Safes and their members, for example as a member of
        the 'Auditors' or 'Vault Admins' group, or with 'List accounts' and
        'View Safe members' on every Safe. The API only returns the Safes that the
        logged-on user can see.
      - 'Audit users' Vault authorization, to read the target user's group membership.
      - For -GroupSource AD or Both: run the script on a domain-joined machine as an
        account that can read the target user object in AD.

.PARAMETER PVWAUrl
    Base PVWA URL, e.g. https://pvwa.company.com (without /PasswordVault).

.PARAMETER TargetUser
    The end user to report on, e.g. jdoe, jdoe@company.com or COMPANY\jdoe.

.PARAMETER AuthType
    The authentication method of the account running the script: Idira (Vault-native users), LDAP or RADIUS.
    'Idira' calls the /auth/CyberArk/Logon endpoint, because the REST API path
    still uses the old product name.

.PARAMETER GroupSource
    Where the target user's group membership comes from: Vault, AD or Both (the default).

.PARAMETER ADDomain
    Optional. The AD domain or domain controller to query, e.g. company.com.
    Defaults to the domain of the machine running the script.

.EXAMPLE
    .\Get-IdiraUserSafes.ps1 -PVWAUrl https://pvwa.company.com -TargetUser jdoe -AuthType LDAP

.EXAMPLE
    .\Get-IdiraUserSafes.ps1 -PVWAUrl https://pvwa.company.com -TargetUser jdoe `
        -AuthType Idira -ExportCsv C:\Temp\jdoe_safes.csv -SkipCertificateCheck
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PVWAUrl,
    [Parameter(Mandatory = $true)][string]$TargetUser,
    [ValidateSet('Idira', 'LDAP', 'RADIUS')][string]$AuthType = 'Idira',
    [System.Management.Automation.PSCredential]$Credential,
    [ValidateSet('Vault', 'AD', 'Both')][string]$GroupSource = 'Both',
    [string]$ADDomain,
    [string]$ExportCsv,
    [switch]$SkipCertificateCheck,
    [ValidateRange(1, 1000)][int]$PageSize = 500
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$BaseUri = ($PVWAUrl.TrimEnd('/')) + '/PasswordVault/API'
$script:Headers = @{}

#region ---------- Helpers ----------

# Only for lab or test servers with self-signed certificates. Don't use this in production.
if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -lt 6) {
    if (-not ('TrustAllCertsPolicy' -as [type])) {
        Add-Type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
    }
    [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

function Invoke-PAS {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [ValidateSet('GET', 'POST', 'PUT', 'DELETE')][string]$Method = 'GET',
        $Body
    )
    $params = @{
        Uri         = $Uri
        Method      = $Method
        Headers     = $script:Headers
        ContentType = 'application/json'
        TimeoutSec  = 120
    }
    if ($null -ne $Body) { $params.Body = ($Body | ConvertTo-Json -Depth 5) }
    if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -ge 6) { $params.SkipCertificateCheck = $true }

    try {
        Invoke-RestMethod @params
    }
    catch {
        $detail = $_.ErrorDetails.Message
        throw "REST call failed [$Method $Uri]: $($_.Exception.Message) $detail"
    }
}

# Removes the domain part: COMPANY\jdoe -> jdoe, jdoe@company.com -> jdoe
function Get-BaseName([string]$Name) {
    if ($Name -match '\\') { $Name = ($Name -split '\\')[-1] }
    if ($Name -match '@') { $Name = ($Name -split '@')[0] }
    return $Name
}

# Gets all pages from a paged Idira PVWA list endpoint (one that returns value / count)
function Get-PASPaged {
    param([Parameter(Mandatory = $true)][string]$Uri)
    $all = New-Object System.Collections.Generic.List[object]
    $offset = 0
    $sep = if ($Uri -match '\?') { '&' } else { '?' }
    do {
        $resp = Invoke-PAS -Uri "$Uri$($sep)offset=$offset&limit=$PageSize"
        $page = @($resp.value)
        foreach ($p in $page) { $all.Add($p) }
        $offset += $PageSize
        $total = if ($resp.PSObject.Properties['count']) { [int]$resp.count } else { -1 }
    } while ($page.Count -eq $PageSize -and ($total -lt 0 -or $offset -lt $total))
    return $all
}

# Gets the user's nested AD security group membership (tokenGroups) and returns the group names
function Get-ADGroupNames {
    param([string]$SamAccountName, [string]$Domain)

    $escaped = $SamAccountName -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    if ($Domain) { $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain") }
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$escaped))"
    [void]$searcher.PropertiesToLoad.Add('distinguishedName')

    $result = $searcher.FindOne()
    if (-not $result) {
        Write-Warning "AD user '$SamAccountName' was not found in AD. Skipping the AD group lookup."
        return @()
    }

    $entry = $result.GetDirectoryEntry()
    $entry.RefreshCache([string[]]@('tokenGroups'))   # includes nested groups

    $names = New-Object System.Collections.Generic.List[string]
    foreach ($sidBytes in $entry.Properties['tokenGroups']) {
        try {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
            $nt = $sid.Translate([System.Security.Principal.NTAccount]).Value   # DOMAIN\Group
            $names.Add((Get-BaseName $nt))
        }
        catch { }   # SIDs that can't be resolved are skipped
    }
    return $names
}

#endregion

try {
    #region ---------- 1. Logon ----------
    if (-not $Credential) { $Credential = Get-Credential -Message "Idira PAM $AuthType logon" }

    Write-Host "Logging on to $PVWAUrl ($AuthType)..." -ForegroundColor Cyan
    $logonBody = @{
        username          = $Credential.UserName
        password          = $Credential.GetNetworkCredential().Password
        concurrentSession = $true
    }
    # The REST API path still uses the old name for Vault-native authentication
    $authPath = if ($AuthType -eq 'Idira') { 'CyberArk' } else { $AuthType }
    $token = Invoke-PAS -Uri "$BaseUri/auth/$authPath/Logon" -Method POST -Body $logonBody
    $logonBody.password = $null
    if (-not $token) { throw 'Logon returned no session token.' }
    $script:Headers = @{ Authorization = $token }
    Write-Host 'Logged on.' -ForegroundColor Green
    #endregion

    #region ---------- 2. Get the target user's identity and groups ----------
    $targetBase = Get-BaseName $TargetUser
    $userNames = @($TargetUser, $targetBase) | Select-Object -Unique
    $groupNames = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $groupSourceMap = @{}   # group name -> 'Vault' / 'AD'

    if ($GroupSource -in 'Vault', 'Both') {
        Write-Host "Looking up Vault group membership for '$TargetUser'..." -ForegroundColor Cyan
        $search = [uri]::EscapeDataString($targetBase)
        $users = @((Invoke-PAS -Uri "$BaseUri/Users?search=$search").Users)
        $vaultUser = $users | Where-Object {
            $_.username -ieq $TargetUser -or $_.username -ieq $targetBase -or (Get-BaseName $_.username) -ieq $targetBase
        } | Select-Object -First 1

        if ($vaultUser) {
            $userNames = @($userNames + $vaultUser.username) | Select-Object -Unique
            $details = Invoke-PAS -Uri "$BaseUri/Users/$($vaultUser.id)"
            foreach ($g in @($details.groupsMembership)) {
                if ($g.groupName -and $groupNames.Add($g.groupName)) { $groupSourceMap[$g.groupName] = "Vault ($($g.groupType))" }
            }
            Write-Host "  Vault user found: $($vaultUser.username) (id $($vaultUser.id)), $(@($details.groupsMembership).Count) Vault group(s)."
        }
        else {
            Write-Warning "User '$TargetUser' is not in the Vault yet. LDAP users are added the first time they log on."
        }
    }

    if ($GroupSource -in 'AD', 'Both') {
        Write-Host "Looking up AD group membership for '$targetBase'..." -ForegroundColor Cyan
        foreach ($g in (Get-ADGroupNames -SamAccountName $targetBase -Domain $ADDomain)) {
            if ($groupNames.Add($g)) { $groupSourceMap[$g] = 'AD' }
        }
    }
    Write-Host "  Total groups to match: $($groupNames.Count)"
    #endregion

    #region ---------- 3. Get all Safes ----------
    Write-Host 'Getting Safes...' -ForegroundColor Cyan
    $safes = Get-PASPaged -Uri "$BaseUri/Safes?includeAccounts=false"
    Write-Host "  $($safes.Count) Safe(s) visible to the logged-on user."
    #endregion

    #region ---------- 4. Check each Safe's members ----------
    $report = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($safe in $safes) {
        $i++
        Write-Progress -Activity 'Checking Safe members' -Status $safe.safeName -PercentComplete (($i / [math]::Max($safes.Count, 1)) * 100)

        try {
            $filter = [uri]::EscapeDataString('includePredefinedUsers eq true')
            $members = Get-PASPaged -Uri "$BaseUri/Safes/$($safe.safeUrlId)/Members?filter=$filter"
        }
        catch {
            Write-Warning "Can't read the members of Safe '$($safe.safeName)': $($_.Exception.Message)"
            continue
        }

        $memberHits = foreach ($m in $members) {
            if ($m.memberType -eq 'User' -and ($userNames -icontains $m.memberName -or (Get-BaseName $m.memberName) -ieq $targetBase)) {
                [pscustomobject]@{ Type = 'Direct'; Via = '' }
            }
            elseif ($m.memberType -eq 'Group') {
                $gName = $m.memberName
                $hit = if ($groupNames.Contains($gName)) { $gName } elseif ($groupNames.Contains((Get-BaseName $gName))) { Get-BaseName $gName }
                if ($hit) { [pscustomobject]@{ Type = 'Group'; Via = "$gName [$($groupSourceMap[$hit])]" } }
            }
        }

        if ($memberHits) {
            $direct = @($memberHits | Where-Object Type -eq 'Direct').Count -gt 0
            $viaGroups = ($memberHits | Where-Object Type -eq 'Group' | Select-Object -ExpandProperty Via -Unique) -join '; '
            $report.Add([pscustomobject]@{
                    SafeName    = $safe.safeName
                    Description = $safe.description
                    AccessType  = if ($direct -and $viaGroups) { 'Direct + Group' } elseif ($direct) { 'Direct' } else { 'Group' }
                    ViaGroups   = $viaGroups
                })
        }
    }
    Write-Progress -Activity 'Checking Safe members' -Completed
    #endregion

    #region ---------- 5. Output ----------
    Write-Host "`n'$TargetUser' is a member of $($report.Count) Safe(s):" -ForegroundColor Green
    $report | Sort-Object SafeName | Format-Table -AutoSize -Wrap

    if ($ExportCsv) {
        $report | Sort-Object SafeName | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
        Write-Host "Exported to $ExportCsv" -ForegroundColor Green
    }
    #endregion
}
catch {
    Write-Error $_
}
finally {
    #region ---------- 6. Logoff ----------
    if ($script:Headers.ContainsKey('Authorization')) {
        try {
            Invoke-PAS -Uri "$BaseUri/Auth/Logoff" -Method POST | Out-Null
            Write-Host 'Logged off from the PVWA session.' -ForegroundColor Cyan
        }
        catch { Write-Warning "Logoff failed: $($_.Exception.Message)" }
        $script:Headers = @{}
    }
    #endregion
}
