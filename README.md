# CyberArk Safe Membership Report

This PowerShell script lists every **Safe**, with its name and description, that a CyberArk PAM end user can access, either **directly** or through **Vault or Active Directory group membership**. It uses the PVWA REST API.

It works with self-hosted CyberArk PAM, v14.6 and later, on Windows PowerShell 5.1 and PowerShell 7+.

## What it does

1. **Logs on** to the PVWA REST API: `POST /PasswordVault/API/auth/{CyberArk|LDAP|RADIUS}/Logon`.
2. **Finds the target user's groups:**
   - **Vault groups:** from `GET /API/Users?search=` and then `GET /API/Users/{id}`, which lists the user's groups.
   - **AD groups:** nested security groups read straight from Active Directory (`tokenGroups`). This uses .NET, so the ActiveDirectory module isn't needed.
3. **Gets all Safes**, page by page: `GET /API/Safes`.
4. **Gets each Safe's members**: `GET /API/Safes/{safeUrlId}/Members`. It then matches them against the user's name and groups.
5. **Logs off**: `POST /API/Auth/Logoff`. This runs in a `finally` block, so the session is closed even if the script fails.

## Usage

```powershell
# Log on as an LDAP user and report on jdoe
.\Get-CyberArkUserSafes.ps1 -PVWAUrl https://pvwa.company.com -TargetUser jdoe -AuthType LDAP

# Log on as a Vault-native user and export the results to CSV
.\Get-CyberArkUserSafes.ps1 -PVWAUrl https://pvwa.company.com -TargetUser jdoe `
    -AuthType CyberArk -ExportCsv C:\Temp\jdoe_safes.csv
```

| Parameter | Description |
|---|---|
| `-PVWAUrl` | Base PVWA URL, without `/PasswordVault` |
| `-TargetUser` | The end user to report on: `jdoe`, `jdoe@company.com` or `COMPANY\jdoe` |
| `-AuthType` | `CyberArk` (Vault-native users), `LDAP` or `RADIUS` |
| `-Credential` | Optional `PSCredential`. If you leave it out, the script asks for one |
| `-GroupSource` | Where group membership comes from: `Vault`, `AD` or `Both` (the default) |
| `-ADDomain` | Optional AD domain or domain controller to query |
| `-ExportCsv` | Optional path for a CSV file of the results |
| `-SkipCertificateCheck` | For lab servers with self-signed certificates only |
| `-PageSize` | Number of items per API page (1–1000, default 500) |

The output has one row per Safe with these columns: `SafeName`, `Description`, `AccessType` (Direct / Group / Direct + Group) and `ViaGroups`.

## Permissions needed

- The account running the script must be able to see **all Safes and their members**, for example as a member of Auditors or Vault Admins. The API returns only the Safes that account can see, so with less access the report is incomplete without any error.
- The account needs the **Audit users** Vault authorization to read the target user's group membership.
- For AD group lookups, run the script on a **domain-joined** machine as an account that can read the user object.

## Notes and limitations

- **Run time:** the script makes one API call per Safe. With about 5,000 Safes, one run takes roughly 8–25 minutes. To report on many users, use a bulk design that downloads all Safe members once and reuses them, instead of running this script once per user.
- **Matching AD groups:** groups are matched by their short name (sAMAccountName). If your LDAP directory mapping names groups differently (for example by CN), check that the names line up.
- **LDAP users who have never logged on** aren't in the Vault yet. The Vault group lookup warns and finds nothing for them, but the AD lookup still works.
