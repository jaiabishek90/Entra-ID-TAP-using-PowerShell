# New-EntraTAP.ps1

Generates Entra ID **Temporary Access Passes (TAP)** via Microsoft Graph using app-only certificate authentication. Supports single-user and bulk-from-CSV modes, with optional control over lifetime, one-time-use, and start time.

## Prerequisites

- PowerShell 5.1+ or PowerShell 7+
- `Microsoft.Graph.Authentication` module: `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`
- An Entra app registration with **Application** permission `UserAuthenticationMethod.ReadWrite.All` (admin-consented)
- A certificate uploaded to the app registration, with the matching private key in `CurrentUser\My` or `LocalMachine\My`
- The **Temporary Access Pass** authentication method enabled in your tenant (Entra admin center → Protection → Authentication methods), with target users in scope

> The caller's effective permissions still apply. Creating a TAP for a privileged-role member additionally requires the app/principal to hold a sufficient directory role.

## Setup

1. **Create the app registration** in Entra ID → App registrations → New registration.
2. **Add the application permission** `UserAuthenticationMethod.ReadWrite.All` under API permissions → Microsoft Graph → Application permissions, then **Grant admin consent**.
3. **Generate / upload a certificate.** To create a self-signed one for testing:
   ```powershell
   $cert = New-SelfSignedCertificate -Subject "CN=EntraTAP" -CertStoreLocation "Cert:\CurrentUser\My" `
       -KeyExportPolicy Exportable -KeySpec Signature -NotAfter (Get-Date).AddYears(1)
   Export-Certificate -Cert $cert -FilePath .\EntraTAP.cer
   ```
   Upload `EntraTAP.cer` to the app registration → Certificates & secrets → Certificates.
4. **Fill in the config block** at the top of `New-EntraTAP.ps1`:
   ```powershell
   $TenantId              = '<your-tenant-guid>'
   $ClientId              = '<app-registration-client-id>'
   $CertificateThumbprint = '<cert-thumbprint>'
   ```

## Usage

| Parameter            | Required        | Description                                                        |
|----------------------|-----------------|--------------------------------------------------------------------|
| `-UserId`            | single-user mode| UPN or object ID of the target user                                |
| `-CsvPath`           | bulk mode       | Path to a CSV containing a `UserId` (or `UserPrincipalName`) column |
| `-StartDateTime`     | optional        | When the TAP becomes valid (omit = immediate)                       |
| `-LifetimeInMinutes` | optional        | TAP lifetime, 10–43200 (omit = tenant policy default)               |
| `-IsUsableOnce`      | optional switch | Create a one-time-use TAP (omit = tenant policy default)            |
| `-ExportCsv`         | optional        | Path to write a results CSV (includes generated passcodes)          |

```powershell
# Default settings for one user
.\New-EntraTAP.ps1 -UserId jdoe@contoso.com

# 4-hour, one-time-use TAP
.\New-EntraTAP.ps1 -UserId jdoe@contoso.com -LifetimeInMinutes 240 -IsUsableOnce

# Bulk, 60-minute TAPs, export results
.\New-EntraTAP.ps1 -CsvPath .\users.csv -LifetimeInMinutes 60 -ExportCsv .\taps.csv
```

### CSV format (bulk mode)

Only the user column is required. The optional columns override the script-level parameters **per row**; blanks fall back to the parameter value, and if that's also unset, to the tenant default.

```csv
UserId,LifetimeInMinutes,IsUsableOnce,StartDateTime
jdoe@contoso.com,60,true,
asmith@contoso.com,,,2026-06-10T09:00:00
bwong@contoso.com,480,false,
```

## Security considerations

- A TAP is a **live credential**. The passcode is returned only at creation and is shown once in the console output — it cannot be retrieved later.
- The `-ExportCsv` file contains plaintext passcodes. Restrict access and delete it once the TAPs are distributed.
- Prefer **one-time-use** TAPs and the shortest viable lifetime for onboarding/recovery scenarios.
- Keep the certificate's private key non-exportable on production hosts where possible, and scope the app to the minimum required users.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `Certificate '…' not found` | Thumbprint mismatch, or cert is in a store the script doesn't scan. It checks `CurrentUser\My` and `LocalMachine\My` only. |
| `Certificate found but has no associated private key` | Only the public `.cer` is installed. Import the `.pfx` (with private key) into the store. |
| `Authorization_RequestDenied` / 403 | Missing/unconsented `UserAuthenticationMethod.ReadWrite.All`, or insufficient directory role for a privileged target user. |
| `…temporaryAccessPass… is not enabled` / policy error | TAP method disabled in the tenant, or the user is not in the method's scope. |
| HTTP 409 / "already has a Temporary Access Pass" | A TAP already exists for that user. Delete the existing method first, then re-run. |
| `Resource '…' does not exist` (404) | UPN/object ID typo, or the user is in another tenant. |
| Lifetime rejected | Value outside the tenant policy's configured min/max (absolute Graph bounds are 10–43200 minutes). |
