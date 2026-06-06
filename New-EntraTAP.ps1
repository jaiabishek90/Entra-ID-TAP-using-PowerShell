#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Generates Entra ID Temporary Access Passes (TAP) via Microsoft Graph using
    app-only certificate authentication.

.DESCRIPTION
    Creates one or more Temporary Access Passes for Entra ID users. Supports a
    single user (parameter) or bulk creation from a CSV. Authenticates non-
    interactively with a certificate thumbprint, runs pre-flight validation
    before connecting, prints a console summary, and can export results to CSV.

    Required application permission (Graph): UserAuthenticationMethod.ReadWrite.All
    The Temporary Access Pass authentication method must be enabled in the tenant
    and the target users must be in its scope.

.PARAMETER UserId
    Single-user mode. UPN or object ID of the target user.

.PARAMETER CsvPath
    Bulk mode. Path to a CSV with a UserId (or UserPrincipalName) column.
    Optional per-row override columns: LifetimeInMinutes, IsUsableOnce, StartDateTime.

.PARAMETER StartDateTime
    Optional. When the TAP becomes valid. Omit to start immediately.

.PARAMETER LifetimeInMinutes
    Optional. TAP lifetime (10-43200). Omit to use the tenant policy default.

.PARAMETER IsUsableOnce
    Optional switch. Create a one-time-use TAP. Omit to use the tenant policy default.

.PARAMETER ExportCsv
    Optional. Path to write a results CSV (includes the generated passcodes).

.EXAMPLE
    .\New-EntraTAP.ps1 -UserId jdoe@contoso.com
    Creates a TAP with tenant default settings.

.EXAMPLE
    .\New-EntraTAP.ps1 -UserId jdoe@contoso.com -LifetimeInMinutes 240 -IsUsableOnce
    Creates a 4-hour, one-time-use TAP.

.EXAMPLE
    .\New-EntraTAP.ps1 -CsvPath .\users.csv -LifetimeInMinutes 60 -ExportCsv .\taps.csv
    Bulk-creates 60-minute TAPs for every user in the CSV (unless overridden per row)
    and exports the passcodes.
#>

[CmdletBinding(DefaultParameterSetName = 'SingleUser')]
param(
    [Parameter(Mandatory, ParameterSetName = 'SingleUser', Position = 0)]
    [string]$UserId,

    [Parameter(Mandatory, ParameterSetName = 'Bulk')]
    [string]$CsvPath,

    [Parameter()]
    [datetime]$StartDateTime,

    [Parameter()]
    [ValidateRange(10, 43200)]
    [int]$LifetimeInMinutes,

    [Parameter()]
    [switch]$IsUsableOnce,

    [Parameter()]
    [string]$ExportCsv
)

# ---------------------------------------------------------------------------
#  CONFIGURATION  -  edit these for your tenant
# ---------------------------------------------------------------------------
$TenantId              = '00000000-0000-0000-0000-000000000000'
$ClientId              = '00000000-0000-0000-0000-000000000000'
$CertificateThumbprint = 'THUMBPRINT_GOES_HERE'
# ---------------------------------------------------------------------------

$ErrorActionPreference = 'Stop'
$script:RunMode  = $PSCmdlet.ParameterSetName
$script:AuthCert = $null

function Get-AuthCertificate {
    param([string]$Thumbprint)
    foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
        $cert = Get-ChildItem -Path $store -ErrorAction SilentlyContinue |
                Where-Object { $_.Thumbprint -eq $Thumbprint } |
                Select-Object -First 1
        if ($cert) { return $cert }
    }
    return $null
}

function Test-Config {
    [CmdletBinding()]
    param()

    $problems    = [System.Collections.Generic.List[string]]::new()
    $guidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'

    # Placeholder / empty detection
    if ([string]::IsNullOrWhiteSpace($TenantId) -or $TenantId -like '00000000-*') {
        $problems.Add('TenantId is empty or still a placeholder.')
    }
    elseif ($TenantId -notmatch $guidPattern) {
        $problems.Add("TenantId '$TenantId' is not a valid GUID.")
    }

    if ([string]::IsNullOrWhiteSpace($ClientId) -or $ClientId -like '00000000-*') {
        $problems.Add('ClientId is empty or still a placeholder.')
    }
    elseif ($ClientId -notmatch $guidPattern) {
        $problems.Add("ClientId '$ClientId' is not a valid GUID.")
    }

    if ([string]::IsNullOrWhiteSpace($CertificateThumbprint) -or $CertificateThumbprint -eq 'THUMBPRINT_GOES_HERE') {
        $problems.Add('CertificateThumbprint is empty or still a placeholder.')
    }
    else {
        $script:AuthCert = Get-AuthCertificate -Thumbprint $CertificateThumbprint
        if (-not $script:AuthCert) {
            $problems.Add("Certificate '$CertificateThumbprint' not found in CurrentUser\My or LocalMachine\My.")
        }
        else {
            if (-not $script:AuthCert.HasPrivateKey) { $problems.Add('Certificate found but has no associated private key.') }
            if ($script:AuthCert.NotAfter -lt (Get-Date)) {
                $problems.Add("Certificate expired on $($script:AuthCert.NotAfter).")
            }
            elseif ($script:AuthCert.NotAfter -lt (Get-Date).AddDays(30)) {
                Write-Warning "Auth certificate expires soon ($($script:AuthCert.NotAfter.ToString('yyyy-MM-dd')))."
            }
        }
    }

    # Bulk mode: CSV must exist
    if ($script:RunMode -eq 'Bulk' -and -not (Test-Path -LiteralPath $CsvPath)) {
        $problems.Add("CSV file not found: $CsvPath")
    }

    if ($problems.Count -gt 0) {
        Write-Host "`nPre-flight validation FAILED:" -ForegroundColor Red
        $problems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        return $false
    }

    Write-Host 'Pre-flight validation passed.' -ForegroundColor Green
    Write-Host "  Certificate: $($script:AuthCert.Subject) (expires $($script:AuthCert.NotAfter.ToString('yyyy-MM-dd')))" -ForegroundColor DarkGray
    return $true
}

function Get-RowValue {
    param($Row, [string[]]$Names)
    foreach ($n in $Names) {
        if ($Row.PSObject.Properties.Name -contains $n) {
            $v = $Row.$n
            if (-not [string]::IsNullOrWhiteSpace([string]$v)) { return $v }
        }
    }
    return $null
}

function New-TemporaryAccessPass {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$User,
        [Nullable[datetime]]$Start,
        [Nullable[int]]$Lifetime,
        [Nullable[bool]]$OnceOnly
    )

    $body = @{}
    if ($null -ne $Start)    { $body.startDateTime     = $Start.Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    if ($null -ne $Lifetime) { $body.lifetimeInMinutes = $Lifetime.Value }
    if ($null -ne $OnceOnly) { $body.isUsableOnce       = $OnceOnly.Value }

    $uri = "https://graph.microsoft.com/v1.0/users/$User/authentication/temporaryAccessPassMethods"
    return Invoke-MgGraphRequest -Method POST -Uri $uri -Body ($body | ConvertTo-Json) -ContentType 'application/json'
}

# ---------------------------------------------------------------------------
#  MAIN
# ---------------------------------------------------------------------------
if (-not (Test-Config)) { exit 1 }

# Build target list
$targets = [System.Collections.Generic.List[object]]::new()

if ($script:RunMode -eq 'SingleUser') {
    $targets.Add([pscustomobject]@{
        UserId    = $UserId
        Start     = if ($PSBoundParameters.ContainsKey('StartDateTime'))     { [Nullable[datetime]]$StartDateTime }     else { $null }
        Lifetime  = if ($PSBoundParameters.ContainsKey('LifetimeInMinutes')) { [Nullable[int]]$LifetimeInMinutes }      else { $null }
        OnceOnly  = if ($PSBoundParameters.ContainsKey('IsUsableOnce'))      { [Nullable[bool]]$IsUsableOnce.IsPresent } else { $null }
    })
}
else {
    foreach ($row in (Import-Csv -LiteralPath $CsvPath)) {
        $rowUser = Get-RowValue -Row $row -Names @('UserId', 'UserPrincipalName', 'UPN')
        if (-not $rowUser) { Write-Warning 'Skipping CSV row with no UserId/UserPrincipalName.'; continue }

        $rowLifeRaw  = Get-RowValue -Row $row -Names @('LifetimeInMinutes')
        $rowOnceRaw  = Get-RowValue -Row $row -Names @('IsUsableOnce')
        $rowStartRaw = Get-RowValue -Row $row -Names @('StartDateTime')

        $life  = if ($rowLifeRaw)  { [Nullable[int]][int]$rowLifeRaw }
                 elseif ($PSBoundParameters.ContainsKey('LifetimeInMinutes')) { [Nullable[int]]$LifetimeInMinutes } else { $null }
        $once  = if ($rowOnceRaw)  { [Nullable[bool]][System.Convert]::ToBoolean($rowOnceRaw) }
                 elseif ($PSBoundParameters.ContainsKey('IsUsableOnce')) { [Nullable[bool]]$IsUsableOnce.IsPresent } else { $null }
        $start = if ($rowStartRaw) { [Nullable[datetime]][datetime]$rowStartRaw }
                 elseif ($PSBoundParameters.ContainsKey('StartDateTime')) { [Nullable[datetime]]$StartDateTime } else { $null }

        $targets.Add([pscustomobject]@{ UserId = $rowUser; Start = $start; Lifetime = $life; OnceOnly = $once })
    }
}

if ($targets.Count -eq 0) { Write-Host 'No valid targets to process.' -ForegroundColor Yellow; exit 0 }

# Connect and process
$results = [System.Collections.Generic.List[object]]::new()
try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -Certificate $script:AuthCert -NoWelcome
    Write-Host "Connected to tenant $TenantId. Processing $($targets.Count) user(s)...`n" -ForegroundColor Cyan

    foreach ($t in $targets) {
        try {
            $resp = New-TemporaryAccessPass -User $t.UserId -Start $t.Start -Lifetime $t.Lifetime -OnceOnly $t.OnceOnly
            $results.Add([pscustomobject]@{
                UserId              = $t.UserId
                Status              = 'Success'
                TemporaryAccessPass = $resp.temporaryAccessPass
                StartDateTime       = $resp.startDateTime
                LifetimeInMinutes   = $resp.lifetimeInMinutes
                IsUsableOnce        = $resp.isUsableOnce
                MethodId            = $resp.id
                Error               = ''
            })
            Write-Host "  [OK]   $($t.UserId)" -ForegroundColor Green
        }
        catch {
            $results.Add([pscustomobject]@{
                UserId              = $t.UserId
                Status              = 'Failed'
                TemporaryAccessPass = ''
                StartDateTime       = ''
                LifetimeInMinutes   = ''
                IsUsableOnce        = ''
                MethodId            = ''
                Error               = $_.Exception.Message
            })
            Write-Host "  [FAIL] $($t.UserId) - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}

# Summary
$ok   = ($results | Where-Object Status -eq 'Success').Count
$fail = ($results | Where-Object Status -eq 'Failed').Count

Write-Host "`n=== Temporary Access Pass Summary ===" -ForegroundColor Cyan
$results |
    Select-Object UserId, Status, TemporaryAccessPass, LifetimeInMinutes, IsUsableOnce, StartDateTime |
    Format-Table -AutoSize
Write-Host "Created: $ok   Failed: $fail" -ForegroundColor Cyan
Write-Host 'NOTE: The passcode above is a live credential shown only once. Handle it securely.' -ForegroundColor Yellow

# Optional export
if ($ExportCsv) {
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nResults exported to $ExportCsv (contains live passcodes - protect or delete after use)." -ForegroundColor Yellow
}
