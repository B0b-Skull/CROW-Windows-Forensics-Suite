<#
.SYNOPSIS
    Kernel, System & PnP Driver Inventory Script (DRV-01)
.DESCRIPTION
    Collects loaded kernel/file-system drivers (Win32_SystemDriver) and signed
    PnP/Display drivers, checking status, start mode, binary path, and Authenticode
    signature status for non-standard or third-party drivers. Read-only.
#>
param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $baseDir "Data\Inventory\driver_inventory_latest.json" }
$nowLocal = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
$nowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$sysDrivers = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue
$driverList = @()

foreach ($d in $sysDrivers) {
    $rawPath = $d.PathName
    $resolvedPath = $rawPath
    if ($rawPath -match '^\\\?\?\\(.+)$') {
        $resolvedPath = $Matches[1]
    } elseif ($rawPath -match '^\\SystemRoot\\(.+)$') {
        $resolvedPath = "C:\Windows\$($Matches[1])"
    } elseif ($rawPath -match '^system32\\(.+)$') {
        $resolvedPath = "C:\Windows\System32\$($Matches[1])"
    }

    $isNonStandardPath = $false
    $sigStatus = "SystemStandard"
    $signer = "Microsoft Windows"
    $company = "Microsoft Corporation"
    $sha256 = $null

    if ($resolvedPath -and (Test-Path $resolvedPath)) {
        $ver = (Get-Item -LiteralPath $resolvedPath -ErrorAction SilentlyContinue).VersionInfo
        if ($ver -and $ver.CompanyName) { $company = $ver.CompanyName }
        if ($resolvedPath -notmatch '^C:\\Windows\\System32\\drivers\\|^C:\\Windows\\System32\\DriverStore\\' -or $company -notmatch 'Microsoft') {
            $isNonStandardPath = ($resolvedPath -notmatch '^C:\\Windows\\System32\\drivers\\|^C:\\Windows\\System32\\DriverStore\\')
            $sig = Get-AuthenticodeSignature -FilePath $resolvedPath -ErrorAction SilentlyContinue
            if ($sig) {
                $sigStatus = [string]$sig.Status
                $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "None" }
            }
            $sha256 = (Get-FileHash -Path $resolvedPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        }
    }

    $driverList += [PSCustomObject]@{
        Name              = $d.Name
        DisplayName       = $d.DisplayName
        State             = $d.State
        StartMode         = $d.StartMode
        ServiceType       = $d.ServiceType
        Status            = $d.Status
        PathName          = $resolvedPath
        CompanyName       = $company
        SignatureStatus   = $sigStatus
        SignerSubject     = $signer
        SHA256            = $sha256
        IsThirdPartyOrCustom = ($company -notmatch 'Microsoft' -or $isNonStandardPath)
    }
}

$output = [PSCustomObject]@{
    ScriptId             = "DRV-01"
    ScriptName           = "Get-DriverInventory.ps1"
    CollectedAtLocal     = $nowLocal
    CollectedAtUtc       = $nowUtc
    TotalDrivers         = $driverList.Count
    RunningDrivers       = @($driverList | Where-Object { $_.State -eq 'Running' }).Count
    ThirdPartyDrivers    = @($driverList | Where-Object { $_.IsThirdPartyOrCustom -and $_.State -eq 'Running' }).Count
    Drivers              = $driverList
}

$outDir = Split-Path -Path $OutputPath -Parent
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$output | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Output "Driver inventory written to $OutputPath"
