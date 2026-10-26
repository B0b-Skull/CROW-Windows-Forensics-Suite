<#
.SYNOPSIS
    System Binary Baseline Manifest Generator (INT-02)
.DESCRIPTION
    Creates a version-matched local SHA-256 and Authenticode baseline manifest
    for core Windows system binaries and drivers in Evidence\HashManifests\
    and Data\Baselines\system_binary_baseline.json.
#>
param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $baseDir "Data\Baselines\system_binary_baseline.json" }
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$nowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$coreFiles = @(
    "C:\Windows\explorer.exe",
    "C:\Windows\System32\ntoskrnl.exe",
    "C:\Windows\System32\ntdll.dll",
    "C:\Windows\System32\kernel32.dll",
    "C:\Windows\System32\KernelBase.dll",
    "C:\Windows\System32\user32.dll",
    "C:\Windows\System32\gdi32.dll",
    "C:\Windows\System32\advapi32.dll",
    "C:\Windows\System32\ws2_32.dll",
    "C:\Windows\System32\svchost.exe",
    "C:\Windows\System32\lsass.exe",
    "C:\Windows\System32\csrss.exe",
    "C:\Windows\System32\services.exe",
    "C:\Windows\System32\wininit.exe",
    "C:\Windows\System32\winlogon.exe",
    "C:\Windows\System32\smss.exe",
    "C:\Windows\System32\dwm.exe",
    "C:\Windows\System32\sihost.exe",
    "C:\Windows\System32\taskhostw.exe",
    "C:\Windows\System32\userinit.exe",
    "C:\Windows\System32\twinui.pcshell.dll",
    "C:\Windows\System32\rundll32.exe",
    "C:\Windows\System32\regsvr32.exe",
    "C:\Windows\System32\cmd.exe",
    "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "C:\Windows\System32\drivers\tcpip.sys",
    "C:\Windows\System32\drivers\http.sys",
    "C:\Windows\System32\drivers\ndis.sys",
    "C:\Windows\System32\drivers\fltmgr.sys",
    "C:\Windows\System32\drivers\dxgkrnl.sys",
    "C:\Windows\System32\drivers\ksecdd.sys",
    "C:\Windows\System32\drivers\acpi.sys"
)

$manifestEntries = @{}
foreach ($fp in $coreFiles) {
    if (Test-Path -LiteralPath $fp) {
        $item = Get-Item -LiteralPath $fp
        $hash = (Get-FileHash -LiteralPath $fp -Algorithm SHA256).Hash
        $sig  = Get-AuthenticodeSignature -FilePath $fp
        $manifestEntries[$fp.ToLower()] = [PSCustomObject]@{
            FilePath        = $fp
            FileName        = $item.Name
            SHA256          = $hash
            FileSize        = $item.Length
            FileVersion     = $item.VersionInfo.FileVersion
            ProductVersion  = $item.VersionInfo.ProductVersion
            SignatureStatus = [string]$sig.Status
            IsOSBinary      = [bool]$sig.IsOSBinary
            RecordedAtUtc   = $nowUtc
        }
    }
}

$baseline = [PSCustomObject]@{
    ScriptId       = "INT-02"
    BaselineDateUtc= $nowUtc
    OSCaption      = $os.Caption
    OSVersion      = $os.Version
    OSBuild        = $os.BuildNumber
    BinaryCount    = $manifestEntries.Count
    Binaries       = $manifestEntries
}

$outDir = Split-Path -Path $OutputPath -Parent
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$baseline | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8

$manifestDir = Join-Path $baseDir "Evidence\HashManifests"
if (!(Test-Path $manifestDir)) { New-Item -ItemType Directory -Path $manifestDir -Force | Out-Null }
$manifestCopy = Join-Path $manifestDir "baseline_manifest_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$baseline | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestCopy -Encoding UTF8
Write-Output "System binary baseline created at $OutputPath ($($manifestEntries.Count) binaries)"
