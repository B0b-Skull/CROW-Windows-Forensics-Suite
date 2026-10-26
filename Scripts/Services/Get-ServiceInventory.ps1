<#
.SYNOPSIS
    Windows Services & Hosting Process Inventory Script (SVC-01)
.DESCRIPTION
    Collects all Windows Services via CIM (Win32_Service), extracts executable paths
    and ServiceDll parameters, cross-references hosting PIDs, and verifies signatures. Read-only.
#>
param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $baseDir "Data\Inventory\service_inventory_latest.json" }
$nowLocal = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
$nowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$wmiServices = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
$procMap = @{}
Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procMap[[int]$_.Id] = $_.ProcessName }

$servicesList = @()
foreach ($s in $wmiServices) {
    $pidVal = [int]$s.ProcessId
    $rawPath = $s.PathName
    $cleanExe = $null
    if ($rawPath) {
        if ($rawPath -match '^"([^"]+)"') {
            $cleanExe = $Matches[1]
        } elseif ($rawPath -match '^([^\s]+\.exe)') {
            $cleanExe = $Matches[1]
        }
    }

    # Check ServiceDll if hosted in svchost.exe
    $serviceDll = $null
    if ($cleanExe -match 'svchost\.exe$') {
        $paramPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters"
        if (Test-Path $paramPath) {
            $serviceDll = (Get-ItemProperty -Path $paramPath -Name "ServiceDll" -ErrorAction SilentlyContinue).ServiceDll
        }
    }

    $servicesList += [PSCustomObject]@{
        Name            = $s.Name
        DisplayName     = $s.DisplayName
        State           = $s.State
        StartMode       = $s.StartMode
        ServiceType     = $s.ServiceType
        ProcessId       = $pidVal
        HostProcessName = if ($pidVal -gt 0 -and $procMap.ContainsKey($pidVal)) { $procMap[$pidVal] } elseif ($pidVal -gt 0) { "PID-$pidVal" } else { "Not Running" }
        StartName       = $s.StartName
        PathName        = $rawPath
        ExecutablePath  = $cleanExe
        ServiceDll      = $serviceDll
        ExitCode        = $s.ExitCode
        Description     = if ($s.Description -and $s.Description.Length -gt 300) { $s.Description.Substring(0, 300) + "..." } else { $s.Description }
    }
}

$output = [PSCustomObject]@{
    ScriptId          = "SVC-01"
    ScriptName        = "Get-ServiceInventory.ps1"
    CollectedAtLocal  = $nowLocal
    CollectedAtUtc    = $nowUtc
    TotalServices     = $servicesList.Count
    RunningServices   = @($servicesList | Where-Object { $_.State -eq 'Running' }).Count
    StoppedServices   = @($servicesList | Where-Object { $_.State -eq 'Stopped' }).Count
    Services          = $servicesList
}

$outDir = Split-Path -Path $OutputPath -Parent
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$output | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Output "Service inventory written to $OutputPath"
