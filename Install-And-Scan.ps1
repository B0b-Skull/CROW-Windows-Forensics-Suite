<#
.SYNOPSIS
    CROW INNOVATIONS Windows System Analysis & Forensics Suite - Automated Bootstrap & Scanner
.DESCRIPTION
    Prepares the local folder hierarchy on any target Windows workstation or server,
    creates a Desktop launcher shortcut with the official CROW icon (assets\crow-icon.ico),
    executes the complete read-only forensic & diagnostic script suite (CORE-01),
    populates the local Obsidian Vault and CSV reports, and launches the interactive
    Web Dashboard with 3-second real-time hardware telemetry (PERF-02).
#>
param(
    [switch]$SkipBrowserLaunch = $false,
    [switch]$SkipShortcut = $false
)

$ErrorActionPreference = 'Continue'
$baseDir = $PSScriptRoot
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host ""
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "  CROW INNOVATIONS Windows System Analysis & Forensics Suite                " -ForegroundColor Cyan
Write-Host "  Cyber Research in Offensive Warfare | https://crowinnovations.com/tools.html" -ForegroundColor DarkCyan
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "  Target Host   : $env:COMPUTERNAME ($env:USERDOMAIN\$env:USERNAME)" -ForegroundColor Gray
Write-Host "  Privilege Mode: $(if ($isAdmin) { 'Administrator (Full Forensic Visibility)' } else { 'Standard User (Non-Elevated)' })" -ForegroundColor $(if ($isAdmin) { 'Green' } else { 'Yellow' })
Write-Host "  Workstation   : $baseDir" -ForegroundColor Gray
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Initialize clean directory hierarchy
$requiredDirs = @(
    "Data\Inventory",
    "Data\Telemetry",
    "Data\Performance",
    "Data\Investigations",
    "Data\Baselines",
    "Data\Cache",
    "Reports\CSV",
    "Reports\Executive",
    "Evidence\HashManifests",
    "Evidence\MemoryDumps",
    "Logs",
    "ObsidianVault\SystemBaselines",
    "ObsidianVault\ThreatFindings",
    "ObsidianVault\Investigations",
    "ObsidianVault\RemediationHistory",
    "ObsidianVault\Architecture"
)

Write-Host "[1/3] Initializing forensic directory structure & tool icon..." -ForegroundColor Yellow
foreach ($rel in $requiredDirs) {
    $full = Join-Path $baseDir $rel
    if (!(Test-Path $full)) {
        New-Item -ItemType Directory -Path $full -Force | Out-Null
    }
}

# Create Desktop Shortcut with official CROW Icon (assets\crow-icon.ico) if available
$iconPath = Join-Path $baseDir "assets\crow-icon.ico"
if ((!$SkipShortcut) -and (Test-Path $iconPath)) {
    try {
        $desktopDir = [Environment]::GetFolderPath("Desktop")
        if ($desktopDir -and (Test-Path $desktopDir)) {
            $lnkPath = Join-Path $desktopDir "CROW Forensics Suite.lnk"
            $wsh = New-Object -ComObject WScript.Shell
            $sc  = $wsh.CreateShortcut($lnkPath)
            $sc.TargetPath       = Join-Path $baseDir "Start-Dashboard.cmd"
            $sc.WorkingDirectory = $baseDir
            $sc.IconLocation     = "$iconPath,0"
            $sc.Description      = "CROW INNOVATIONS Windows System Analysis & Forensics Suite"
            $sc.Save()
            Write-Host "  -> Desktop shortcut created with CROW icon: $lnkPath" -ForegroundColor Green
        }
    } catch {
        # Non-fatal if Desktop shortcut creation is restricted
    }
}
Write-Host "  -> Directory structure verified." -ForegroundColor Green

# 2. Execute Full System Forensic Snapshot (CORE-01)
Write-Host ""
Write-Host "[2/3] Executing Full System Analysis & Forensic Check (CORE-01)..." -ForegroundColor Yellow
Write-Host "      Collecting Hardware, Performance, Processes, Services, Drivers, Registry," -ForegroundColor Gray
Write-Host "      Network + Public IP Intel, Event Logs, Stability Incidents, Entity Correlation," -ForegroundColor Gray
Write-Host "      System Binary Integrity, Malware/Persistence Audit, Crash Dumps & Obsidian Vault..." -ForegroundColor Gray

$coreScript = Join-Path $baseDir "Scripts\Core\Invoke-FullSystemSnapshot.ps1"
& $coreScript

Write-Host "  -> Full forensic snapshot & dashboard data bundle (data.js) generated!" -ForegroundColor Green

if ($SkipBrowserLaunch) {
    Write-Host "`n[3/3] Scan complete (Browser launch skipped via -SkipBrowserLaunch)." -ForegroundColor Cyan
    exit 0
}

# 3. Launch Interactive Dashboard (Localhost Python Backend or Standalone Native PowerShell Live Stream Mode)
Write-Host ""
Write-Host "[3/3] Launching CROW INNOVATIONS Interactive Forensic Dashboard..." -ForegroundColor Yellow

$pyExe = $null
if (Get-Command "python.exe" -ErrorAction SilentlyContinue) {
    $pyExe = (Get-Command "python.exe").Source
} else {
    $candidates = @(
        "C:\Program Files\Python3*\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe"
    )
    foreach ($pattern in $candidates) {
        $found = Get-Item $pattern -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
        if ($found) { $pyExe = $found.FullName; break }
    }
}

$indexPath  = Join-Path $baseDir "index.html"
$serverPath = Join-Path $baseDir "Dashboard\Backend\server.py"
$streamPath = Join-Path $baseDir "Scripts\Performance\Start-LiveTelemetryStream.ps1"

if ($pyExe -and (Test-Path $serverPath)) {
    Write-Host "  -> Python 3 detected ($pyExe)." -ForegroundColor Green
    Write-Host "  -> Opening http://127.0.0.1:8765/index.html and starting Script Execution + Live Telemetry Backend..." -ForegroundColor Cyan
    Start-Process "http://127.0.0.1:8765/index.html"
    & $pyExe $serverPath --host 127.0.0.1 --port 8765
} else {
    Write-Host "  -> Opening Dashboard in Standalone Native PowerShell Mode ($indexPath)..." -ForegroundColor Cyan
    Start-Process $indexPath
    if (Test-Path $streamPath) {
        Write-Host "  -> Starting Native PowerShell Live Hardware Telemetry Streamer (PERF-02, 3s interval)..." -ForegroundColor Green
        & $streamPath -IntervalSeconds 3 -MaxSamples 999999
    }
}
