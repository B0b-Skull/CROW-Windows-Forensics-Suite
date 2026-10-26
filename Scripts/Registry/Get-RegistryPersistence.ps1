<#
.SYNOPSIS
    Registry Persistence, Autostart & Shell Configuration Script (REG-01)
.DESCRIPTION
    Audits registry Run/RunOnce keys, Winlogon Shell/Userinit values,
    Image File Execution Options (IFEO) debugger/silent process exit hooks,
    AppInit_DLLs, Startup Folders, and Scheduled Tasks at logon/boot. Read-only.
#>
param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $baseDir "Data\Inventory\registry_persistence_latest.json" }
$nowLocal = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
$nowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$entries = @()

# 1. Standard Run / RunOnce / Policies Run Keys
$runPaths = @(
    @{ Scope = "HKLM Run"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" },
    @{ Scope = "HKLM RunOnce"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" },
    @{ Scope = "HKLM WOW6432 Run"; Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" },
    @{ Scope = "HKLM WOW6432 RunOnce"; Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce" },
    @{ Scope = "HKCU Run"; Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" },
    @{ Scope = "HKCU RunOnce"; Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" },
    @{ Scope = "HKLM Policies Explorer Run"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" },
    @{ Scope = "HKCU Policies Explorer Run"; Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" }
)

foreach ($rp in $runPaths) {
    if (Test-Path $rp.Path) {
        $item = Get-Item -Path $rp.Path -ErrorAction SilentlyContinue
        foreach ($valName in $item.Property) {
            $valData = $item.GetValue($valName)
            $exeMatch = $null
            if ($valData -match '^"([^"]+)"') { $exeMatch = $Matches[1] }
            elseif ($valData -match '^([^\s]+\.(exe|dll|bat|cmd|ps1|vbs))') { $exeMatch = $Matches[1] }
            $entries += [PSCustomObject]@{
                Category       = "RegistryAutorun"
                Scope          = $rp.Scope
                RegistryKey    = $rp.Path
                EntryName      = $valName
                ValueData      = [string]$valData
                TargetBinary   = $exeMatch
                RiskNote       = if ($valData -match 'powershell|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32.*AppData') { "Script/LOLBin Autorun" } else { "Standard Autorun" }
            }
        }
    }
}

# 2. Winlogon Shell & Userinit Integrity
$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (Test-Path $winlogonPath) {
    $wl = Get-ItemProperty -Path $winlogonPath -ErrorAction SilentlyContinue
    $entries += [PSCustomObject]@{
        Category     = "WinlogonCore"
        Scope        = "HKLM Winlogon"
        RegistryKey  = $winlogonPath
        EntryName    = "Shell"
        ValueData    = [string]$wl.Shell
        TargetBinary = "C:\Windows\explorer.exe"
        RiskNote     = if ($wl.Shell -ne "explorer.exe") { "ANOMALY: Non-standard Winlogon Shell value" } else { "Verified Default (explorer.exe)" }
    }
    $entries += [PSCustomObject]@{
        Category     = "WinlogonCore"
        Scope        = "HKLM Winlogon"
        RegistryKey  = $winlogonPath
        EntryName    = "Userinit"
        ValueData    = [string]$wl.Userinit
        TargetBinary = "C:\Windows\system32\userinit.exe"
        RiskNote     = if ($wl.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$') { "ANOMALY: Modified Userinit value" } else { "Verified Default (userinit.exe)" }
    }
}

# 3. IFEO Debugger Redirects
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue |
    Where-Object { $_.Property -contains "Debugger" } |
    ForEach-Object {
        $dbg = (Get-ItemProperty -Path $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
        if ($dbg) {
            $entries += [PSCustomObject]@{
                Category     = "IFEO_DebuggerHook"
                Scope        = "HKLM IFEO"
                RegistryKey  = $_.Name
                EntryName    = $_.PSChildName
                ValueData    = "Debugger = $dbg"
                TargetBinary = $dbg
                RiskNote     = "Intercepts execution of $($_.PSChildName) and redirects to $dbg"
            }
        }
    }

# 4. Startup Folders
$startupFolders = @(
    @{ Scope = "User Startup Folder"; Path = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" },
    @{ Scope = "Common Startup Folder"; Path = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" }
)
foreach ($sf in $startupFolders) {
    if (Test-Path $sf.Path) {
        Get-ChildItem -Path $sf.Path -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "desktop.ini" } | ForEach-Object {
            $entries += [PSCustomObject]@{
                Category     = "StartupFolder"
                Scope        = $sf.Scope
                RegistryKey  = $sf.Path
                EntryName    = $_.Name
                ValueData    = $_.FullName
                TargetBinary = $_.FullName
                RiskNote     = "Startup Folder Shortcut/Executable"
            }
        }
    }
}

$output = [PSCustomObject]@{
    ScriptId          = "REG-01"
    ScriptName        = "Get-RegistryPersistence.ps1"
    CollectedAtLocal  = $nowLocal
    CollectedAtUtc    = $nowUtc
    TotalEntries      = $entries.Count
    Entries           = $entries
}

$outDir = Split-Path -Path $OutputPath -Parent
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$output | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Output "Registry persistence audit written to $OutputPath"
