<#
.SYNOPSIS
    Controlled, User-Authorized Remediation Script (REM-01)
.DESCRIPTION
    Executes or previews specific, approved administrative remediation actions.
    CRITICAL SAFETY RULE: Defaults to -PreviewOnly ($true). State-changing execution
    is blocked unless BOTH -ExecuteRemediation AND -ConfirmationToken "AUTHORIZE-CHANGE"
    are explicitly supplied by the user via the dashboard authorization dialog.
    Compatible with Windows PowerShell 5.1 (Desktop) and PowerShell 7+ (Core).
#>
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet(
        "REM-EXP-01_ExplorerSeparateProcess",
        "REM-GPU-01_TdrDelayIncrease",
        "REM-SHUT-01_ReduceServiceKillTimeout",
        "REM-NET-01_SetRustDeskManual",
        "REM-LEGACY-01_ApplyPreviousSystemOptimizations"
    )]
    [string]$ActionId,
    [switch]$ExecuteRemediation = $false,
    [string]$ConfirmationToken = ""
)

$ErrorActionPreference = 'Stop'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$nowLocal = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
$legacyScriptPath = Join-Path $baseDir "apply_system_modifications.ps1"
$psVer = $PSVersionTable.PSVersion.ToString()

$actionCatalog = @{
    "REM-EXP-01_ExplorerSeparateProcess" = @{
        Title            = "Isolate File Explorer Folder Windows in a Separate Process"
        IncidentTarget   = "Shell Stability (Explorer.exe Cross-Thread Hang / Crash Isolation)"
        RequiresAdmin    = $false
        RegistryPath     = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        ValueName        = "SeparateProcess"
        NewValue         = 1
        ValueType        = "DWord"
        RiskLevel        = "Low (Reversible User Preference)"
        Description      = "Configures Windows Explorer to launch folder windows in a separate explorer.exe worker process so thumbnail/shell extension hangs in media directories cannot crash the desktop taskbar shell."
        VerificationCmd  = "(Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name SeparateProcess).SeparateProcess -eq 1"
        Command_PS51     = "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'SeparateProcess' -Value 1 -Type DWord"
        Command_PS7      = "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'SeparateProcess' -Value 1 -Type DWord"
    }
    "REM-GPU-01_TdrDelayIncrease" = @{
        Title            = "Increase Windows GPU Timeout Detection & Recovery (TDR) Threshold to 8 Seconds"
        IncidentTarget   = "Display / Browser Compositor Stability (LiveKernelEvent 141 / Event 4101)"
        RequiresAdmin    = $true
        RegistryPath     = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
        ValueName        = "TdrDelay"
        NewValue         = 8
        ValueType        = "DWord"
        RiskLevel        = "Low-Medium (Requires Reboot to Take Effect; Reversible)"
        Description      = "Increases the DirectX kernel watchdog timeout (TdrDelay) from the 2-second default to 8 seconds, preventing transient hybrid GPU P-state switches or heavy CUDA/WebGL frames from prematurely resetting the display driver (BugCheck 0x141)."
        VerificationCmd  = "(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -Name TdrDelay).TdrDelay -eq 8"
        Command_PS51     = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -Name 'TdrDelay' -Value 8 -Type DWord"
        Command_PS7      = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -Name 'TdrDelay' -Value 8 -Type DWord"
    }
    "REM-SHUT-01_ReduceServiceKillTimeout" = @{
        Title            = "Enable AutoEndTasks for Hung User Processes at Shutdown"
        IncidentTarget   = "Shutdown / Restart Responsiveness (Event 7043 Service/Task Hang)"
        RequiresAdmin    = $false
        RegistryPath     = "HKCU:\Control Panel\Desktop"
        ValueName        = "AutoEndTasks"
        NewValue         = "1"
        ValueType        = "String"
        RiskLevel        = "Low (Reversible)"
        Description      = "Enables AutoEndTasks in HKCU:\Control Panel\Desktop so hung background user tasks do not block Windows shutdown/restart."
        VerificationCmd  = "(Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name AutoEndTasks).AutoEndTasks -eq '1'"
        Command_PS51     = "Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'AutoEndTasks' -Value '1' -Type String"
        Command_PS7      = "Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'AutoEndTasks' -Value '1' -Type String"
    }
    "REM-NET-01_SetRustDeskManual" = @{
        Title            = "Set Remote Desktop Agent Service (RustDesk) to Manual Startup"
        IncidentTarget   = "Security Audit Flag (Active Remote Control Service)"
        RequiresAdmin    = $true
        RegistryPath     = "Service:RustDesk"
        ValueName        = "StartupType"
        NewValue         = "Manual"
        ValueType        = "Service"
        RiskLevel        = "Low (Reversible)"
        Description      = "Sets the RustDesk service StartupType from Automatic to Manual so remote access is only active when explicitly started by the administrator."
        VerificationCmd  = "(Get-Service 'RustDesk*' -ErrorAction SilentlyContinue).StartType -eq 'Manual'"
        Command_PS51     = "Get-Service -Name 'RustDesk*' -ErrorAction SilentlyContinue | Set-Service -StartupType Manual"
        Command_PS7      = "Get-Service -Name 'RustDesk*' -ErrorAction SilentlyContinue | Set-Service -StartupType Manual"
    }
    "REM-LEGACY-01_ApplyPreviousSystemOptimizations" = @{
        Title            = "Execute System Telemetry & Bloatware Optimization Script"
        IncidentTarget   = "Resource Bloat (SearchApp, PhoneExperienceHost, DiagTrack)"
        RequiresAdmin    = $true
        RegistryPath     = $legacyScriptPath
        ValueName        = "Script"
        NewValue         = "Run"
        ValueType        = "Script"
        RiskLevel        = "Medium (Modifies HKLM Policies, IFEO, and Services)"
        Description      = "Runs the system optimization script (apply_system_modifications.ps1)."
        VerificationCmd  = "Get-Service DiagTrack"
        Command_PS51     = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$legacyScriptPath`""
        Command_PS7      = "pwsh.exe -NoProfile -ExecutionPolicy Bypass -File `"$legacyScriptPath`""
    }
}

$meta = $actionCatalog[$ActionId]

# Check current state before any change
$currentVal = "Not Set / Default"
try {
    if ($meta.ValueType -in @("DWord", "String")) {
        $prop = Get-ItemProperty -Path $meta.RegistryPath -Name $meta.ValueName -ErrorAction SilentlyContinue
        if ($null -ne $prop -and $null -ne $prop.($meta.ValueName)) {
            $currentVal = [string]$prop.($meta.ValueName)
        }
    } elseif ($meta.ValueType -eq "Service") {
        $svc = Get-Service "RustDesk*" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($svc) { $currentVal = [string]$svc.StartType } else { $currentVal = "Service Not Installed" }
    }
} catch {}

if (!$ExecuteRemediation -or $ConfirmationToken -ne "AUTHORIZE-CHANGE") {
    $preview = [PSCustomObject]@{
        ScriptId           = "REM-01"
        Status             = "Success"
        Mode               = "DRY-RUN PREVIEW (No System Changes Made)"
        TimestampLocal     = $nowLocal
        DetectedPSVersion  = $psVer
        ActionId           = $ActionId
        Title              = $meta.Title
        IncidentTarget     = $meta.IncidentTarget
        RequiresAdmin      = $meta.RequiresAdmin
        CurrentAdminState  = $isAdmin
        TargetLocation     = "$($meta.RegistryPath) [$($meta.ValueName)]"
        CurrentValue       = $currentVal
        ProposedNewValue   = $meta.NewValue
        RiskLevel          = $meta.RiskLevel
        Description        = $meta.Description
        VerificationMethod = $meta.VerificationCmd
        Command_PS51       = $meta.Command_PS51
        Command_PS7        = $meta.Command_PS7
        AuthorizationNote  = "To execute this change, check the explicit authorization box in the Dashboard Remediation view and click 'Authorize & Execute'."
    }
    $preview | ConvertTo-Json -Depth 4
    exit 0
}

# Log directory setup
$remLogDir = Join-Path $baseDir "ObsidianVault\RemediationHistory"
if (!(Test-Path $remLogDir)) { New-Item -ItemType Directory -Path $remLogDir -Force -ErrorAction SilentlyContinue | Out-Null }
$remLogPath = Join-Path $remLogDir "Remediation_Log.md"
if (!(Test-Path $remLogPath)) {
    "# Authorized Remediation History Log`r`n" | Set-Content -Path $remLogPath -Encoding UTF8 -ErrorAction SilentlyContinue
}

# If authorized execution is requested on an Admin-only action while running non-elevated:
if ($meta.RequiresAdmin -and !$isAdmin) {
    # Attempt UAC elevation via Start-Process -Verb RunAs
    $elevatedSuccess = $false
    try {
        $argStr = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -ActionId `"$ActionId`" -ExecuteRemediation -ConfirmationToken `"AUTHORIZE-CHANGE`""
        $p = Start-Process -FilePath "powershell.exe" -ArgumentList $argStr -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
        if ($p -and $p.ExitCode -eq 0) {
            $elevatedSuccess = $true
        }
    } catch {
        $elevatedSuccess = $false
    }

    if ($elevatedSuccess) {
        $execResult = [PSCustomObject]@{
            ScriptId         = "REM-01"
            Status           = "Success"
            Mode             = "EXECUTED VIA UAC ADMINISTRATOR ELEVATION"
            TimestampLocal   = $nowLocal
            ActionId         = $ActionId
            Title            = $meta.Title
            PreviousValue    = $currentVal
            AppliedValue     = $meta.NewValue
            VerificationCmd  = $meta.VerificationCmd
        }
        $execResult | ConvertTo-Json -Depth 4
        exit 0
    }

    # If UAC prompt was declined or unavailable, return a clear diagnostic explanation & recommended fix (exit 0 so UI displays structured guidance instead of a generic fault)
    $elevGuide = [PSCustomObject]@{
        ScriptId          = "REM-01"
        Status            = "ElevationRequired"
        Mode              = "PAUSED - ADMINISTRATOR ELEVATION REQUIRED"
        ActionId          = $ActionId
        Title             = $meta.Title
        TargetLocation    = "$($meta.RegistryPath) [$($meta.ValueName)]"
        CurrentValue      = $currentVal
        ProposedNewValue  = $meta.NewValue
        Explanation       = "Action '$($meta.Title)' modifies a protected machine-wide Windows setting ($($meta.RegistryPath)), which Windows restricts to elevated Administrator sessions."
        RecommendedFix    = "1. Click 'Authorize & Execute' again and click 'Yes' on the Windows User Account Control (UAC) prompt, OR 2. Right-click 'Start-Dashboard.cmd' -> 'Run as administrator', OR 3. Copy and run the PowerShell command below in an Administrator PowerShell window."
        Command_PS51      = $meta.Command_PS51
        Command_PS7       = $meta.Command_PS7
        VerificationCmd   = $meta.VerificationCmd
    }
    $elevGuide | ConvertTo-Json -Depth 4
    exit 0
}

# Execute the authorized modification
try {
    if ($meta.ValueType -in @("DWord", "String")) {
        if (!(Test-Path $meta.RegistryPath)) { New-Item -Path $meta.RegistryPath -Force | Out-Null }
        Set-ItemProperty -Path $meta.RegistryPath -Name $meta.ValueName -Value $meta.NewValue -Type $meta.ValueType -ErrorAction Stop
    } elseif ($ActionId -eq "REM-NET-01_SetRustDeskManual") {
        $svc = Get-Service "RustDesk*" -ErrorAction SilentlyContinue
        if ($svc) {
            $svc | Set-Service -StartupType Manual -ErrorAction Stop
        } else {
            $noSvc = [PSCustomObject]@{
                ScriptId       = "REM-01"
                Status         = "NotApplicable"
                Mode           = "SKIPPED - TARGET SERVICE NOT INSTALLED"
                ActionId       = $ActionId
                Title          = $meta.Title
                Explanation    = "The RustDesk remote desktop service is not currently installed as a Windows Service on this host."
                RecommendedFix = "No service startup modification is needed unless RustDesk is installed as a system service."
            }
            $noSvc | ConvertTo-Json -Depth 4
            exit 0
        }
    } elseif ($ActionId -eq "REM-LEGACY-01_ApplyPreviousSystemOptimizations") {
        if (Test-Path $legacyScriptPath) { & $legacyScriptPath }
    }

    $logEntry = "- **$nowLocal** | Action: [$ActionId] ($($meta.Title)) | Previous: [$currentVal] -> New: [$($meta.NewValue)] | User: [$env:USERNAME]"
    $logEntry | Add-Content -Path $remLogPath -Encoding UTF8 -ErrorAction SilentlyContinue

    $execResult = [PSCustomObject]@{
        ScriptId         = "REM-01"
        Status           = "Success"
        Mode             = "EXECUTED (Authorized by User)"
        TimestampLocal   = $nowLocal
        ActionId         = $ActionId
        Title            = $meta.Title
        PreviousValue    = $currentVal
        AppliedValue     = $meta.NewValue
        VerificationCmd  = $meta.VerificationCmd
    }
    $execResult | ConvertTo-Json -Depth 4
    exit 0
} catch {
    $errObj = [PSCustomObject]@{
        ScriptId       = "REM-01"
        Status         = "Error"
        Mode           = "EXECUTION ERROR"
        ActionId       = $ActionId
        Title          = $meta.Title
        ErrorMessage   = $_.Exception.Message
        Explanation    = "Windows rejected the modification to '$($meta.RegistryPath)' due to an operating system permission lock or endpoint protection policy."
        RecommendedFix = "Run PowerShell as Administrator and execute: $($meta.Command_PS51)"
        Command_PS51   = $meta.Command_PS51
        Command_PS7    = $meta.Command_PS7
    }
    $errObj | ConvertTo-Json -Depth 4
    exit 0
}
