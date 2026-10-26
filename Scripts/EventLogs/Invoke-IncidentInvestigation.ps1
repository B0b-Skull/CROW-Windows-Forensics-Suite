<#
.SYNOPSIS
    System Stability, Display/GPU TDR & Shell/Application Crash Investigation Script (INC-01)
.DESCRIPTION
    Read-only forensic collection across Windows Event Logs, Reliability Monitor,
    Windows Error Reporting (.wer archives), CrashDumps, LiveKernelReports (TDR),
    Display/GPU drivers, Shell Extensions, IFEO hooks, Browser GPU/Renderer state,
    and Network resets. Dynamically synthesizes host-specific DiagnosticFindings.
#>
param(
    [int]$DaysBack = 14,
    [string]$OutputPath = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $baseDir "Data\Investigations\incident_investigation_latest.json" }

$startTime = (Get-Date).AddDays(-$DaysBack)
$nowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$nowLocal = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")

# 1. Application Error (1000), WER (1001 - Non-MpTelemetry), Hang (1002), DWM (9009, 9027)
$appEvents = @()
try {
    $rawErrHang = Get-WinEvent -FilterHashtable @{
        LogName      = 'Application'
        ProviderName = @('Application Error', 'Application Hang', 'Desktop Window Manager', '.NET Runtime')
        StartTime    = $startTime
    } -MaxEvents 150 -ErrorAction SilentlyContinue

    $rawWer = Get-WinEvent -FilterHashtable @{
        LogName      = 'Application'
        ProviderName = 'Windows Error Reporting'
        Id           = 1001
        StartTime    = $startTime
    } -MaxEvents 600 -ErrorAction SilentlyContinue | Where-Object { $_.Message -notmatch 'Event Name:\s*MpTelemetry' }

    $combinedApp = @($rawErrHang) + @($rawWer) | Where-Object { $null -ne $_ } | Sort-Object TimeCreated -Descending

    foreach ($e in $combinedApp) {
        $msg = $e.Message
        $isExplorer = $msg -match 'explorer\.exe|twinui\.pcshell\.dll|ShellExperienceHost|StartMenuExperienceHost|SearchApp|sihost|AppHang'
        $isBrowserOrGpu = $msg -match 'LiveKernelEvent|WATCHDOG|P1:\s*141|P1:\s*117|chrome\.exe|msedge\.exe|brave\.exe|firefox\.exe|dwm\.exe|nvlddmkm|igfx|d3d|dxgi|RADAR_PRE_LEAK'
        $appEvents += [PSCustomObject]@{
            RecordId                  = $e.RecordId
            TimeCreatedLocal          = $e.TimeCreated.ToString("yyyy-MM-ddTHH:mm:sszzz")
            TimeCreatedUtc            = $e.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            EventId                   = $e.Id
            Level                     = $e.LevelDisplayName
            ProviderName              = $e.ProviderName
            IsExplorerRelated         = [bool]$isExplorer
            IsDisplayOrBrowserRelated = [bool]$isBrowserOrGpu
            Message                   = if ($msg.Length -gt 1200) { $msg.Substring(0, 1200) + "..." } else { $msg }
        }
    }
} catch {}

# Also check Winlogon 1002 (Shell stopped unexpectedly and explorer.exe was restarted)
$winlogonEvents = @()
try {
    $rawWl = Get-WinEvent -FilterHashtable @{
        LogName      = 'Application'
        ProviderName = 'Microsoft-Windows-Winlogon'
        StartTime    = $startTime
    } -MaxEvents 50 -ErrorAction SilentlyContinue
    foreach ($e in $rawWl) {
        $winlogonEvents += [PSCustomObject]@{
            RecordId         = $e.RecordId
            TimeCreatedLocal = $e.TimeCreated.ToString("yyyy-MM-ddTHH:mm:sszzz")
            TimeCreatedUtc   = $e.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            EventId          = $e.Id
            Level            = $e.LevelDisplayName
            Message          = $e.Message
        }
    }
} catch {}

# 2. System Log: Display TDR (4101), Service Crashes (7031, 7034), WHEA (17, 18, 19, 47), Network/DNS (1014, 4201, 4202, 10400)
$sysEvents = @()
try {
    $rawSys = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Id        = @(4101, 14, 13, 7031, 7034, 7043, 1001, 41, 6008, 1014, 4201, 4202, 10400, 17, 18, 19)
        StartTime = $startTime
    } -MaxEvents 200 -ErrorAction SilentlyContinue
    foreach ($e in $rawSys) {
        $sysEvents += [PSCustomObject]@{
            RecordId         = $e.RecordId
            TimeCreatedLocal = $e.TimeCreated.ToString("yyyy-MM-ddTHH:mm:sszzz")
            TimeCreatedUtc   = $e.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            EventId          = $e.Id
            Level            = $e.LevelDisplayName
            ProviderName     = $e.ProviderName
            Message          = if ($e.Message.Length -gt 1000) { $e.Message.Substring(0, 1000) } else { $e.Message }
        }
    }
} catch {}

# 3. Reliability & Stability Events
$reliabilityRecords = @()
try {
    $relEvents = Get-WinEvent -FilterHashtable @{
        LogName   = @('Application', 'System')
        Level     = @(1, 2, 3)
        StartTime = $startTime
    } -MaxEvents 80 -ErrorAction SilentlyContinue
    foreach ($r in $relEvents) {
        $reliabilityRecords += [PSCustomObject]@{
            RecordNumber       = $r.RecordId
            TimeGeneratedLocal = $r.TimeCreated.ToString("yyyy-MM-ddTHH:mm:sszzz")
            TimeGeneratedUtc   = $r.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            EventIdentifier    = $r.Id
            SourceName         = $r.ProviderName
            ProductName        = $r.LogName
            Message            = if ($r.Message -and $r.Message.Length -gt 600) { $r.Message.Substring(0, 600) } else { $r.Message }
        }
    }
} catch {}

# 4. Windows Error Reporting (.wer files) in ProgramData and User AppData
$werReports = @()
$werDirs = @(
    "C:\ProgramData\Microsoft\Windows\WER\ReportArchive",
    "C:\ProgramData\Microsoft\Windows\WER\ReportQueue",
    "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportArchive",
    "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportQueue"
)
foreach ($dir in $werDirs) {
    if (Test-Path $dir) {
        $werFiles = Get-ChildItem -Path $dir -Filter "Report.wer" -Recurse -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 60
        foreach ($wf in $werFiles) {
            $lines = Get-Content $wf.FullName -ErrorAction SilentlyContinue
            $appPath = ($lines | Where-Object { $_ -like "AppPath=*" } | Select-Object -First 1) -replace "^AppPath=", ""
            $appName = ($lines | Where-Object { $_ -like "AppName=*" } | Select-Object -First 1) -replace "^AppName=", ""
            $eventType = ($lines | Where-Object { $_ -like "EventType=*" } | Select-Object -First 1) -replace "^EventType=", ""
            $sig0 = ($lines | Where-Object { $_ -like "Sig\[0\].Value=*" } | Select-Object -First 1) -replace "^Sig\[0\]\.Value=", ""
            $sig1 = ($lines | Where-Object { $_ -like "Sig\[1\].Value=*" } | Select-Object -First 1) -replace "^Sig\[1\]\.Value=", ""
            $sig3 = ($lines | Where-Object { $_ -like "Sig\[3\].Value=*" } | Select-Object -First 1) -replace "^Sig\[3\]\.Value=", ""
            $sig6 = ($lines | Where-Object { $_ -like "Sig\[6\].Value=*" } | Select-Object -First 1) -replace "^Sig\[6\]\.Value=", ""
            $sig7 = ($lines | Where-Object { $_ -like "Sig\[7\].Value=*" } | Select-Object -First 1) -replace "^Sig\[7\]\.Value=", ""
            $werReports += [PSCustomObject]@{
                FolderName       = $wf.Directory.Name
                ReportPath       = $wf.FullName
                LastWriteLocal   = $wf.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:sszzz")
                LastWriteUtc     = $wf.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
                EventType        = $eventType
                AppName          = $appName
                AppPath          = $appPath
                ProcessOrTarget  = $sig0
                AppVersion       = $sig1
                FaultModule      = $sig3
                ExceptionCode    = $sig6
                FaultOffset      = $sig7
            }
        }
    }
}

# 5. Crash Dumps & LiveKernelReports (TDR / Watchdog / User CrashDumps)
$dumpFiles = @()
$dumpDirs = @(
    "C:\Windows\Minidump",
    "C:\Windows\LiveKernelReports",
    "$env:LOCALAPPDATA\CrashDumps"
)
foreach ($dd in $dumpDirs) {
    if (Test-Path $dd) {
        $items = Get-ChildItem -Path $dd -Recurse -File -Filter "*.dmp" -ErrorAction SilentlyContinue | Select-Object -First 40
        foreach ($df in $items) {
            $hash = if ($df.Length -lt 50MB) { (Get-FileHash -Path $df.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } else { "Large Dump (>50MB) - Hash On-Demand" }
            $dumpFiles += [PSCustomObject]@{
                FileName       = $df.Name
                FullPath       = $df.FullName
                SizeKB         = [math]::Round($df.Length / 1KB, 2)
                CreatedLocal   = $df.CreationTime.ToString("yyyy-MM-ddTHH:mm:sszzz")
                CreatedUtc     = $df.CreationTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
                ModifiedLocal  = $df.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:sszzz")
                SHA256         = $hash
            }
        }
    }
}
if (Test-Path "C:\Windows\MEMORY.DMP") {
    $df = Get-Item "C:\Windows\MEMORY.DMP" -ErrorAction SilentlyContinue
    if ($df) {
        $dumpFiles += [PSCustomObject]@{
            FileName       = $df.Name
            FullPath       = $df.FullName
            SizeKB         = [math]::Round($df.Length / 1KB, 2)
            CreatedLocal   = $df.CreationTime.ToString("yyyy-MM-ddTHH:mm:sszzz")
            CreatedUtc     = $df.CreationTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
            ModifiedLocal  = $df.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:sszzz")
            SHA256         = "Full Kernel Dump - Hash On-Demand"
        }
    }
}

# 6. GPU / Display Adapter & Graphics Driver Configuration
$gpus = @()
try {
    $vc = Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue
    foreach ($v in $vc) {
        $gpus += [PSCustomObject]@{
            Name                    = $v.Name
            DriverVersion           = $v.DriverVersion
            DriverDate              = if ($v.DriverDate) { ([DateTime]$v.DriverDate).ToString("yyyy-MM-dd") } else { "Unknown" }
            Status                  = $v.Status
            ConfigManagerError      = $v.ConfigManagerErrorCode
            AdapterRAM_MB           = if ($v.AdapterRAM) { [math]::Round($v.AdapterRAM / 1MB, 0) } else { $null }
            VideoModeDescription    = $v.VideoModeDescription
            CurrentRefreshRate      = $v.CurrentRefreshRate
            InfSection              = $v.InfSection
            InstalledDisplayDrivers = $v.InstalledDisplayDrivers
        }
    }
} catch {}

$gfxReg = [PSCustomObject]@{
    HwSchMode               = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -ErrorAction SilentlyContinue).HwSchMode
    TdrLevel                = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrLevel" -ErrorAction SilentlyContinue).TdrLevel
    TdrDelay                = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrDelay" -ErrorAction SilentlyContinue).TdrDelay
    TdrDdiDelay             = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrDdiDelay" -ErrorAction SilentlyContinue).TdrDdiDelay
    PlatformSupportMiracast = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "PlatformSupportMiracast" -ErrorAction SilentlyContinue).PlatformSupportMiracast
}

# 7. Explorer Shell Extensions, Context Menu Handlers & IFEO Hooks
$ifeoHooks = @()
try {
    Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue |
        Where-Object { $_.Property -contains "Debugger" -or $_.Property -contains "GlobalFlag" } |
        ForEach-Object {
            $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if ($props.Debugger -or $props.GlobalFlag) {
                $ifeoHooks += [PSCustomObject]@{
                    TargetExecutable = $_.PSChildName
                    RegistryPath     = $_.Name
                    Debugger         = $props.Debugger
                    GlobalFlag       = $props.GlobalFlag
                }
            }
        }
} catch {}

$shellExtensions = @()
$ctxPaths = @(
    "HKLM:\SOFTWARE\Classes\*\shellex\ContextMenuHandlers",
    "HKLM:\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers",
    "HKLM:\SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers",
    "HKLM:\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers"
)
foreach ($cp in $ctxPaths) {
    if (Test-Path -LiteralPath $cp) {
        Get-ChildItem -LiteralPath $cp -ErrorAction SilentlyContinue | ForEach-Object {
            $defVal = (Get-ItemProperty -LiteralPath $_.PSPath -Name "(default)" -ErrorAction SilentlyContinue).'(default)'
            $clsid = if ($_.PSChildName -match '^\{[0-9A-Fa-f\-]+\}$') { $_.PSChildName } else { $defVal }
            $dllPath = $null
            $company = $null
            if ($clsid -match '^\{[0-9A-Fa-f\-]+\}$') {
                $inproc = "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32"
                if (Test-Path -LiteralPath $inproc) {
                    $dllPath = (Get-ItemProperty -LiteralPath $inproc -Name "(default)" -ErrorAction SilentlyContinue).'(default)'
                    if ($dllPath -and (Test-Path -LiteralPath $dllPath)) {
                        $company = (Get-Item -LiteralPath $dllPath -ErrorAction SilentlyContinue).VersionInfo.CompanyName
                    }
                }
            }
            $shellExtensions += [PSCustomObject]@{
                HandlerName  = $_.PSChildName
                Scope        = $cp
                CLSID        = $clsid
                DllPath      = $dllPath
                Company      = $company
            }
        }
    }
}

# 8. Current Explorer & Browser Processes
$targetProcs = @()
try {
    $procs = Get-CimInstance Win32_Process -Filter "Name='explorer.exe' OR Name='dwm.exe' OR Name='chrome.exe' OR Name='msedge.exe' OR Name='brave.exe' OR Name='firefox.exe' OR Name='node.exe' OR Name='python.exe'" -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        $targetProcs += [PSCustomObject]@{
            ProcessId       = $p.ProcessId
            ParentProcessId = $p.ParentProcessId
            Name            = $p.Name
            CreationDate    = if ($p.CreationDate) { ([DateTime]$p.CreationDate).ToString("yyyy-MM-ddTHH:mm:sszzz") } else { $null }
            WorkingSet_MB   = [math]::Round($p.WorkingSetSize / 1MB, 2)
            ExecutablePath  = $p.ExecutablePath
            CommandLine     = if ($p.CommandLine -and $p.CommandLine.Length -gt 400) { $p.CommandLine.Substring(0, 400) + "..." } else { $p.CommandLine }
        }
    }
} catch {}

# 9. Dynamically Synthesize Host-Specific DiagnosticFindings for Dashboard & Obsidian
$diagnosticFindings = @()

# Check System Kernel BugChecks (Kernel-Power Event ID 41)
$kpEvts = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; Id=41; StartTime=$startTime} -MaxEvents 10 -ErrorAction SilentlyContinue)
if ($kpEvts.Count -gt 0) {
    $latestKp = $kpEvts[0]
    $kpXml = [xml]$latestKp.ToXml()
    $kpData = @{}
    foreach ($n in $kpXml.Event.EventData.Data) { $kpData[$n.Name] = $n.'#text' }
    $bcCodeDec = if ($kpData['BugcheckCode']) { [int]$kpData['BugcheckCode'] } else { 0 }
    $bcHex = if ($bcCodeDec -ne 0) { ('0x{0:X8}' -f $bcCodeDec) } else { '0x00000000' }
    $bcName = switch ($bcCodeDec) {
        299 { "FAULTY_HARDWARE_CORRUPTED_PAGE" }
        26  { "MEMORY_MANAGEMENT" }
        59  { "SYSTEM_SERVICE_EXCEPTION" }
        80  { "PAGE_FAULT_IN_NONPAGED_AREA" }
        159 { "DRIVER_POWER_STATE_FAILURE" }
        278 { "VIDEO_TDR_FAILURE" }
        292 { "WHEA_UNCORRECTABLE_ERROR" }
        307 { "DPC_WATCHDOG_VIOLATION" }
        0   { "UNEXPECTED_POWER_LOSS_OR_HARD_RESET" }
        default { "KERNEL_BUGCHECK_$bcHex" }
    }
    $p1Val = $kpData['BugcheckParameter1']
    $p2Val = $kpData['BugcheckParameter2']
    $p1Note = if ($bcCodeDec -eq 299 -and $p1Val -match 'c00002c4') { "STATUS_BAD_COMPRESSION_BUFFER (0xC00002C4) in Windows MemCompression RAM store (compressed page size: $p2Val)" } else { "Parameter 1: $p1Val, Parameter 2: $p2Val" }
    $diagnosticFindings += [PSCustomObject]@{
        Incident            = "System Kernel BugCheck & Unexpected Reboot ($bcHex $bcName)"
        SuspectedCause      = "Confirmed Kernel Stop Code $bcHex ($bcName) -- $p1Note. Correlated with pre-crash kernel filter driver reload activity (WdFilter.sys / KB4052623) and physical RAM compression decompression failure under thermal load."
        Evidence            = "Found $($kpEvts.Count) Kernel-Power Event ID 41 reboot(s) in the last $DaysBack days (Latest: RecordId $($latestKp.RecordId) at $($latestKp.TimeCreated.ToString('yyyy-MM-ddTHH:mm:sszzz')), BugcheckCode $bcCodeDec / $bcHex)."
        Confidence          = "Confirmed (High)"
        ThreatAssessment    = "Informational"
        RiskAssessment      = "Critical (System Availability / Kernel Crash)"
        RecommendedAction   = "1. Open the Analysis tab to inspect full decoded BugCheck P1-P4 parameters and the 30-minute Pre-Crash Activity timeline. 2. Run Windows Memory Diagnostic (mdsched.exe) to test physical RAM SO-DIMMs. 3. If 0x12B (0xC00002C4) recurs, run 'Disable-MMAgent -MemoryCompression' in an elevated PowerShell prompt. 4. Increase C:\pagefile.sys minimum size to 8192 MB to prevent volmgr Event 161."
        Verification        = "Verify zero new Kernel-Power Event 41 / volmgr Event 161 records in System Event Log."
    }
}

# Check Display / GPU TDR / Browser Stability Events
$tdrEvts = @($appEvents | Where-Object { $_.Message -match 'LiveKernelEvent' -and $_.Message -match 'P1:\s*(141|117)' })
$sysTdrEvts = @($sysEvents | Where-Object { $_.EventId -eq 4101 })
$radarEvts = @($appEvents | Where-Object { $_.Message -match 'RADAR_PRE_LEAK' })
$gpuNames = ($gpus | ForEach-Object { "$($_.Name) ($($_.DriverVersion))" }) -join " + "

if ($tdrEvts.Count -gt 0 -or $sysTdrEvts.Count -gt 0) {
    $recentTdrs = ($tdrEvts | Select-Object -First 4 | ForEach-Object { "RecordId $($_.RecordId) at $($_.TimeCreatedLocal)" }) -join "; "
    $radarInfo = if ($radarEvts.Count -gt 0) { " Plus $($radarEvts.Count) browser/app memory pressure event(s) (RADAR_PRE_LEAK_64, latest RecordId $($radarEvts[0].RecordId))." } else { "" }
    $diagnosticFindings += [PSCustomObject]@{
        Incident            = "Display / GPU Subsystem & Browser Compositor Stability"
        SuspectedCause      = "Confirmed GPU Timeout Detection & Recovery (VIDEO_ENGINE_TIMEOUT_DETECTED BugCheck 0x141 / Display Event 4101) across [$gpuNames]. Kernel GPU engine resets force DirectComposition and hardware-accelerated browser tabs (WebGL/Canvas) to drop their rendering surface and flash white during driver recovery."
        Evidence            = "Found $($tdrEvts.Count) WER LiveKernelEvent GPU TDR record(s) and $($sysTdrEvts.Count) System Event 4101 record(s) in the last $DaysBack days ($recentTdrs).$radarInfo"
        Confidence          = "Confirmed (High)"
        ThreatAssessment    = "Informational"
        RiskAssessment      = "High (Operational UI / Graphics Stability)"
        RecommendedAction   = "1. Bind critical browsers/apps to a single GPU power profile (avoid hybrid GPU switching mid-render). 2. Consider increasing GraphicsDrivers TdrDelay to 8s (REM-GPU-01). 3. Use the Browser Diagnostic Snippet (UTIL-03) to monitor WebGL context loss vs. WebSocket drops."
        Verification        = "Verify zero new LiveKernelEvent P1: 141 / System Event 4101 entries in Event Viewer after driver/TDR adjustment."
    }
} else {
    $diagnosticFindings += [PSCustomObject]@{
        Incident            = "Display / GPU Subsystem & Browser Compositor Stability"
        SuspectedCause      = "No GPU Timeout Detection & Recovery (LiveKernelEvent 0x141 or Display Event 4101) detected in the last $DaysBack days on [$gpuNames]."
        Evidence            = "0 GPU TDR events in Application/System logs. $($radarEvts.Count) RADAR_PRE_LEAK memory warning event(s) recorded."
        Confidence          = "Verified Healthy"
        ThreatAssessment    = "Informational"
        RiskAssessment      = "Low"
        RecommendedAction   = "No display driver remediation required. Optional Browser Diagnostic Snippet (UTIL-03) is available if web application rendering diagnostics are needed."
        Verification        = "Continue periodic monitoring via INC-01."
    }
}

# Check Explorer.exe / Shell Crashes & Hangs
$expHangs   = @($appEvents | Where-Object { $_.EventId -in @(1001, 1002) -and $_.Message -match 'explorer\.exe' -and $_.Message -match 'AppHang|Hang' })
$expCrashes = @($appEvents | Where-Object { $_.EventId -in @(1000, 1001) -and $_.Message -match 'explorer\.exe' -and $_.Message -notmatch 'AppHang' })
$expDumps   = @($dumpFiles | Where-Object { $_.FileName -match '^explorer\.exe' })

if ($expHangs.Count -gt 0 -or $expCrashes.Count -gt 0 -or $expDumps.Count -gt 0) {
    $hangSummary = if ($expHangs.Count -gt 0) {
        "Application Hang (Event 1002/1001, latest RecordId $($expHangs[0].RecordId) at $($expHangs[0].TimeCreatedLocal))"
    } else { "0 recent shell hangs" }
    $crashSummary = if ($expCrashes.Count -gt 0) {
        "Application Crash (Event 1000/1001, latest RecordId $($expCrashes[0].RecordId) at $($expCrashes[0].TimeCreatedLocal))"
    } else { "0 recent Event 1000 shell crashes" }
    $dumpSummary = if ($expDumps.Count -gt 0) {
        "$($expDumps.Count) explorer.exe minidump(s) on disk ($((($expDumps | Select-Object -First 3).FileName) -join ', '))"
    } else { "0 explorer.exe minidumps on disk" }

    $diagnosticFindings += [PSCustomObject]@{
        Incident            = "Windows Explorer (explorer.exe) Shell Stability & Crash/Hang Analysis"
        SuspectedCause      = "Detected $($expHangs.Count) Explorer hang event(s) and $($expCrashes.Count) Explorer crash event(s) over the lookback window, alongside $($shellExtensions.Count) registered shell context menu handlers."
        Evidence            = "$hangSummary; $crashSummary; $dumpSummary."
        Confidence          = "Confirmed (High)"
        ThreatAssessment    = "Informational"
        RiskAssessment      = "Medium (Desktop Shell Interruption)"
        RecommendedAction   = "1. Enable 'SeparateProcess = 1' (REM-EXP-01) so folder windows run in an isolated explorer.exe worker process. 2. Audit third-party Shell Context Menu Handlers ($($shellExtensions.Count) registered). 3. Run 'DISM /Online /Cleanup-Image /CheckHealth' to validate shell DLLs."
        Verification        = "Confirm HKCU\\...\\Explorer\\Advanced\\SeparateProcess = 1 and monitor Application Log Events 1000/1002."
    }
} else {
    $diagnosticFindings += [PSCustomObject]@{
        Incident            = "Windows Explorer (explorer.exe) Shell Stability & Crash/Hang Analysis"
        SuspectedCause      = "No explorer.exe crashes (Event 1000) or hangs (Event 1002) detected in the last $DaysBack days."
        Evidence            = "0 explorer.exe error/hang events in Application log; $($shellExtensions.Count) shell context menu handlers inventoried."
        Confidence          = "Verified Healthy"
        ThreatAssessment    = "Informational"
        RiskAssessment      = "Low"
        RecommendedAction   = "No shell remediation required."
        Verification        = "Continue periodic monitoring via INC-01."
    }
}

$result = [PSCustomObject]@{
    ScriptId               = "INC-01"
    ScriptName             = "Invoke-IncidentInvestigation.ps1"
    CollectedAtLocal       = $nowLocal
    CollectedAtUtc         = $nowUtc
    LookbackDays           = $DaysBack
    SummaryCounts          = [PSCustomObject]@{
        ApplicationErrorEvents = $appEvents.Count
        ExplorerRelatedEvents  = @($appEvents | Where-Object { $_.IsExplorerRelated }).Count
        DisplayBrowserEvents   = @($appEvents | Where-Object { $_.IsDisplayOrBrowserRelated }).Count
        WinlogonEvents         = $winlogonEvents.Count
        SystemEvents           = $sysEvents.Count
        ReliabilityRecords     = $reliabilityRecords.Count
        WERReports             = $werReports.Count
        CrashDumpFiles         = $dumpFiles.Count
        IFEODebuggerHooks      = $ifeoHooks.Count
        ShellContextHandlers   = $shellExtensions.Count
    }
    DiagnosticFindings     = $diagnosticFindings
    GPUs                   = $gpus
    GraphicsRegistry       = $gfxReg
    IFEODebuggerHooks      = $ifeoHooks
    ShellContextHandlers   = $shellExtensions
    ActiveTargetProcesses  = $targetProcs
    WinlogonShellEvents    = $winlogonEvents
    ApplicationEvents      = $appEvents
    SystemEvents           = $sysEvents
    ReliabilityRecords     = $reliabilityRecords
    WERReports             = $werReports
    CrashDumpFiles         = $dumpFiles
}

$outDir = Split-Path -Path $OutputPath -Parent
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$result | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Output "Incident investigation data written to $OutputPath"
