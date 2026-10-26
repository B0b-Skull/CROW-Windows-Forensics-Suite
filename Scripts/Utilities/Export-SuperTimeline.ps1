<#
.SYNOPSIS
    Unified Forensic Super-Timeline & Incident Chronology Generator (UTIL-04)
.DESCRIPTION
    Merges timestamps across all forensic telemetry sources into a single chronologically
    sorted Super-Timeline (JSON + CSV compatible with Excel & Timeline Explorer):
      - Process Creation Timestamps (PROC-01 / CORR-01)
      - Network TCP/UDP Socket Creation Timestamps (NET-01)
      - Multi-Channel Windows Event Logs (EVT-01)
      - Stability & Incident Events (INC-01)
      - Crash Dump Creation & GPU TDR Timestamps (MEM-01)
      - Scheduled Task LastRunTime & PowerShell 4104 ScriptBlock Logs (MAL-02)
#>
param(
    [int]$MaxTimelineEntries = 500,
    [string]$OutputPath = "$PSScriptRoot\..\..\Data\Investigations\super_timeline_latest.json"
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir  = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$nowLocal = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
$nowUtc   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

function Read-JsonSafe([string]$p) {
    if (Test-Path $p) {
        try { return (Get-Content $p -Raw | ConvertFrom-Json) } catch { return $null }
    }
    return $null
}

function Convert-ToSortableUtc([string]$tsStr) {
    if ([string]::IsNullOrWhiteSpace($tsStr) -or $tsStr -match 'Unknown|Never|Not ') { return $null }
    try {
        $dt = [DateTimeOffset]::Parse($tsStr)
        return $dt.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
    } catch {
        return $null
    }
}

$corrData = Read-JsonSafe "$baseDir\Data\Inventory\correlated_entities_latest.json"
$netData  = Read-JsonSafe "$baseDir\Data\Inventory\network_forensics_latest.json"
$evtData  = Read-JsonSafe "$baseDir\Data\Telemetry\event_forensics_latest.json"
$memData  = Read-JsonSafe "$baseDir\Data\Investigations\memory_crash_forensics_latest.json"
$mal2Data = Read-JsonSafe "$baseDir\Data\Investigations\deep_persistence_scriptblock_latest.json"

$rawTimeline = New-Object System.Collections.Generic.List[object]

# 1. Process Creation Events (CORR-01)
if ($corrData -and $corrData.Entities) {
    foreach ($p in $corrData.Entities) {
        $utc = Convert-ToSortableUtc ([string]$p.StartTime)
        if (-not $utc) { continue }
        $rawTimeline.Add([PSCustomObject]@{
            TimestampUtc      = $utc
            TimestampLocal    = [string]$p.StartTime
            ArtifactType      = "Process Creation"
            SourceModule      = "CORR-01"
            EntityOrEvent     = "$($p.ProcessName) (PID $($p.PID))"
            PID_Or_RecordId   = "PID $($p.PID) (PPID $($p.PPID))"
            SeverityOrThreat  = [string]$p.ThreatAssessment
            Summary           = "Parent: $($p.ParentProcess) | Sig: $($p.SignatureStatus) ($($p.Publisher)) | Cmd: $($p.CommandLine)"
            BinaryPath        = [string]$p.BinaryPath
            SHA256            = [string]$p.SHA256
            Explanation       = "Process '$($p.ProcessName)' started at $($p.StartTime) under parent '$($p.ParentProcess)'."
            RecommendedAction = "Click VT to check SHA-256 ($($p.SHA256)) on VirusTotal or inspect associated services ($($p.Services)) and network sockets ($($p.Network))."
        })
    }
}

# 2. Network Socket Creation Timestamps (NET-01)
if ($netData -and $netData.TCPConnections) {
    foreach ($c in $netData.TCPConnections) {
        $utc = Convert-ToSortableUtc ([string]$c.ConnectionStartTime)
        if (-not $utc) { continue }
        $rawTimeline.Add([PSCustomObject]@{
            TimestampUtc      = $utc
            TimestampLocal    = [string]$c.ConnectionStartTime
            ArtifactType      = "Network Socket"
            SourceModule      = "NET-01"
            EntityOrEvent     = "$($c.ProcessName) ($($c.State))"
            PID_Or_RecordId   = "PID $($c.PID)"
            SeverityOrThreat  = [string]$c.ExposureRisk
            Summary           = "$($c.LocalAddress):$($c.LocalPort) -> $($c.RemoteAddress):$($c.RemotePort) | Org: $($c.ASN_Organization) ($($c.Country))"
            BinaryPath        = [string]$c.BinaryPath
            SHA256            = ""
            Explanation       = "TCP socket ($($c.State)) bound/established by '$($c.ProcessName)' to remote endpoint $($c.RemoteAddress):$($c.RemotePort)."
            RecommendedAction = "Inspect remote IP reputation on VirusTotal/AbuseIPDB and verify owning process binary '$($c.BinaryPath)'."
        })
    }
}

# 3. Multi-Channel Windows Event Logs (EVT-01)
if ($evtData -and $evtData.Events) {
    foreach ($e in $evtData.Events) {
        $utc = if ($e.TimeCreatedUtc) { [string]$e.TimeCreatedUtc } else { Convert-ToSortableUtc ([string]$e.TimeCreatedLocal) }
        if (-not $utc) { continue }
        $msgShort = ([string]$e.Message -replace '\r?\n', ' ').Trim()
        if ($msgShort.Length -gt 240) { $msgShort = $msgShort.Substring(0, 240) + "..." }
        $rawTimeline.Add([PSCustomObject]@{
            TimestampUtc      = $utc
            TimestampLocal    = [string]$e.TimeCreatedLocal
            ArtifactType      = "Windows Event Log"
            SourceModule      = "EVT-01"
            EntityOrEvent     = "[$($e.Channel)] Event $($e.EventId)"
            PID_Or_RecordId   = "Rec $($e.RecordId) / PID $($e.ProcessId)"
            SeverityOrThreat  = [string]$e.Severity
            Summary           = "Provider: $($e.ProviderName) | $msgShort"
            BinaryPath        = ""
            SHA256            = ""
            Explanation       = "Windows Event ID $($e.EventId) ($($e.Severity)) logged by $($e.ProviderName) in $($e.Channel)."
            RecommendedAction = "Correlate this event timestamp with nearby Process Creation, Network Socket, or Crash Dump entries in the Super-Timeline."
        })
    }
}

# 4. System Kernel Crashes, Crash Dumps & GPU TDR Kernel Events (MEM-01)
if ($memData) {
    if ($memData.SystemCrashHistory) {
        foreach ($sc in $memData.SystemCrashHistory) {
            $utc = if ($sc.RebootTimestampUtc) { [string]$sc.RebootTimestampUtc } else { Convert-ToSortableUtc ([string]$sc.RebootTimestampLocal) }
            if (-not $utc) { continue }
            $rawTimeline.Add([PSCustomObject]@{
                TimestampUtc      = $utc
                TimestampLocal    = [string]$sc.RebootTimestampLocal
                ArtifactType      = "System Crash / BugCheck"
                SourceModule      = "MEM-01"
                EntityOrEvent     = "$($sc.StopCodeHex) ($($sc.StopCodeName))"
                PID_Or_RecordId   = "Rec $($sc.KernelPowerRecordId)"
                SeverityOrThreat  = [string]$sc.RiskAssessment
                Summary           = "P1: $($sc.Parameter1) | Pre-Crash Trigger: $($sc.PreCrashTriggerSummary) | Dump: $($sc.DumpCreationStatus)"
                BinaryPath        = "C:\Windows\System32\ntoskrnl.exe"
                SHA256            = ""
                Explanation       = [string]$sc.RootCauseAnalysis
                RecommendedAction = "Open the Analysis tab to inspect the full decoded 64-bit BugCheck parameters and 30-minute Pre-Crash Activity timeline."
            })
        }
    }
    if ($memData.DumpInventory) {
        foreach ($d in $memData.DumpInventory) {
            $tsLocal = if ($d.ModifiedLocal) { [string]$d.ModifiedLocal } else { [string]$d.CreatedLocal }
            $utc = if ($d.ModifiedUtc) { [string]$d.ModifiedUtc } elseif ($d.CreatedUtc) { [string]$d.CreatedUtc } else { Convert-ToSortableUtc $tsLocal }
            if (-not $utc) { continue }
            $rawTimeline.Add([PSCustomObject]@{
                TimestampUtc      = $utc
                TimestampLocal    = $tsLocal
                ArtifactType      = "Crash Dump Artifact"
                SourceModule      = "MEM-01"
                EntityOrEvent     = "$($d.FileName) ($($d.TargetProcess))"
                PID_Or_RecordId   = "$($d.Size_MB) MB"
                SeverityOrThreat  = [string]$d.RiskAssessment
                Summary           = "Category: $($d.Category) | Exception: $($d.ExceptionCode) | FaultModule: $($d.FaultingModule) | $($d.AnalysisSummary)"
                BinaryPath        = [string]$d.FullPath
                SHA256            = [string]$d.SHA256
                Explanation       = [string]$d.AnalysisSummary
                RecommendedAction = "Inspect surrounding Windows Event Log and Process Creation entries within +/- 60 seconds of this dump timestamp."
            })
        }
    }
    if ($memData.SystemCrashHistory) {
        foreach ($sc in $memData.SystemCrashHistory) {
            $tsLocal = [string]$sc.CrashTimeLocal
            $utc = Convert-ToSortableUtc $tsLocal
            if (-not $utc) { continue }
            $rawTimeline.Add([PSCustomObject]@{
                TimestampUtc      = $utc
                TimestampLocal    = $tsLocal
                ArtifactType      = "System Crash / BugCheck"
                SourceModule      = "MEM-01"
                EntityOrEvent     = "$($sc.BugCheckHex) $($sc.StopCodeName)"
                PID_Or_RecordId   = "Event 41 ($($sc.FaultModule))"
                SeverityOrThreat  = [string]$sc.RiskAssessment
                Summary           = "BugCheck $($sc.BugCheckHex) ($($sc.StopCodeName)) | SubStatus: $($sc.SubStatusHex) ($($sc.SubStatusName)) | $($sc.RootCauseTitle)"
                BinaryPath        = [string]$sc.DumpFile
                SHA256            = ""
                Explanation       = [string]$sc.PrimaryDiagnosis
                RecommendedAction = [string]$sc.RemediationSteps
            })
        }
    }
    if ($memData.GPUTDRKernelEvents) {
        foreach ($tdr in $memData.GPUTDRKernelEvents) {
            $utc = if ($tdr.TimestampUtc) { [string]$tdr.TimestampUtc } else { Convert-ToSortableUtc ([string]$tdr.TimestampLocal) }
            if (-not $utc) { continue }
            $rawTimeline.Add([PSCustomObject]@{
                TimestampUtc      = $utc
                TimestampLocal    = [string]$tdr.TimestampLocal
                ArtifactType      = "GPU TDR Watchdog"
                SourceModule      = "MEM-01"
                EntityOrEvent     = [string]$tdr.EventName
                PID_Or_RecordId   = "WER $($tdr.RecordId)"
                SeverityOrThreat  = "High"
                Summary           = "Kernel Watchdog Dump: $($tdr.DumpFileReferenced) | Retention: $($tdr.StatusOnDisk)"
                BinaryPath        = ""
                SHA256            = ""
                Explanation       = "Windows DirectX Graphics Kernel detected a GPU timeout (LiveKernelEvent 141) and reset the display driver."
                RecommendedAction = "Review View 10 (REM-GPU-01_TdrDelayIncrease) if hybrid GPU power transitions cause recurring TDR resets."
            })
        }
    }
}

# 5. Scheduled Task Executions & PowerShell 4104 ScriptBlocks (MAL-02)
if ($mal2Data) {
    if ($mal2Data.ScheduledTasks) {
        foreach ($st in $mal2Data.ScheduledTasks) {
            $utc = Convert-ToSortableUtc ([string]$st.LastRunTime)
            if (-not $utc) { continue }
            $rawTimeline.Add([PSCustomObject]@{
                TimestampUtc      = $utc
                TimestampLocal    = [string]$st.LastRunTime
                ArtifactType      = "Scheduled Task Run"
                SourceModule      = "MAL-02"
                EntityOrEvent     = "$($st.TaskName)"
                PID_Or_RecordId   = "Result $($st.LastTaskResult)"
                SeverityOrThreat  = [string]$st.ThreatAssessment
                Summary           = "Path: $($st.TaskPath) | Cmd: $($st.ExecuteCommand) $($st.Arguments) | Sig: $($st.SignatureStatus)"
                BinaryPath        = [string]$st.BinaryPath
                SHA256            = [string]$st.SHA256
                Explanation       = [string]$st.Explanation
                RecommendedAction = [string]$st.RecommendedAction
            })
        }
    }
    if ($mal2Data.PowerShellScriptLogs) {
        foreach ($sb in ($mal2Data.PowerShellScriptLogs | Select-Object -First 60)) {
            $utc = if ($sb.TimeCreatedUtc) { [string]$sb.TimeCreatedUtc } else { Convert-ToSortableUtc ([string]$sb.TimeCreatedLocal) }
            if (-not $utc) { continue }
            $rawTimeline.Add([PSCustomObject]@{
                TimestampUtc      = $utc
                TimestampLocal    = [string]$sb.TimeCreatedLocal
                ArtifactType      = "PowerShell ScriptBlock"
                SourceModule      = "MAL-02"
                EntityOrEvent     = "PS Event $($sb.EventId) ($($sb.DetectedPatterns))"
                PID_Or_RecordId   = "PID $($sb.ProcessId) / Rec $($sb.RecordId)"
                SeverityOrThreat  = [string]$sb.ThreatAssessment
                Summary           = [string]$sb.ScriptBlockPreview
                BinaryPath        = ""
                SHA256            = ""
                Explanation       = [string]$sb.Explanation
                RecommendedAction = [string]$sb.RecommendedAction
            })
        }
    }
}

$sortedTimeline = @($rawTimeline | Sort-Object TimestampUtc -Descending | Select-Object -First $MaxTimelineEntries)

# Export Super-Timeline CSV to Reports\CSV
$csvDir = Join-Path $baseDir "Reports\CSV"
if (!(Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }
$csvLatestPath = Join-Path $csvDir "SuperTimeline_Latest.csv"
$sortedTimeline | Export-Csv -Path $csvLatestPath -NoTypeInformation -Encoding UTF8

$byType = @{}
foreach ($item in $sortedTimeline) {
    $t = [string]$item.ArtifactType
    if ($byType.ContainsKey($t)) { $byType[$t]++ } else { $byType[$t] = 1 }
}

$payload = [PSCustomObject]@{
    ScriptId          = "UTIL-04"
    ScriptName        = "Export-SuperTimeline.ps1"
    Status            = "Success"
    GeneratedAtLocal  = $nowLocal
    GeneratedAtUtc    = $nowUtc
    TotalEntries      = $sortedTimeline.Count
    CsvExportPath     = $csvLatestPath
    BreakdownByType   = $byType
    Explanation       = "Merged and chronologically sorted $($sortedTimeline.Count) forensic events across Processes, Network Sockets, Windows Event Logs, Crash Dumps, Scheduled Tasks, and PowerShell 4104 ScriptBlocks."
    RecommendedFix    = "Use the Super-Timeline table in View 4 (Windows Events & Super-Timeline) or open Reports\CSV\SuperTimeline_Latest.csv in Excel / Timeline Explorer to correlate activity around any incident timestamp."
    TimelineEntries   = $sortedTimeline
}

$outDir = Split-Path -Path $OutputPath -Parent
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$payload | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Output "Super-Timeline generated with $($sortedTimeline.Count) entries -> $OutputPath and $csvLatestPath"
