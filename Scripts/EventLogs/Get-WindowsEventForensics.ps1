<#
.SYNOPSIS
    Multi-Channel Windows Event Log Collection & Correlation Script (EVT-01)
.DESCRIPTION
    Collects and correlates events across System, Application, Security (if elevated),
    Setup, Windows Defender Operational, PowerShell Operational, Sysmon (if present),
    and Graphics/WER channels. Performs crash clustering and repeated error detection. Read-only.
#>
param(
    [int]$DaysBack = 7,
    [int]$MaxPerChannel = 60,
    [int[]]$EventIds = @(),
    [string]$OutputPath = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $baseDir "Data\Telemetry\event_forensics_latest.json" }
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$startTime = (Get-Date).AddDays(-$DaysBack)
$nowLocal = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
$nowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$channels = @(
    @{ Name = "System"; LogName = "System"; Levels = @(1, 2, 3) },
    @{ Name = "Application"; LogName = "Application"; Levels = @(1, 2, 3) },
    @{ Name = "Setup"; LogName = "Setup"; Levels = @(1, 2, 3, 4) },
    @{ Name = "Windows Defender"; LogName = "Microsoft-Windows-Windows Defender/Operational"; Levels = @(1, 2, 3, 4) },
    @{ Name = "PowerShell Operational"; LogName = "Microsoft-Windows-PowerShell/Operational"; Levels = @(1, 2, 3) },
    @{ Name = "RestartManager"; LogName = "Microsoft-Windows-RestartManager/Operational"; Levels = @(1, 2, 3, 4) },
    @{ Name = "Sysmon"; LogName = "Microsoft-Windows-Sysmon/Operational"; Levels = @(1, 2, 3, 4) },
    @{ Name = "Security"; LogName = "Security"; Levels = @(1, 2, 3, 4); RequiresAdmin = $true }
)

$channelStatus = @()
$allEvents = @()

foreach ($ch in $channels) {
    if ($ch.RequiresAdmin -and !$isAdmin) {
        $channelStatus += [PSCustomObject]@{
            Channel      = $ch.Name
            LogName      = $ch.LogName
            Status       = "PermissionRestricted (Requires Administrator Elevation)"
            EventsPulled = 0
        }
        continue
    }

    $logMeta = Get-WinEvent -ListLog $ch.LogName -ErrorAction SilentlyContinue
    if (!$logMeta -or !$logMeta.IsEnabled) {
        $channelStatus += [PSCustomObject]@{
            Channel      = $ch.Name
            LogName      = $ch.LogName
            Status       = "Not Installed or Disabled"
            EventsPulled = 0
        }
        continue
    }

    $filter = @{
        LogName   = $ch.LogName
        StartTime = $startTime
    }
    if ($EventIds -and $EventIds.Count -gt 0) {
        $filter['Id'] = $EventIds
    } elseif ($ch.LogName -ne "Security") {
        $filter['Level'] = $ch.Levels
    } else {
        $filter['Id'] = @(4624, 4625, 4648, 4672, 4688, 4697, 4698, 4720, 4732, 1102)
    }

    $evts = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxPerChannel -ErrorAction SilentlyContinue)
    $channelStatus += [PSCustomObject]@{
        Channel      = $ch.Name
        LogName      = $ch.LogName
        Status       = "Collected"
        EventsPulled = $evts.Count
    }

    foreach ($e in $evts) {
        $sev = switch ($e.Level) {
            1 { "Critical" }
            2 { "Error" }
            3 { "Warning" }
            4 { "Information" }
            default { "Information" }
        }
        $msg = if ($e.Message) { ($e.Message -replace '\r\n', ' ').Trim() } else { "No formatted message" }
        $allEvents += [PSCustomObject]@{
            RecordId         = $e.RecordId
            Channel          = $ch.Name
            LogName          = $e.LogName
            TimeCreatedLocal = $e.TimeCreated.ToString("yyyy-MM-ddTHH:mm:sszzz")
            TimeCreatedUtc   = $e.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            EventId          = $e.Id
            Severity         = $sev
            ProviderName     = $e.ProviderName
            ProcessId        = $e.ProcessId
            Message          = if ($msg.Length -gt 800) { $msg.Substring(0, 800) + "..." } else { $msg }
        }
    }
}

# Sort all events newest first
$allEvents = $allEvents | Sort-Object TimeCreatedUtc -Descending

# Repeated Error & Crash Clustering
$clusters = $allEvents | Group-Object Channel, ProviderName, EventId | ForEach-Object {
    $first = $_.Group[0]
    [PSCustomObject]@{
        Channel       = $first.Channel
        ProviderName  = $first.ProviderName
        EventId       = $first.EventId
        Severity      = $first.Severity
        Occurrences   = $_.Count
        FirstSeenLocal= ($_.Group | Select-Object -Last 1).TimeCreatedLocal
        LastSeenLocal = $first.TimeCreatedLocal
        SampleMessage = if ($first.Message.Length -gt 240) { $first.Message.Substring(0, 240) + "..." } else { $first.Message }
    }
} | Sort-Object Occurrences -Descending

$sevCounts = [PSCustomObject]@{
    Critical    = @($allEvents | Where-Object { $_.Severity -eq 'Critical' }).Count
    Error       = @($allEvents | Where-Object { $_.Severity -eq 'Error' }).Count
    Warning     = @($allEvents | Where-Object { $_.Severity -eq 'Warning' }).Count
    Information = @($allEvents | Where-Object { $_.Severity -eq 'Information' }).Count
}

$output = [PSCustomObject]@{
    ScriptId          = "EVT-01"
    ScriptName        = "Get-WindowsEventForensics.ps1"
    CollectedAtLocal  = $nowLocal
    CollectedAtUtc    = $nowUtc
    LookbackDays      = $DaysBack
    IsElevatedAdmin   = $isAdmin
    SeveritySummary   = $sevCounts
    ChannelStatus     = $channelStatus
    EventClusters     = $clusters
    Events            = $allEvents
}

$outDir = Split-Path -Path $OutputPath -Parent
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$output | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Output "Event forensics written to $OutputPath ($($allEvents.Count) events across $($channelStatus.Count) channels)"
