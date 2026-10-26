<#
.SYNOPSIS
    Performance & Resource Telemetry Script (PERF-01)
.DESCRIPTION
    Collects system-wide and per-process CPU, Working Set, Private Bytes, Commit Size,
    GPU Engine & Process VRAM utilization, Disk I/O latency, Network throughput,
    Handle/Thread counts, and Page Faults.
    Supports both one-time snapshots and bounded-duration sampling. Read-only.
#>
param(
    [int]$SampleCount = 1,
    [int]$SampleIntervalSeconds = 2,
    [int]$TopProcessCount = 40,
    [string]$OutputPath = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $baseDir "Data\Telemetry\performance_telemetry_latest.json" }
if ($SampleCount -lt 1) { $SampleCount = 1 }
if ($SampleCount -gt 15) { $SampleCount = 15 }

$nowLocal = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
$nowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$logicalCpus = [int]$cs.NumberOfLogicalProcessors
if ($logicalCpus -lt 1) { $logicalCpus = 1 }

# 1. Bounded-duration or Snapshot System Series
$samples = @()
for ($i = 0; $i -lt $SampleCount; $i++) {
    if ($i -gt 0) { Start-Sleep -Seconds $SampleIntervalSeconds }
    $ts = (Get-Date).ToString("HH:mm:ss")
    $cpuLoad = (Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    $osSnap = Get-CimInstance -ClassName Win32_OperatingSystem
    $memCounter = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Memory
    $diskCounter = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'"
    $netCounters = Get-CimInstance -ClassName Win32_PerfFormattedData_Tcpip_NetworkInterface

    $totalRamMB = [math]::Round($cs.TotalPhysicalMemory / 1MB, 0)
    $freeRamMB  = [math]::Round($osSnap.FreePhysicalMemory / 1KB, 0)
    $usedRamMB  = $totalRamMB - $freeRamMB

    $netRecvKBps = if ($netCounters) { [math]::Round((($netCounters | Measure-Object -Property BytesReceivedPersec -Sum).Sum) / 1KB, 2) } else { 0 }
    $netSentKBps = if ($netCounters) { [math]::Round((($netCounters | Measure-Object -Property BytesSentPersec -Sum).Sum) / 1KB, 2) } else { 0 }

    $samples += [PSCustomObject]@{
        SampleIndex          = $i + 1
        Timestamp            = $ts
        CPU_Percent          = if ($null -ne $cpuLoad) { [math]::Round($cpuLoad, 1) } else { 0 }
        RAM_Used_MB          = $usedRamMB
        RAM_Available_MB     = $freeRamMB
        RAM_Used_Percent     = if ($totalRamMB -gt 0) { [math]::Round(($usedRamMB / $totalRamMB) * 100, 1) } else { 0 }
        Committed_MB         = if ($memCounter) { [math]::Round($memCounter.CommittedBytes / 1MB, 0) } else { 0 }
        CommitLimit_MB       = if ($memCounter) { [math]::Round($memCounter.CommitLimit / 1MB, 0) } else { 0 }
        PageFaultsPerSec     = if ($memCounter) { $memCounter.PageFaultsPersec } else { 0 }
        PagesPerSec_HardFaults = if ($memCounter) { $memCounter.PagesPersec } else { 0 }
        PoolNonpaged_MB      = if ($memCounter) { [math]::Round($memCounter.PoolNonpagedBytes / 1MB, 1) } else { 0 }
        PoolPaged_MB         = if ($memCounter) { [math]::Round($memCounter.PoolPagedBytes / 1MB, 1) } else { 0 }
        Disk_Read_KBps       = if ($diskCounter) { [math]::Round($diskCounter.DiskReadBytesPersec / 1KB, 1) } else { 0 }
        Disk_Write_KBps      = if ($diskCounter) { [math]::Round($diskCounter.DiskWriteBytesPersec / 1KB, 1) } else { 0 }
        Disk_QueueLength     = if ($diskCounter) { $diskCounter.CurrentDiskQueueLength } else { 0 }
        Disk_AvgSecPerRead_ms= if ($diskCounter) { [math]::Round($diskCounter.AvgDisksecPerRead * 1000, 2) } else { 0 }
        Disk_AvgSecPerWrite_ms= if ($diskCounter) { [math]::Round($diskCounter.AvgDisksecPerWrite * 1000, 2) } else { 0 }
        Net_Recv_KBps        = $netRecvKBps
        Net_Sent_KBps        = $netSentKBps
    }
}

# 2. Per-Process GPU Utilization & VRAM Mapping (by PID)
$gpuMemByPid = @{}
$gpuUtilByPid = @{}
try {
    $gpuProcMem = Get-CimInstance -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUProcessMemory -ErrorAction SilentlyContinue
    foreach ($gm in $gpuProcMem) {
        if ($gm.Name -match 'pid_(\d+)_') {
            $pidVal = [int]$Matches[1]
            $dedMB = [math]::Round($gm.DedicatedUsage / 1MB, 2)
            $shrMB = [math]::Round($gm.SharedUsage / 1MB, 2)
            if (!$gpuMemByPid.ContainsKey($pidVal) -or ($dedMB + $shrMB) -gt ($gpuMemByPid[$pidVal].Dedicated_MB + $gpuMemByPid[$pidVal].Shared_MB)) {
                $gpuMemByPid[$pidVal] = @{ Dedicated_MB = $dedMB; Shared_MB = $shrMB }
            }
        }
    }

    $gpuEng = Get-CimInstance -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine -ErrorAction SilentlyContinue |
        Where-Object { $_.UtilizationPercentage -gt 0 }
    foreach ($ge in $gpuEng) {
        if ($ge.Name -match 'pid_(\d+)_') {
            $pidVal = [int]$Matches[1]
            if (!$gpuUtilByPid.ContainsKey($pidVal)) { $gpuUtilByPid[$pidVal] = 0 }
            $gpuUtilByPid[$pidVal] += $ge.UtilizationPercentage
        }
    }
} catch {}

# 3. Per-Process CPU, Memory, Handle, Thread, Page Faults
$perfProcMap = @{}
try {
    $perfProcs = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfProc_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.IDProcess -ne 0 -and $_.Name -ne '_Total' -and $_.Name -ne 'Idle' }
    foreach ($pp in $perfProcs) {
        $perfProcMap[[int]$pp.IDProcess] = $pp
    }
} catch {}

$processMetrics = @()
$rawProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne 0 -and $_.Id -ne 4 }
foreach ($p in $rawProcs) {
    $pidVal = [int]$p.Id
    $pp = $perfProcMap[$pidVal]
    $cpuPct = if ($pp -and $pp.PercentProcessorTime) { [math]::Round($pp.PercentProcessorTime / $logicalCpus, 2) } else { 0 }
    $ioBytesPerSec = if ($pp -and $pp.IODataBytesPersec) { [math]::Round($pp.IODataBytesPersec / 1KB, 2) } else { 0 }
    $pageFaultsSec = if ($pp -and $pp.PageFaultsPersec) { $pp.PageFaultsPersec } else { 0 }
    $gpuMem = if ($gpuMemByPid.ContainsKey($pidVal)) { $gpuMemByPid[$pidVal] } else { @{ Dedicated_MB = 0; Shared_MB = 0 } }
    $gpuPct = if ($gpuUtilByPid.ContainsKey($pidVal)) { [math]::Round($gpuUtilByPid[$pidVal], 1) } else { 0 }

    $processMetrics += [PSCustomObject]@{
        PID                 = $pidVal
        ProcessName         = $p.ProcessName
        CPU_Percent         = $cpuPct
        TotalCPU_Seconds    = if ($p.CPU) { [math]::Round($p.CPU, 2) } else { 0 }
        WorkingSet_MB       = [math]::Round($p.WorkingSet64 / 1MB, 2)
        PrivateBytes_MB     = [math]::Round($p.PrivateMemorySize64 / 1MB, 2)
        CommitSize_MB       = [math]::Round($p.PagedMemorySize64 / 1MB, 2)
        PeakWorkingSet_MB   = [math]::Round($p.PeakWorkingSet64 / 1MB, 2)
        GPU_Percent         = $gpuPct
        GPU_Dedicated_MB    = $gpuMem.Dedicated_MB
        GPU_Shared_MB       = $gpuMem.Shared_MB
        IO_KBps             = $ioBytesPerSec
        HandleCount         = $p.Handles
        ThreadCount         = if ($p.Threads) { $p.Threads.Count } else { 0 }
        PageFaultsPerSec    = $pageFaultsSec
        StartTime           = if ($p.StartTime) { $p.StartTime.ToString("yyyy-MM-ddTHH:mm:sszzz") } else { "Restricted/System" }
    }
}

$topByRAM = $processMetrics | Sort-Object WorkingSet_MB -Descending | Select-Object -First $TopProcessCount
$topByCPU = $processMetrics | Sort-Object CPU_Percent, TotalCPU_Seconds -Descending | Select-Object -First 20
$topByGPU = $processMetrics | Where-Object { $_.GPU_Dedicated_MB -gt 0 -or $_.GPU_Percent -gt 0 } | Sort-Object GPU_Dedicated_MB -Descending | Select-Object -First 20

$telemetry = [PSCustomObject]@{
    ScriptId          = "PERF-01"
    ScriptName        = "Get-PerformanceTelemetry.ps1"
    CollectedAtLocal  = $nowLocal
    CollectedAtUtc    = $nowUtc
    LogicalProcessors = $logicalCpus
    LatestSnapshot    = $samples[-1]
    TimeSeriesSamples = $samples
    TopProcessesByRAM = $topByRAM
    TopProcessesByCPU = $topByCPU
    TopProcessesByGPU = $topByGPU
    TotalProcessCount = $rawProcs.Count
}

$outDir = Split-Path -Path $OutputPath -Parent
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$telemetry | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Output "Performance telemetry written to $OutputPath"
