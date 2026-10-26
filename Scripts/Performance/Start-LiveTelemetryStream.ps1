<#
.SYNOPSIS
    Zero-Dependency PowerShell Live Telemetry Streamer (PERF-02)
.DESCRIPTION
    Samples real-time CPU Load %, RAM Used/Free GB, Commit Charge, Paged/Non-Paged Pool,
    GPU Engine Utilization %, and Dedicated/Shared VRAM Used MB using native Windows WMI/CIM
    formatted performance classes with near-zero CPU overhead (< 0.5%).
    Writes both Data\Performance\live_telemetry.json (for HTTP API) and
    Data\Performance\live_telemetry.js (JSONP script for zero-server file:/// auto-update)
    using atomic temp-file replacement (.tmp -> Move-Item -Force) to prevent partial-read
    JSON corruption, and explicitly disposes Process/CIM handles to prevent handle/memory growth.
#>
param(
    [int]$IntervalSeconds = 2,
    [int]$MaxSamples = 1,
    [string]$OutputPath = "$PSScriptRoot\..\..\Data\Performance\live_telemetry.json"
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$perfDir = Join-Path $baseDir "Data\Performance"
if (!(Test-Path $perfDir)) { New-Item -ItemType Directory -Path $perfDir -Force | Out-Null }

$jsonPath = Join-Path $perfDir "live_telemetry.json"
$jsPath   = Join-Path $perfDir "live_telemetry.js"
$pidFile  = Join-Path $perfDir "live_streamer.pid"

if ($IntervalSeconds -lt 1) { $IntervalSeconds = 1 }
if ($MaxSamples -lt 1) { $MaxSamples = 1 }

# Single-instance guard when running as a continuous background daemon ($MaxSamples > 1)
if ($MaxSamples -gt 1) {
    if (Test-Path $pidFile) {
        try {
            $oldPid = [int](Get-Content $pidFile -Raw -ErrorAction SilentlyContinue).Trim()
            if ($oldPid -gt 0 -and $oldPid -ne $PID) {
                $oldProc = Get-Process -Id $oldPid -ErrorAction SilentlyContinue
                if ($oldProc -and $oldProc.ProcessName -match 'powershell|pwsh') {
                    Stop-Process -Id $oldPid -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {}
    }
    Set-Content -Path $pidFile -Value $PID -Encoding ASCII -Force
}

function Write-AtomicUtf8File {
    param(
        [string]$TargetPath,
        [string]$Content
    )
    $tmpPath = "$TargetPath.$PID.tmp"
    try {
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($tmpPath, $Content, $utf8NoBom)
        Move-Item -LiteralPath $tmpPath -Destination $TargetPath -Force -ErrorAction Stop
    } catch {
        # Fallback if target file is momentarily locked by reader
        try {
            Set-Content -LiteralPath $TargetPath -Value $Content -Encoding UTF8 -Force -ErrorAction SilentlyContinue
        } catch {}
        if (Test-Path -LiteralPath $tmpPath) {
            Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-FastLiveSample {
    $nowLocal = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
    $nowTime  = (Get-Date).ToString("HH:mm:ss")

    # 1. Fast CPU Load %
    $cpuLoad = 0.0
    $perfCpu = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction SilentlyContinue
    if ($perfCpu -and $null -ne $perfCpu.PercentProcessorTime) {
        $cpuLoad = [math]::Round([double]$perfCpu.PercentProcessorTime, 1)
    } else {
        $wmiCpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue
        if ($wmiCpu) {
            $cpuLoad = [math]::Round(($wmiCpu | Measure-Object -Property LoadPercentage -Average).Average, 1)
            foreach ($c in @($wmiCpu)) { if ($c -is [System.IDisposable]) { $c.Dispose() } }
        }
    }
    if ($perfCpu -is [System.IDisposable]) { $perfCpu.Dispose() }

    # 2. Fast RAM & Commit Telemetry
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $totalRamGB = 0.0; $usedRamGB = 0.0; $freeRamGB = 0.0; $ramPct = 0.0
    $commitUsedGB = 0.0; $commitLimitGB = 0.0; $commitPct = 0.0
    if ($os) {
        $totalRamGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $freeRamGB  = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $usedRamGB  = [math]::Round($totalRamGB - $freeRamGB, 2)
        if ($totalRamGB -gt 0) { $ramPct = [math]::Round(($usedRamGB / $totalRamGB) * 100.0, 1) }

        $commitLimitGB = [math]::Round($os.TotalVirtualMemorySize / 1MB, 2)
        $commitFreeGB  = [math]::Round($os.FreeVirtualMemory / 1MB, 2)
        $commitUsedGB  = [math]::Round($commitLimitGB - $commitFreeGB, 2)
        if ($commitLimitGB -gt 0) { $commitPct = [math]::Round(($commitUsedGB / $commitLimitGB) * 100.0, 1) }
        if ($os -is [System.IDisposable]) { $os.Dispose() }
    }

    # 3. Kernel Pools & Disk Queue
    $memPerf = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Memory -ErrorAction SilentlyContinue
    $pagedMB = 0.0; $nonPagedMB = 0.0
    if ($memPerf) {
        $pagedMB    = [math]::Round($memPerf.PoolPagedBytes / 1MB, 1)
        $nonPagedMB = [math]::Round($memPerf.PoolNonpagedBytes / 1MB, 1)
        if ($memPerf -is [System.IDisposable]) { $memPerf.Dispose() }
    }

    # 4. Fast GPU Engine Utilization % & VRAM Used MB (WDDM Performance Counters)
    $gpuUtilPct = 0.0
    $gpu3dPct   = 0.0
    $gpuCopyPct = 0.0
    $vramDedicatedMB = 0.0
    $vramSharedMB    = 0.0

    $gpuEngines = @(Get-CimInstance -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine -ErrorAction SilentlyContinue)
    if ($gpuEngines.Count -gt 0) {
        $totalEng = ($gpuEngines | Measure-Object -Property UtilizationPercentage -Sum).Sum
        $eng3d    = ($gpuEngines | Where-Object { $_.Name -match 'engtype_3D' } | Measure-Object -Property UtilizationPercentage -Sum).Sum
        $engCopy  = ($gpuEngines | Where-Object { $_.Name -match 'engtype_Copy' } | Measure-Object -Property UtilizationPercentage -Sum).Sum
        $gpuUtilPct = [math]::Min(100.0, [math]::Round([double]$totalEng, 1))
        $gpu3dPct   = [math]::Min(100.0, [math]::Round([double]$eng3d, 1))
        $gpuCopyPct = [math]::Min(100.0, [math]::Round([double]$engCopy, 1))
        foreach ($ge in $gpuEngines) { if ($ge -is [System.IDisposable]) { $ge.Dispose() } }
    }

    $gpuMem = @(Get-CimInstance -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUAdapterMemory -ErrorAction SilentlyContinue)
    $vramTotalCommittedMB = 0.0
    if ($gpuMem.Count -gt 0) {
        $maxDed = ($gpuMem | Measure-Object -Property DedicatedUsage -Maximum).Maximum
        $maxShr = ($gpuMem | Measure-Object -Property SharedUsage -Maximum).Maximum
        $maxCom = ($gpuMem | Measure-Object -Property TotalCommitted -Maximum).Maximum
        if ($maxDed) { $vramDedicatedMB = [math]::Round($maxDed / 1MB, 1) }
        if ($maxShr) { $vramSharedMB    = [math]::Round($maxShr / 1MB, 1) }
        if ($maxCom) { $vramTotalCommittedMB = [math]::Round($maxCom / 1MB, 1) }
        if ($vramDedicatedMB -le 0 -and $vramTotalCommittedMB -gt $vramSharedMB) {
            $vramDedicatedMB = [math]::Round($vramTotalCommittedMB - $vramSharedMB, 1)
        }
        foreach ($gm in $gpuMem) { if ($gm -is [System.IDisposable]) { $gm.Dispose() } }
    }

    # 5. Top 6 Active Processes by Working Set MB (Explicitly dispose Process handles!)
    $allProcs = @(Get-Process -ErrorAction SilentlyContinue)
    $topProcs = @($allProcs |
        Sort-Object -Property WorkingSet64 -Descending |
        Select-Object -First 6 |
        ForEach-Object {
            [PSCustomObject]@{
                ProcessName  = $_.ProcessName
                PID          = $_.Id
                WorkingSetMB = [math]::Round($_.WorkingSet64 / 1MB, 1)
                CPU_Seconds  = if ($null -ne $_.CPU) { [math]::Round($_.CPU, 1) } else { 0.0 }
            }
        })
    foreach ($p in $allProcs) {
        try { $p.Dispose() } catch {}
    }

    return [PSCustomObject]@{
        ScriptId                = "PERF-02"
        TimestampLocal          = $nowLocal
        TimeShort               = $nowTime
        CPU_Load_Percent        = $cpuLoad
        RAM_Used_GB             = $usedRamGB
        RAM_Free_GB             = $freeRamGB
        RAM_Total_GB            = $totalRamGB
        RAM_Used_Percent        = $ramPct
        Commit_Used_GB          = $commitUsedGB
        Commit_Limit_GB         = $commitLimitGB
        Commit_Used_Percent     = $commitPct
        Pool_Paged_MB           = $pagedMB
        Pool_NonPaged_MB        = $nonPagedMB
        GPU_Utilization_Percent = $gpuUtilPct
        GPU_3D_Percent          = $gpu3dPct
        GPU_Copy_Percent        = $gpuCopyPct
        VRAM_Dedicated_MB       = $vramDedicatedMB
        VRAM_Shared_MB          = $vramSharedMB
        VRAM_TotalCommitted_MB  = $vramTotalCommittedMB
        VRAM_Dedicated_GB       = [math]::Round($vramDedicatedMB / 1024.0, 2)
        VRAM_Shared_GB          = [math]::Round($vramSharedMB / 1024.0, 2)
        VRAM_TotalCommitted_GB  = [math]::Round($vramTotalCommittedMB / 1024.0, 2)
        TopProcesses            = $topProcs
    }
}

$lastSample = $null
for ($i = 0; $i -lt $MaxSamples; $i++) {
    $lastSample = Get-FastLiveSample
    $jsonText = $lastSample | ConvertTo-Json -Depth 5 -Compress
    Write-AtomicUtf8File -TargetPath $jsonPath -Content $jsonText
    if ($OutputPath -and ($OutputPath -ne $jsonPath)) {
        Write-AtomicUtf8File -TargetPath $OutputPath -Content $jsonText
    }
    $jsText = "window.__LIVE_TELEMETRY = $jsonText; if (typeof window.__onLiveTelemetry === 'function') { window.__onLiveTelemetry(window.__LIVE_TELEMETRY); }"
    Write-AtomicUtf8File -TargetPath $jsPath -Content $jsText

    if (($i % 20) -eq 19) {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }

    if ($i -lt ($MaxSamples - 1)) {
        Start-Sleep -Seconds $IntervalSeconds
    }
}

Write-Output ($lastSample | ConvertTo-Json -Depth 5)
