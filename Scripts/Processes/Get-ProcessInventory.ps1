<#
.SYNOPSIS
    Process Inventory & Forensic Metadata Script (PROC-01)
.DESCRIPTION
    Enumerates all running processes with PID, PPID, Process Creation Timestamp,
    Executable Path, Command Line, User/Owner, CPU/Memory/GPU utilization,
    SHA-256 Hash, Authenticode Signature status, and parent-child anomaly detection.
    Uses path-level deduplication for fast hashing and signature verification. Read-only.
#>
param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $baseDir "Data\Inventory\process_inventory_latest.json" }
$nowLocal = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
$nowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# 1. Gather WMI Process List (for PPID, CommandLine, CreationDate, ExecutablePath)
$wmiProcs = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue
$psProcs  = Get-Process -ErrorAction SilentlyContinue
$psMap    = @{}
foreach ($p in $psProcs) { $psMap[[int]$p.Id] = $p }

# Map PID -> Process Name & CreationDate for Parent-Child validation (accounting for PID reuse)
$pidInfoMap = @{}
foreach ($wp in $wmiProcs) {
    $pidInfoMap[[int]$wp.ProcessId] = @{
        Name         = $wp.Name
        CreationDate = if ($wp.CreationDate) { [DateTime]$wp.CreationDate } else { $null }
        Path         = $wp.ExecutablePath
    }
}

# 2. GPU Memory per PID
$gpuMemMap = @{}
try {
    $gpuCounter = Get-CimInstance -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUProcessMemory -ErrorAction SilentlyContinue
    foreach ($gc in $gpuCounter) {
        if ($gc.Name -match 'pid_(\d+)_') {
            $pidVal = [int]$Matches[1]
            $dedMB = [math]::Round($gc.DedicatedUsage / 1MB, 2)
            if (!$gpuMemMap.ContainsKey($pidVal) -or $dedMB -gt $gpuMemMap[$pidVal]) {
                $gpuMemMap[$pidVal] = $dedMB
            }
        }
    }
} catch {}

# 3. Deduplicated Binary Hash & Authenticode Signature Cache
$binaryCache = @{}
$uniquePaths = $wmiProcs | Where-Object { $_.ExecutablePath -and (Test-Path $_.ExecutablePath) } | Select-Object -ExpandProperty ExecutablePath -Unique

foreach ($path in $uniquePaths) {
    $hashVal = (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
    $verInfo = (Get-Item -LiteralPath $path -ErrorAction SilentlyContinue).VersionInfo
    $signerSubject = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "None" }
    $isMicrosoft = $signerSubject -match "CN=Microsoft Windows|CN=Microsoft Corporation|O=Microsoft Corporation"
    $binaryCache[$path] = @{
        SHA256          = if ($hashVal) { $hashVal } else { "Unavailable (Access Denied / Locked)" }
        SignatureStatus = if ($sig) { [string]$sig.Status } else { "Unknown" }
        SignerSubject   = $signerSubject
        IsOSBinary      = if ($sig) { [bool]$sig.IsOSBinary } else { $false }
        IsMicrosoft     = [bool]$isMicrosoft
        CompanyName     = if ($verInfo -and $verInfo.CompanyName) { $verInfo.CompanyName } else { "Unknown" }
        FileDescription = if ($verInfo -and $verInfo.FileDescription) { $verInfo.FileDescription } else { "" }
        FileVersion     = if ($verInfo -and $verInfo.FileVersion) { $verInfo.FileVersion } else { "" }
    }
}

# 4. Build Normalized Process Records
$processRecords = @()
foreach ($wp in $wmiProcs) {
    $pidVal  = [int]$wp.ProcessId
    $ppidVal = [int]$wp.ParentProcessId
    $psObj   = $psMap[$pidVal]
    $path    = $wp.ExecutablePath
    $binMeta = if ($path -and $binaryCache.ContainsKey($path)) { $binaryCache[$path] } else {
        @{
            SHA256          = if ($pidVal -in @(0, 4)) { "Kernel/System Pseudo-Process" } else { "Path Unavailable (Protected/Elevated Process)" }
            SignatureStatus = if ($pidVal -in @(0, 4)) { "KernelTrusted" } else { "VerificationUnavailable" }
            SignerSubject   = "N/A"
            IsOSBinary      = ($pidVal -in @(0, 4))
            IsMicrosoft     = ($pidVal -in @(0, 4))
            CompanyName     = if ($pidVal -in @(0, 4)) { "Microsoft Windows Kernel" } else { "Unknown" }
            FileDescription = ""
            FileVersion     = ""
        }
    }

    $createTime = if ($wp.CreationDate) { [DateTime]$wp.CreationDate } else { $null }
    $createIso  = if ($createTime) { $createTime.ToString("yyyy-MM-ddTHH:mm:sszzz") } else { "Boot/System" }
    $entityKey  = "PROC-$pidVal-" + $(if ($createTime) { $createTime.ToUniversalTime().ToString("yyyyMMddHHmmss") } else { "SYSTEM" })

    # Parent validation (check if PPID exists and was created BEFORE child process to account for PID reuse)
    $parentName = "Orphaned / Exited ($ppidVal)"
    $isOrphaned = $true
    if ($pidInfoMap.ContainsKey($ppidVal)) {
        $pInfo = $pidInfoMap[$ppidVal]
        if (!$createTime -or !$pInfo.CreationDate -or $pInfo.CreationDate -le $createTime) {
            $parentName = "$($pInfo.Name) ($ppidVal)"
            $isOrphaned = $false
        } else {
            $parentName = "Exited (PID $ppidVal reused by $($pInfo.Name))"
            $isOrphaned = $true
        }
    }

    # Check suspicious execution location or anomalies
    $anomalies = @()
    if ($path) {
        if ($path -match '\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|\\Users\\Public\\|\\PerfLogs\\') {
            $anomalies += "Execution from Temp/Public staging directory"
        }
        $expectedSysProcs = @('svchost.exe', 'lsass.exe', 'csrss.exe', 'services.exe', 'wininit.exe', 'smss.exe', 'winlogon.exe', 'dwm.exe', 'taskhostw.exe')
        if ($wp.Name.ToLower() -in $expectedSysProcs -and $path -notmatch '^C:\\Windows\\(System32|SysWOW64)\\') {
            $anomalies += "Potential Process Masquerading: System process name outside System32/SysWOW64"
        }
    }
    if ($binMeta.SignatureStatus -notin @('Valid', 'KernelTrusted', 'VerificationUnavailable')) {
        $anomalies += "Binary signature status: $($binMeta.SignatureStatus)"
    }

    $processRecords += [PSCustomObject]@{
        EntityId            = $entityKey
        PID                 = $pidVal
        PPID                = $ppidVal
        ParentDisplay       = $parentName
        IsOrphanedProcess   = $isOrphaned
        ProcessName         = $wp.Name
        BinaryPath          = if ($path) { $path } else { "System / Protected Path" }
        CommandLine         = if ($wp.CommandLine) { $wp.CommandLine } else { "" }
        StartTime           = $createIso
        WorkingSet_MB       = [math]::Round($wp.WorkingSetSize / 1MB, 2)
        PrivateBytes_MB     = [math]::Round($wp.PrivatePageCount / 1MB, 2)
        CPU_Seconds         = if ($psObj -and $psObj.CPU) { [math]::Round($psObj.CPU, 2) } else { 0 }
        GPU_Dedicated_MB    = if ($gpuMemMap.ContainsKey($pidVal)) { $gpuMemMap[$pidVal] } else { 0 }
        ThreadCount         = $wp.ThreadCount
        HandleCount         = $wp.HandleCount
        CompanyName         = $binMeta.CompanyName
        FileDescription     = $binMeta.FileDescription
        FileVersion         = $binMeta.FileVersion
        SHA256              = $binMeta.SHA256
        SignatureStatus     = $binMeta.SignatureStatus
        SignerSubject       = $binMeta.SignerSubject
        IsOSBinary          = $binMeta.IsOSBinary
        IsMicrosoftSigned   = $binMeta.IsMicrosoft
        AnomalyFlags        = $anomalies
    }
}

$output = [PSCustomObject]@{
    ScriptId          = "PROC-01"
    ScriptName        = "Get-ProcessInventory.ps1"
    CollectedAtLocal  = $nowLocal
    CollectedAtUtc    = $nowUtc
    TotalProcesses    = $processRecords.Count
    UniqueBinaries    = $uniquePaths.Count
    SignedCount       = @($processRecords | Where-Object { $_.SignatureStatus -in @('Valid', 'KernelTrusted') }).Count
    UnsignedOrInvalid = @($processRecords | Where-Object { $_.SignatureStatus -notin @('Valid', 'KernelTrusted', 'VerificationUnavailable') }).Count
    Processes         = $processRecords
}

$outDir = Split-Path -Path $OutputPath -Parent
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$output | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Output "Process inventory written to $OutputPath"
