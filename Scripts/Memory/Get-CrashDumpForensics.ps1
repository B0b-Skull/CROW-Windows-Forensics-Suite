<#
.SYNOPSIS
    Full System Crash, BugCheck Root-Cause Analysis & Memory Dump Forensics Engine (MEM-01)
.DESCRIPTION
    Performs two complementary forensic layers:
      1. Full System Crash & BugCheck Root-Cause Logic Engine:
         - Queries Microsoft-Windows-Kernel-Power (Event ID 41) XML EventData to extract
           exact 64-bit BugCheck codes and Parameters 1-4 (works WITHOUT Administrator rights).
         - Queries Microsoft-Windows-WER-SystemErrorReporting (Event 1001), EventLog (Event 6008),
           volmgr (Event 161 / 46), WHEA-Logger (Events 1, 17, 18, 19, 47), and
           Kernel-Processor-Power (Event 37/55 thermal/power throttling).
         - Reconstructs the 30-minute Pre-Crash Activity Window prior to each crash
           (FilterManager driver unloads/reloads such as WdFilter.sys/MpKsl, WindowsUpdateClient
           failures such as KB4052623, Service Control Manager crashes).
         - Decodes BugCheck stop codes and parameters (including 0x0000012B
           FAULTY_HARDWARE_CORRUPTED_PAGE + 0xC00002C4 STATUS_BAD_COMPRESSION_BUFFER in
           MemCompression, 0x1A, 0x3B, 0x50, 0x7E, 0x9F, 0x116, 0x124, 0x133, 0x139, 0x141, etc.).
         - Audits CrashControl registry configuration, Pagefile allocation vs. Physical RAM
           (explaining volmgr Event 161), MMAgent MemoryCompression state, Physical RAM DIMM
           part/serial numbers, and PhysicalDisk health.
      2. Windows Crash Dump & Minidump File Inventory:
         - Inventories C:\Windows\MEMORY.DMP, C:\Windows\Minidump, C:\Windows\LiveKernelReports,
           %LOCALAPPDATA%\CrashDumps, and Evidence\MemoryDumps.
         - Sorts by LastWriteTime (ModifiedLocal) descending so overwritten in-place kernel dumps
           (MEMORY.DMP) appear at the top with their true crash timestamp and correlated BugCheck code.
         - Explicitly reports NTFS ACL elevation status when run as a Standard User vs. Administrator.
    Read-only.
#>
param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $baseDir "Data\Investigations\memory_crash_forensics_latest.json" }

$nowLocal = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
$nowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Check elevation status
$isAdmin = $false
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}

# Check available debugging / analysis tools on host
$cdbPath = (Get-Command "cdb.exe" -ErrorAction SilentlyContinue).Source
$kdPath = (Get-Command "kd.exe" -ErrorAction SilentlyContinue).Source
$windbgPath = (Get-Command "windbg.exe" -ErrorAction SilentlyContinue).Source
$volPath = (Get-Command "vol.exe" -ErrorAction SilentlyContinue).Source

# ----------------------------------------------------------------------------
# 1. Host Memory, Pagefile, MMAgent, CrashControl & Storage Context
# ----------------------------------------------------------------------------
$osCim = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$totalRamMB = if ($osCim) { [math]::Round($osCim.TotalVisibleMemorySize / 1024, 0) } else { 0 }
$freeRamMB  = if ($osCim) { [math]::Round($osCim.FreePhysicalMemory / 1024, 0) } else { 0 }
$lastBootLocal = if ($osCim -and $osCim.LastBootUpTime) { ([DateTime]$osCim.LastBootUpTime).ToString("yyyy-MM-ddTHH:mm:sszzz") } else { "Unknown" }

$dimmList = @()
try {
    $dimms = Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue
    foreach ($d in $dimms) {
        $capGB = [math]::Round($d.Capacity / 1GB, 0)
        $mfg = ($d.Manufacturer -replace '\s+', ' ').Trim()
        $part = ($d.PartNumber -replace '\s+', ' ').Trim()
        $ser = ($d.SerialNumber -replace '\s+', ' ').Trim()
        $dimmList += [PSCustomObject]@{
            DeviceLocator      = $d.DeviceLocator
            BankLabel          = $d.BankLabel
            Capacity_GB        = $capGB
            Manufacturer       = $mfg
            PartNumber         = $part
            SerialNumber       = $ser
            RatedSpeed_MTs     = $d.Speed
            ConfiguredSpeed_MTs= $d.ConfiguredClockSpeed
            ConfiguredVoltage_mV = $d.ConfiguredVoltage
            Summary            = "$($d.DeviceLocator): ${capGB}GB $mfg $part (SN: $ser) @ $($d.ConfiguredClockSpeed) MT/s"
        }
    }
} catch {}

$pageFiles = @()
$totalPagefileAllocatedMB = 0
try {
    $pfs = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue
    foreach ($pf in $pfs) {
        $totalPagefileAllocatedMB += [int]$pf.AllocatedBaseSize
        $pageFiles += [PSCustomObject]@{
            Name              = $pf.Name
            AllocatedBase_MB  = [int]$pf.AllocatedBaseSize
            CurrentUsage_MB   = [int]$pf.CurrentUsage
            PeakUsage_MB      = [int]$pf.PeakUsage
            TempPageFile      = [bool]$pf.TempPageFile
        }
    }
} catch {}

$memCompressionEnabled = $true
$pageCombiningEnabled = $false
try {
    $mm = Get-MMAgent -ErrorAction SilentlyContinue
    if ($null -ne $mm) {
        $memCompressionEnabled = [bool]$mm.MemoryCompression
        $pageCombiningEnabled = [bool]$mm.PageCombining
    }
} catch {}

$crashCtrl = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -ErrorAction SilentlyContinue
$crashDumpTypeCode = if ($null -ne $crashCtrl.CrashDumpEnabled) { [int]$crashCtrl.CrashDumpEnabled } else { 7 }
$crashDumpTypeLabel = switch ($crashDumpTypeCode) {
    0 { "0 (None - Crash Dumps Disabled)" }
    1 { "1 (Complete Memory Dump)" }
    2 { "2 (Kernel Memory Dump)" }
    3 { "3 (Small Memory Dump - 256 KB Minidump)" }
    7 { "7 (Automatic Memory Dump)" }
    default { "$crashDumpTypeCode (Custom)" }
}

$diskHealthList = @()
try {
    $pDisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
    foreach ($pd in $pDisks) {
        $diskHealthList += [PSCustomObject]@{
            FriendlyName      = $pd.FriendlyName
            MediaType         = [string]$pd.MediaType
            BusType           = [string]$pd.BusType
            HealthStatus      = [string]$pd.HealthStatus
            OperationalStatus = [string]$pd.OperationalStatus
            Size_GB           = [math]::Round($pd.Size / 1GB, 1)
        }
    }
} catch {}

# ----------------------------------------------------------------------------
# 2. Helper: BugCheck Stop Code & Parameter Decoder Engine
# ----------------------------------------------------------------------------
function Convert-ToHex64 {
    param([string]$RawVal)
    if ([string]::IsNullOrWhiteSpace($RawVal)) { return "0x0" }
    $v = $RawVal.Trim()
    if ($v -match '^0x0+$' -or $v -eq '0') { return "0x0" }
    if ($v -match '^0x[0-9a-fA-F]+$') {
        return "0x" + ($v.Substring(2).ToUpper())
    }
    try {
        $num = [int64]$v
        return ('0x{0:X}' -f $num)
    } catch {
        return $v
    }
}

function Get-BugCheckAnalysis {
    param(
        [int]$BugcheckCodeDec,
        [string]$P1Raw,
        [string]$P2Raw,
        [string]$P3Raw,
        [string]$P4Raw
    )
    $p1 = Convert-ToHex64 $P1Raw
    $p2 = Convert-ToHex64 $P2Raw
    $p3 = Convert-ToHex64 $P3Raw
    $p4 = Convert-ToHex64 $P4Raw

    if ($BugcheckCodeDec -eq 0) {
        return [PSCustomObject]@{
            StopCodeHex       = "0x00000000"
            StopCodeName      = "KERNEL_POWER_UNEXPECTED_SHUTDOWN (No BugCheck Stop Code)"
            Subsystem         = "System Power / Firmware / Hard Reset or Total Freeze"
            FaultingComponent = "Hardware Power Rail / EC Firmware / Forced Power Button Hold"
            DecodedP1         = "$p1 (No BugCheck exception parameter recorded)"
            DecodedP2         = "$p2"
            DecodedP3         = "$p3"
            DecodedP4         = "$p4"
            RootCauseAnalysis = "Windows rebooted without writing a BugCheck stop code (BugcheckCode = 0). This occurs when the system loses power abruptly, hits an EC/thermal hardware shutdown, freezes completely in hardware/GPU lockup before the kernel trap handler can run, or the user holds the power button."
            RemediationSteps  = @(
                "Check System log prior to the reboot for GPU TDR (Event 4101) or Kernel-Processor-Power thermal throttling (Event 37).",
                "Ensure laptop AC adapter and battery power delivery are stable under peak CPU+GPU load."
            )
        }
    }

    $codeHex = ('0x{0:X8}' -f $BugcheckCodeDec)

    switch ($BugcheckCodeDec) {
        299 {
            # 0x0000012B: FAULTY_HARDWARE_CORRUPTED_PAGE
            $isBadComp = ($p1 -match 'C00002C4$')
            $compBytes = try { [Convert]::ToInt64($p2, 16) } catch { 0 }
            $p1Desc = if ($isBadComp) {
                "$p1 (STATUS_BAD_COMPRESSION_BUFFER -- XPRESS Huffman decompression failed on a corrupted 4 KB page in the Windows MemCompression RAM store)"
            } else {
                "$p1 (NTSTATUS error code returned during single-page memory operation)"
            }
            $p2Desc = if ($compBytes -gt 0) {
                "$p2 ($compBytes bytes -- compressed size of the corrupted 4,096-byte page in physical RAM)"
            } else { "$p2 (Compressed page size / secondary parameter)" }
            $p3Desc = "$p3 (User-mode virtual address of the corrupted compressed buffer inside the MemCompression process)"
            $p4Desc = "$p4 (Kernel-mode destination buffer address for page decompression: nt!ST_STORE<SM_TRAITS>::StDmSinglePageCopy -> nt!RtlDecompressBufferEx)"

            return [PSCustomObject]@{
                StopCodeHex       = $codeHex
                StopCodeName      = "FAULTY_HARDWARE_CORRUPTED_PAGE"
                Subsystem         = "Windows Memory Manager / In-RAM Store (MemCompression)"
                FaultingComponent = "ntoskrnl.exe (MemCompression Store / Physical DDR4 RAM Cell or Filter Driver Memory Stomp)"
                DecodedP1         = $p1Desc
                DecodedP2         = $p2Desc
                DecodedP3         = $p3Desc
                DecodedP4         = $p4Desc
                RootCauseAnalysis = "Stop Code 0x0000012B (FAULTY_HARDWARE_CORRUPTED_PAGE) with Parameter 1 = 0xFFFFFFFFC00002C4 (STATUS_BAD_COMPRESSION_BUFFER) proves that the Windows Store/Memory Manager (nt!RtlDecompressBufferEx) tried to decompress a $compBytes-byte compressed page from the in-RAM MemCompression store (VA $p3) into kernel buffer $p4 and failed because the compressed bitstream in physical RAM was corrupted. Unlike a disk failure, MemCompression pages reside in physical RAM. This is caused by either (1) a single-bit flip in physical DDR4 SO-DIMM memory under high chassis heat/throttling, or (2) a kernel mini-filter / driver memory stomp during heavy paging."
                RemediationSteps  = @(
                    "1. Test physical RAM SO-DIMMs for thermal/marginal bit-flips using Windows Memory Diagnostic (mdsched.exe) or MemTest86.",
                    "2. Workaround if 0x12B (0xC00002C4) recurs: Disable Windows RAM Compression in an elevated PowerShell prompt via 'Disable-MMAgent -MemoryCompression' and reboot (you have $([math]::Round($totalRamMB/1024,0)) GB physical RAM).",
                    "3. Clear any stuck Windows Defender Platform update loop (KB4052623 / WdFilter.sys reload) via: & `"$env:ProgramFiles\Windows Defender\MpCmdRun.exe`" -SignatureUpdate -MMPC",
                    "4. Increase C:\pagefile.sys minimum size to at least 8192 MB (or enable Small Memory Dumps) so volmgr Event 161 does not fail during dump creation."
                )
            }
        }
        26 {
            return [PSCustomObject]@{
                StopCodeHex       = $codeHex
                StopCodeName      = "MEMORY_MANAGEMENT"
                Subsystem         = "Windows Virtual Memory Manager"
                FaultingComponent = "ntoskrnl.exe / Physical RAM or Kernel Driver PTE Corruption"
                DecodedP1         = "$p1 (Memory Management subtype code -- e.g. 0x41790/0x41792 corrupted page table or PFN entry)"
                DecodedP2         = "$p2 (Faulting virtual/PTE address)"
                DecodedP3         = "$p3 (Page Table Entry / PFN value)"
                DecodedP4         = "$p4 (Internal Memory Manager parameter)"
                RootCauseAnalysis = "Severe kernel memory management violation (corrupted Page Table Entry, PFN database, or single-bit RAM flip)."
                RemediationSteps  = @("Run Windows Memory Diagnostic (mdsched.exe) to test physical RAM modules.", "Run 'sfc /scannow' and 'DISM /Online /Cleanup-Image /RestoreHealth'.")
            }
        }
        59 {
            return [PSCustomObject]@{
                StopCodeHex       = $codeHex
                StopCodeName      = "SYSTEM_SERVICE_EXCEPTION"
                Subsystem         = "Kernel System Service Dispatcher"
                FaultingComponent = "Kernel Driver / Win32k / ntoskrnl.exe"
                DecodedP1         = "$p1 (Exception code -- e.g. 0xC0000005 STATUS_ACCESS_VIOLATION)"
                DecodedP2         = "$p2 (Instruction pointer address where exception occurred)"
                DecodedP3         = "$p3 (Context Record address)"
                DecodedP4         = "$p4 (Reserved)"
                RootCauseAnalysis = "An exception (typically an invalid memory pointer dereference) occurred while executing a routine that transitions from non-privileged code to privileged kernel code."
                RemediationSteps  = @("Update GPU, chipset, and antivirus filter drivers.", "Inspect third-party kernel drivers in the Drivers tab (DRV-01).")
            }
        }
        80 {
            return [PSCustomObject]@{
                StopCodeHex       = $codeHex
                StopCodeName      = "PAGE_FAULT_IN_NONPAGED_AREA"
                Subsystem         = "Kernel Non-Paged Pool / Virtual Memory"
                FaultingComponent = "Kernel Driver or Physical RAM"
                DecodedP1         = "$p1 (Invalid virtual memory address referenced)"
                DecodedP2         = "$p2 (0 = Read operation, 1 = Write operation, 2 = Execute operation)"
                DecodedP3         = "$p3 (Instruction pointer address that referenced the invalid memory)"
                DecodedP4         = "$p4 (Type of fault / Reserved)"
                RootCauseAnalysis = "Invalid system memory was referenced in the kernel Non-Paged Pool (either a freed driver buffer pointer or a corrupted RAM bit)."
                RemediationSteps  = @("Audit third-party kernel drivers (DRV-01) and run Windows Memory Diagnostic (mdsched.exe).")
            }
        }
        159 {
            return [PSCustomObject]@{
                StopCodeHex       = $codeHex
                StopCodeName      = "DRIVER_POWER_STATE_FAILURE"
                Subsystem         = "Kernel Power Manager / PnP Device IRP"
                FaultingComponent = "Device Driver Blocking Power Transition IRP"
                DecodedP1         = "$p1 (Power state violation subtype -- e.g. 0x3 = Device object blocked Power IRP too long)"
                DecodedP2         = "$p2 (Physical Device Object PDO address)"
                DecodedP3         = "$p3 (Functional Device Object FDO / Triage stack address)"
                DecodedP4         = "$p4 (Blocked Power IRP address)"
                RootCauseAnalysis = "A kernel device driver failed to complete a power-state transition IRP (sleep, hibernate, modern standby, or dGPU wake/sleep) within the timeout."
                RemediationSteps  = @("Update NVIDIA/Intel GPU, Wi-Fi, and Thunderbolt/USB drivers.")
            }
        }
        278 {
            return [PSCustomObject]@{
                StopCodeHex       = $codeHex
                StopCodeName      = "VIDEO_TDR_FAILURE"
                Subsystem         = "DirectX Graphics Kernel (dxgkrnl.sys)"
                FaultingComponent = "Display / GPU Kernel Driver (nvlddmkm.sys / igdkmdn64.sys)"
                DecodedP1         = "$p1 (TDR Context address)"
                DecodedP2         = "$p2 (Faulting display miniport driver routine address)"
                DecodedP3         = "$p3 (Failure status code)"
                DecodedP4         = "$p4 (TDR recovery context)"
                RootCauseAnalysis = "The display driver failed to respond within the Timeout Detection and Recovery (TDR) window and could not be reset without a full system bugcheck."
                RemediationSteps  = @("Increase GraphicsDrivers TdrDelay to 8s (REM-GPU-01) and update Intel/NVIDIA GPU drivers.")
            }
        }
        292 {
            return [PSCustomObject]@{
                StopCodeHex       = $codeHex
                StopCodeName      = "WHEA_UNCORRECTABLE_ERROR"
                Subsystem         = "Windows Hardware Error Architecture (WHEA)"
                FaultingComponent = "CPU Core / Cache / PCIe Bus / NVMe Controller"
                DecodedP1         = "$p1 (Error source type: 0 = Machine Check Exception, 4 = PCIe Error, 0x10 = NVMe/Device Error)"
                DecodedP2         = "$p2 (WHEA_ERROR_RECORD structure address)"
                DecodedP3         = "$p3 (High 32 bits of MCi_STATUS)"
                DecodedP4         = "$p4 (Low 32 bits of MCi_STATUS)"
                RootCauseAnalysis = "The processor or PCIe root complex reported an uncorrectable hardware error via WHEA."
                RemediationSteps  = @("Check WHEA-Logger events in System Log, verify CPU thermal throttling, and check NVMe SMART health.")
            }
        }
        307 {
            return [PSCustomObject]@{
                StopCodeHex       = $codeHex
                StopCodeName      = "DPC_WATCHDOG_VIOLATION"
                Subsystem         = "Kernel Deferred Procedure Call (DPC) Watchdog"
                FaultingComponent = "Kernel Driver Running at IRQL >= DISPATCH_LEVEL"
                DecodedP1         = "$p1 (0 = Single DPC exceeded timeout, 1 = Cumulative DPC queue exceeded timeout)"
                DecodedP2         = "$p2 (DPC Period in ticks)"
                DecodedP3         = "$p3 (Current Tick count)"
                DecodedP4         = "$p4 (DPC Watchdog triage block)"
                RootCauseAnalysis = "A kernel driver spent too long at DISPATCH_LEVEL (IRQL 2), preventing thread scheduling and triggering the DPC Watchdog."
                RemediationSteps  = @("Update GPU, NVMe storage, and network/USB filter drivers.")
            }
        }
        default {
            return [PSCustomObject]@{
                StopCodeHex       = $codeHex
                StopCodeName      = "KERNEL_BUGCHECK_$codeHex"
                Subsystem         = "Windows Kernel Executive"
                FaultingComponent = "ntoskrnl.exe / Kernel Mode Driver"
                DecodedP1         = "$p1"
                DecodedP2         = "$p2"
                DecodedP3         = "$p3"
                DecodedP4         = "$p4"
                RootCauseAnalysis = "Windows halted with Stop Code $codeHex ($BugcheckCodeDec). Review the 30-minute Pre-Crash Activity Window and BugCheck parameters."
                RemediationSteps  = @("Inspect correlated pre-crash driver/service events and run 'sfc /scannow'.")
            }
        }
    }
}

# ----------------------------------------------------------------------------
# 3. Query System Crash Events (Kernel-Power 41, BugCheck 1001, EventLog 6008, volmgr 161)
# ----------------------------------------------------------------------------
$kp41Events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; Id=41} -MaxEvents 20 -ErrorAction SilentlyContinue)
$bugcheck1001Events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'; Id=1001} -MaxEvents 20 -ErrorAction SilentlyContinue)
$volmgr161Events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='volmgr'; Id=@(161, 46)} -MaxEvents 20 -ErrorAction SilentlyContinue)
$evt6008Events = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=6008} -MaxEvents 20 -ErrorAction SilentlyContinue)
$wheaEvents = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName=@('Microsoft-Windows-WHEA-Logger','Microsoft-Windows-Kernel-WHEA')} -MaxEvents 25 -ErrorAction SilentlyContinue | Where-Object { $_.Level -le 3 })
$thermalEvents = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Processor-Power'; Id=@(37, 55)} -MaxEvents 30 -ErrorAction SilentlyContinue | Where-Object { $_.Level -le 3 })

$systemCrashHistory = @()
foreach ($kp in $kp41Events) {
    $xml = [xml]$kp.ToXml()
    $d = @{}
    foreach ($n in $xml.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }

    $bcDec = if ($d['BugcheckCode']) { [int]$d['BugcheckCode'] } else { 0 }
    $decoded = Get-BugCheckAnalysis -BugcheckCodeDec $bcDec -P1Raw $d['BugcheckParameter1'] -P2Raw $d['BugcheckParameter2'] -P3Raw $d['BugcheckParameter3'] -P4Raw $d['BugcheckParameter4']

    $crashRebootTime = $kp.TimeCreated
    $windowStart = $crashRebootTime.AddMinutes(-30)

    # Correlate volmgr 161 within 3 minutes of Kernel-Power 41
    $matchingVolmgr = @($volmgr161Events | Where-Object { [math]::Abs(($_.TimeCreated - $crashRebootTime).TotalMinutes) -le 3 })
    $volmgrStatus = if ($matchingVolmgr.Count -gt 0) {
        "volmgr Event ID $($matchingVolmgr[0].Id) (RecordId $($matchingVolmgr[0].RecordId)): $($matchingVolmgr[0].Message.Trim()) [Pagefile: ${totalPagefileAllocatedMB} MB vs RAM: ${totalRamMB} MB]"
    } else {
        "Dump write completed without volmgr Event 161 error"
    }

    # Correlate Event 6008 within 5 minutes of Kernel-Power 41
    $matching6008 = @($evt6008Events | Where-Object { [math]::Abs(($_.TimeCreated - $crashRebootTime).TotalMinutes) -le 5 })
    $unexpectedShutdownNote = if ($matching6008.Count -gt 0) {
        ($matching6008[0].Message -replace '\r|\n', ' ' -replace '\?', '').Trim()
    } else { "System rebooted without clean shutdown at $($crashRebootTime.ToString('yyyy-MM-dd HH:mm:ss'))." }

    # Reconstruct 30-Minute Pre-Crash Activity Window (FilterManager, WindowsUpdateClient, Service Control Manager)
    $preCrashEvents = @()
    try {
        $rawPre = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            StartTime = $windowStart
            EndTime   = $crashRebootTime.AddSeconds(-2)
        } -MaxEvents 120 -ErrorAction SilentlyContinue | Where-Object {
            $_.Id -notin @(12, 13) -and $_.ProviderName -match 'FilterManager|WindowsUpdateClient|Service Control Manager|WHEA|Kernel-Processor-Power|volmgr|Display|Ntfs|disk'
        }
        foreach ($pe in ($rawPre | Select-Object -First 15)) {
            $cleanMsg = ($pe.Message -replace '\r\n|\n', ' ').Trim()
            if ($cleanMsg.Length -gt 240) { $cleanMsg = $cleanMsg.Substring(0, 240) + "..." }
            $preCrashEvents += [PSCustomObject]@{
                TimeLocal    = $pe.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                EventId      = $pe.Id
                Level        = $pe.LevelDisplayName
                ProviderName = $pe.ProviderName
                RecordId     = $pe.RecordId
                Message      = $cleanMsg
            }
        }
    } catch {}

    # Summarize pre-crash triggers
    $wdFilterReloads = @($preCrashEvents | Where-Object { $_.Message -match 'WdFilter|MpKsl' })
    $wuFailures = @($preCrashEvents | Where-Object { $_.ProviderName -match 'WindowsUpdateClient' -and $_.EventId -eq 20 })
    $preCrashTriggerSummary = if ($wdFilterReloads.Count -gt 0 -or $wuFailures.Count -gt 0) {
        $wuText = if ($wuFailures.Count -gt 0) { "$($wuFailures.Count) Windows Update installation failure(s) ($($wuFailures[0].Message)); " } else { "" }
        $wdText = if ($wdFilterReloads.Count -gt 0) { "$($wdFilterReloads.Count) Kernel FilterManager unload/reload event(s) for WdFilter.sys / MpKsl immediately before the crash." } else { "" }
        "$wuText$wdText".Trim()
    } elseif ($preCrashEvents.Count -gt 0) {
        "$($preCrashEvents.Count) system/driver events in the 30m window prior to reboot (Latest: [$($preCrashEvents[0].ProviderName) Event $($preCrashEvents[0].EventId)] $($preCrashEvents[0].Message))"
    } else {
        "No abnormal driver unload/reload or Windows Update failure logged in the 30 minutes prior to reboot."
    }

    $systemCrashHistory += [PSCustomObject]@{
        CrashIndex             = $systemCrashHistory.Count + 1
        RebootTimestampLocal   = $crashRebootTime.ToString("yyyy-MM-ddTHH:mm:sszzz")
        RebootTimestampUtc     = $crashRebootTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        KernelPowerRecordId    = $kp.RecordId
        IsBugCheck             = ($bcDec -ne 0)
        BugcheckCodeDec        = $bcDec
        StopCodeHex            = $decoded.StopCodeHex
        StopCodeName           = $decoded.StopCodeName
        Subsystem              = $decoded.Subsystem
        FaultingComponent      = $decoded.FaultingComponent
        Parameter1             = $decoded.DecodedP1
        Parameter2             = $decoded.DecodedP2
        Parameter3             = $decoded.DecodedP3
        Parameter4             = $decoded.DecodedP4
        RawP1                  = (Convert-ToHex64 $d['BugcheckParameter1'])
        RawP2                  = (Convert-ToHex64 $d['BugcheckParameter2'])
        RawP3                  = (Convert-ToHex64 $d['BugcheckParameter3'])
        RawP4                  = (Convert-ToHex64 $d['BugcheckParameter4'])
        UnexpectedShutdownNote = $unexpectedShutdownNote
        DumpCreationStatus     = $volmgrStatus
        PreCrashTriggerSummary = $preCrashTriggerSummary
        PreCrashTimeline       = $preCrashEvents
        RootCauseAnalysis      = $decoded.RootCauseAnalysis
        RemediationSteps       = $decoded.RemediationSteps
        ThreatAssessment       = "Informational"
        RiskAssessment         = if ($bcDec -ne 0) { "Critical (Kernel BugCheck)" } else { "High (Unexpected Reboot)" }
    }
}

$latestBugCheck = $systemCrashHistory | Where-Object { $_.IsBugCheck } | Select-Object -First 1
if (-not $latestBugCheck -and $systemCrashHistory.Count -gt 0) {
    $latestBugCheck = $systemCrashHistory[0]
}

# ----------------------------------------------------------------------------
# 4. Gather Application Error (1000), Hang (1002), and WER (1001) events for dump correlation
# ----------------------------------------------------------------------------
$crashEvents = @()
try {
    $rawEvts = Get-WinEvent -FilterHashtable @{
        LogName      = 'Application'
        ProviderName = @('Application Error', 'Application Hang', 'Windows Error Reporting')
        StartTime    = (Get-Date).AddDays(-60)
    } -MaxEvents 800 -ErrorAction SilentlyContinue | Where-Object { $_.Message -notmatch 'MpTelemetry' }
    $crashEvents = @($rawEvts)
} catch {}

# ----------------------------------------------------------------------------
# 5. Inventory Physical Dump Files & Check Directory Access Permissions
# ----------------------------------------------------------------------------
$searchLocations = @(
    @{ Category = "Kernel Minidump"; Path = "C:\Windows\Minidump"; RequiresAdmin = $true },
    @{ Category = "Kernel LiveReport (TDR/Watchdog)"; Path = "C:\Windows\LiveKernelReports"; RequiresAdmin = $true },
    @{ Category = "User-Mode CrashDump"; Path = "$env:LOCALAPPDATA\CrashDumps"; RequiresAdmin = $false },
    @{ Category = "Collected Forensic Evidence"; Path = (Join-Path $baseDir "Evidence\MemoryDumps"); RequiresAdmin = $false }
)

$directoryAccessStatus = @()
$dumps = @()

foreach ($loc in $searchLocations) {
    $exists = Test-Path $loc.Path
    $accessOk = $true
    $errMsg = "Accessible"
    $fileCount = 0
    if ($exists) {
        try {
            $files = @(Get-ChildItem -Path $loc.Path -Recurse -File -Filter "*.dmp" -ErrorAction Stop)
            $fileCount = $files.Count
            foreach ($f in $files) {
                $dumps += @{ File = $f; Category = $loc.Category }
            }
        } catch {
            $accessOk = $false
            $errMsg = "Access Restricted (Run Dashboard/Script as Administrator to enumerate $($loc.Path))"
        }
    } else {
        $errMsg = "Directory Not Present"
    }
    $directoryAccessStatus += [PSCustomObject]@{
        Category      = $loc.Category
        Path          = $loc.Path
        Exists        = $exists
        Accessible    = $accessOk
        FilesFound    = $fileCount
        StatusMessage = $errMsg
    }
}

if (Test-Path "C:\Windows\MEMORY.DMP") {
    $f = Get-Item "C:\Windows\MEMORY.DMP" -ErrorAction SilentlyContinue
    if ($f) {
        $dumps += @{ File = $f; Category = "Full Kernel Memory Dump" }
        $directoryAccessStatus += [PSCustomObject]@{
            Category      = "Full Kernel Memory Dump"
            Path          = "C:\Windows\MEMORY.DMP"
            Exists        = $true
            Accessible    = $isAdmin
            FilesFound    = 1
            StatusMessage = if ($isAdmin) { "Full read access (Elevated)" } else { "Metadata visible ($([math]::Round($f.Length/1MB,2)) MB, Last Modified $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))); raw byte read requires Administrator" }
        }
    }
}

$dumpInventory = @()
foreach ($entry in ($dumps | Sort-Object { $_.File.LastWriteTime } -Descending)) {
    $df = $entry.File
    $sizeMB = [math]::Round($df.Length / 1MB, 2)

    # Read 8-byte header signature if accessible
    $headerSig = if ($isAdmin) { "Unknown" } else { "Metadata Verified (Byte Read Requires Admin)" }
    try {
        if ($df.Length -ge 8) {
            $bytes = [byte[]]::new(8)
            $fs = [System.IO.File]::Open($df.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            [void]$fs.Read($bytes, 0, 8)
            $fs.Close()
            $ascii = [System.Text.Encoding]::ASCII.GetString($bytes, 0, 4)
            $headerSig = switch ($ascii) {
                "MDMP" { "Valid User/Mini Dump (MDMP)" }
                "PAGE" { "Valid 64-bit Kernel Dump (PAGEDU64)" }
                default { "Header: $ascii" }
            }
        } elseif ($df.Length -eq 0) {
            $headerSig = "Empty (0-byte Truncated Dump)"
        }
    } catch {}

    $sha256 = if ($df.Length -gt 0 -and $df.Length -le 100MB) {
        $h = (Get-FileHash -LiteralPath $df.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        if ($h) { $h } else { "Access Restricted (Requires Elevation)" }
    } elseif ($df.Length -eq 0) {
        "Empty File (0 Bytes)"
    } else {
        "Deferred (>100 MB Full Kernel Dump - Hash On-Demand)"
    }

    # Dynamically correlate with Event Logs by process name or dump filename
    $procGuess = ($df.Name -replace '\.\d+\.dmp$', '' -replace '\(\d+\)', '' -replace '_PID\d+_\d+_\d+\.dmp$', '')
    $exceptionCode = "Unknown / Inspect via WinDbg"
    $faultingModule = "Unknown"
    $analysisSummary = "Crash dump artifact captured at $($df.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))."
    $riskLevel = if ($df.Name -match 'explorer|WATCHDOG|lsass|svchost') { "Medium" } else { "Low" }

    if ($df.Name -match '^WATCHDOG') {
        $exceptionCode = "BugCheck 0x141 (VIDEO_ENGINE_TIMEOUT_DETECTED)"
        $faultingModule = "dxgkrnl.sys / Display GPU Engine Driver"
        $analysisSummary = "Kernel Watchdog GPU TDR dump generated during display engine timeout recovery."
        $riskLevel = "High"
    } elseif ($df.Name -eq 'MEMORY.DMP') {
        $riskLevel = "Critical"
        if ($latestBugCheck) {
            $exceptionCode = "$($latestBugCheck.StopCodeHex) ($($latestBugCheck.StopCodeName))"
            $faultingModule = $latestBugCheck.FaultingComponent
            $analysisSummary = "Correlated with Kernel-Power Event 41 (RecordId $($latestBugCheck.KernelPowerRecordId) at $($latestBugCheck.RebootTimestampLocal)): Stop Code $($latestBugCheck.StopCodeHex) $($latestBugCheck.StopCodeName) | P1: $($latestBugCheck.Parameter1) | Pre-Crash Trigger: $($latestBugCheck.PreCrashTriggerSummary)"
        } else {
            $exceptionCode = "System Kernel BugCheck"
            $faultingModule = "ntoskrnl.exe / Kernel Mode"
            $analysisSummary = "$sizeMB MB full/kernel system memory dump (Last Modified: $($df.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')))."
        }
    } else {
        $escapedProc = [regex]::Escape($procGuess)
        $matchingEvts = @($crashEvents | Where-Object { $_.Id -eq 1000 -and $_.Message -match $escapedProc })
        if ($matchingEvts.Count -gt 0) {
            $latestEvt = $matchingEvts[0]
            $msg = $latestEvt.Message
            if ($msg -match 'Faulting module name:\s*([^\r\n,]+)') { $faultingModule = $Matches[1].Trim() }
            if ($msg -match 'Exception code:\s*([^\r\n,]+)') { $exceptionCode = $Matches[1].Trim() }
            $recIds = (($matchingEvts | Select-Object -First 4).RecordId) -join ", "
            $analysisSummary = "Correlated with Application Error Event 1000 (RecordId(s): $recIds): $procGuess fault in $faultingModule ($exceptionCode)."
        } else {
            $faultingModule = $procGuess
            $analysisSummary = "User-mode minidump for $procGuess captured on $($df.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))."
        }
    }

    $dumpInventory += [PSCustomObject]@{
        FileName         = $df.Name
        Category         = $entry.Category
        FullPath         = $df.FullName
        Size_MB          = $sizeMB
        ModifiedLocal    = $df.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:sszzz")
        ModifiedUtc      = $df.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
        CreatedLocal     = $df.CreationTime.ToString("yyyy-MM-ddTHH:mm:sszzz")
        HeaderValidation = $headerSig
        SHA256           = $sha256
        TargetProcess    = $procGuess
        ExceptionCode    = $exceptionCode
        FaultingModule   = $faultingModule
        AnalysisSummary  = $analysisSummary
        ThreatAssessment = "Informational"
        RiskAssessment   = $riskLevel
    }
}

# Extract LiveKernelEvent 141 TDR virtual dump references from Event Logs
$tdrEvts = $crashEvents | Where-Object { $_.Message -match 'LiveKernelEvent' -and $_.Message -match 'P1:\s*141' }
$tdrTimeline = @()
foreach ($te in ($tdrEvts | Select-Object -First 20)) {
    $dmpRef = "WATCHDOG-*.dmp"
    if ($te.Message -match '(WATCHDOG-\d+-\d+\.dmp)') { $dmpRef = $Matches[1] }
    $tdrTimeline += [PSCustomObject]@{
        RecordId           = $te.RecordId
        TimestampLocal     = $te.TimeCreated.ToString("yyyy-MM-ddTHH:mm:sszzz")
        TimestampUtc       = $te.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        EventName          = "LiveKernelEvent (P1: 141 - VIDEO_ENGINE_TIMEOUT_DETECTED)"
        DumpFileReferenced = $dmpRef
        StatusOnDisk       = if ($isAdmin -and (Test-Path "C:\Windows\LiveKernelReports\WATCHDOG\$dmpRef")) { "Present on Disk" } elseif (-not $isAdmin) { "Purged or Requires Admin to Inspect C:\Windows\LiveKernelReports" } else { "Purged after WER Archive Packaging" }
    }
}

$bugCheckCount = @($systemCrashHistory | Where-Object { $_.IsBugCheck }).Count
$explorerDumpCount = @($dumpInventory | Where-Object { $_.FileName -match '^explorer' }).Count
$kernelDumpCount = @($dumpInventory | Where-Object { $_.Category -match 'Kernel' }).Count

$output = [PSCustomObject]@{
    ScriptId           = "MEM-01"
    ScriptName         = "Get-CrashDumpForensics.ps1"
    CollectedAtLocal   = $nowLocal
    CollectedAtUtc     = $nowUtc
    IsElevatedAdmin    = $isAdmin
    ElevationNote      = if ($isAdmin) {
        "Running with Administrator privileges: Full access to C:\Windows\Minidump, C:\Windows\LiveKernelReports, C:\Windows\MEMORY.DMP, and Windows Event Logs."
    } else {
        "Running as Standard User (Non-Admin): Windows restricts direct directory listing of C:\Windows\Minidump and C:\Windows\LiveKernelReports and raw byte reads of C:\Windows\MEMORY.DMP to Administrators. However, the Kernel BugCheck & Pre-Crash Event Correlation Engine below operates at 100% capability without Admin rights by decoding Kernel-Power Event 41 XML, volmgr Event 161, FilterManager, WindowsUpdateClient, and MEMORY.DMP file metadata."
    }
    PrivacyNotice      = "Memory dumps may contain sensitive credentials, session tokens, or application state. Dumps are never uploaded externally."
    ToolAvailability   = [PSCustomObject]@{
        WinDbg_CDB  = if ($cdbPath) { $cdbPath } elseif ($kdPath) { $kdPath } elseif ($windbgPath) { $windbgPath } else { "Built-In PowerShell BugCheck XML & Pre-Crash Correlation Engine Active" }
        Volatility3 = if ($volPath) { $volPath } else { "Not Installed on PATH" }
    }
    HostCrashConfiguration = [PSCustomObject]@{
        LastBootUpLocal            = $lastBootLocal
        TotalPhysicalRAM_MB        = $totalRamMB
        FreePhysicalRAM_MB         = $freeRamMB
        MemoryCompressionEnabled   = $memCompressionEnabled
        PageCombiningEnabled       = $pageCombiningEnabled
        CrashDumpType              = $crashDumpTypeLabel
        TotalPagefileAllocated_MB  = $totalPagefileAllocatedMB
        PagefileSizingWarning      = if ($totalPagefileAllocatedMB -lt ($totalRamMB * 0.25)) {
            "Pagefile is allocated at ${totalPagefileAllocatedMB} MB on a ${totalRamMB} MB ($([math]::Round($totalRamMB/1024,0)) GB) RAM host. Under heavy kernel commit, BugCheck stage-2 dump creation can fail with volmgr Event ID 161."
        } else { "Adequate" }
        PhysicalMemoryModules      = $dimmList
        PageFiles                  = $pageFiles
        StorageDisks               = $diskHealthList
        RecentThermalThrottleCount = $thermalEvents.Count
        RecentWHEAHardwareErrors   = $wheaEvents.Count
    }
    Summary            = [PSCustomObject]@{
        TotalDumpFilesOnDisk       = $dumpInventory.Count
        ExplorerDumpsCount         = $explorerDumpCount
        KernelDumpsCount           = $kernelDumpCount
        RecentTDRKernelEvents      = $tdrTimeline.Count
        TotalUnexpectedReboots     = $systemCrashHistory.Count
        ConfirmedBugCheckCount     = $bugCheckCount
        LatestCrashTimestampLocal  = if ($latestBugCheck) { $latestBugCheck.RebootTimestampLocal } else { "None" }
        LatestStopCodeHex          = if ($latestBugCheck) { $latestBugCheck.StopCodeHex } else { "None" }
        LatestStopCodeName         = if ($latestBugCheck) { $latestBugCheck.StopCodeName } else { "None" }
    }
    LatestCrashAnalysis    = $latestBugCheck
    SystemCrashHistory     = $systemCrashHistory
    DirectoryAccessStatus  = $directoryAccessStatus
    DumpInventory          = $dumpInventory
    GPUTDRKernelEvents     = $tdrTimeline
}

$outDir = Split-Path -Path $OutputPath -Parent
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$output | ConvertTo-Json -Depth 7 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Output "Crash dump forensics written to $OutputPath ($($dumpInventory.Count) dump files inventoried; $($systemCrashHistory.Count) system crash/reboot events analyzed)"
