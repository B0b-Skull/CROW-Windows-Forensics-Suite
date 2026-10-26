<#
.SYNOPSIS
    Hardware & OS Configuration Inventory Script (HW-01)
.DESCRIPTION
    Collects comprehensive hardware, firmware, storage, GPU, network adapter,
    monitor, peripheral, OS build, hotfix, and security posture (TPM, SecureBoot,
    BitLocker, VBS/DeviceGuard) telemetry. Read-only.
    Clearly distinguishes unavailable metrics from zero values.
#>
param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $baseDir "Data\Inventory\hardware_inventory_latest.json" }
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$nowLocal = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
$nowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# 1. OS & System Info
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$bios = Get-CimInstance -ClassName Win32_BIOS
$board = Get-CimInstance -ClassName Win32_BaseBoard

$uptimeSpan = (Get-Date) - $os.LastBootUpTime
$totalRamGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
$freeRamGB  = [math]::Round(($os.FreePhysicalMemory * 1KB) / 1GB, 2)
$usedRamGB  = [math]::Round($totalRamGB - $freeRamGB, 2)
$ramPercent = if ($totalRamGB -gt 0) { [math]::Round(($usedRamGB / $totalRamGB) * 100, 1) } else { 0 }

# 2. CPU & Thermal Telemetry
$cpus = @()
$rawCpus = Get-CimInstance -ClassName Win32_Processor
$thermalZones = Get-CimInstance -ClassName Win32_PerfFormattedData_Counters_ThermalZoneInformation -ErrorAction SilentlyContinue
$tempCelsius = "Unavailable (Sensor requires elevation or vendor WMI)"
if ($thermalZones) {
    $tz = $thermalZones | Where-Object { $_.Temperature -gt 200 } | Select-Object -First 1
    if ($tz) {
        $tempCelsius = [math]::Round($tz.Temperature - 273.15, 1)
    }
}

foreach ($c in $rawCpus) {
    $cpus += [PSCustomObject]@{
        Name                      = ($c.Name -replace '\s+', ' ').Trim()
        Manufacturer              = $c.Manufacturer
        Architecture              = switch ($c.Architecture) { 9 { "x64 (AMD64/Intel64)" } 0 { "x86" } 5 { "ARM" } 12 { "ARM64" } default { "Arch-$($c.Architecture)" } }
        PhysicalCores             = $c.NumberOfCores
        LogicalProcessors         = $c.NumberOfLogicalProcessors
        MaxClockSpeed_MHz         = $c.MaxClockSpeed
        CurrentClockSpeed_MHz     = $c.CurrentClockSpeed
        LoadPercentage            = if ($null -ne $c.LoadPercentage) { $c.LoadPercentage } else { 0 }
        L2CacheSize_KB            = $c.L2CacheSize
        L3CacheSize_KB            = $c.L3CacheSize
        VirtualizationFirmwareEnabled = $c.VirtualizationFirmwareEnabled
        Temperature_C             = $tempCelsius
    }
}

# 3. Physical Memory Modules (DIMMs)
$dimms = @()
$rawDimms = Get-CimInstance -ClassName Win32_PhysicalMemory
foreach ($d in $rawDimms) {
    $dimms += [PSCustomObject]@{
        BankLabel            = $d.BankLabel
        DeviceLocator        = $d.DeviceLocator
        Manufacturer         = ($d.Manufacturer -replace '\s+', ' ').Trim()
        PartNumber           = ($d.PartNumber -replace '\s+', ' ').Trim()
        SerialNumber         = $d.SerialNumber
        Capacity_GB          = [math]::Round($d.Capacity / 1GB, 2)
        ConfiguredSpeed_MHz  = $d.ConfiguredClockSpeed
        SMBIOSSpeed_MHz      = $d.Speed
    }
}

# 4. GPUs, Driver Versions, VRAM & Vendor Telemetry (nvidia-smi if available)
$gpus = @()
$rawGpus = Get-CimInstance -ClassName Win32_VideoController
$gpuAdapterMem = Get-CimInstance -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUAdapterMemory -ErrorAction SilentlyContinue
$totalDedicatedVRAM_MB = if ($gpuAdapterMem) { [math]::Round((($gpuAdapterMem | Measure-Object -Property DedicatedUsage -Sum).Sum) / 1MB, 1) } else { $null }
$totalSharedVRAM_MB    = if ($gpuAdapterMem) { [math]::Round((($gpuAdapterMem | Measure-Object -Property SharedUsage -Sum).Sum) / 1MB, 1) } else { $null }

$gpuEngines = Get-CimInstance -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine -ErrorAction SilentlyContinue
$gpuUtilPercent = if ($gpuEngines) {
    $sum3D = ($gpuEngines | Where-Object { $_.Name -match 'engtype_3D|engtype_Compute|engtype_Copy' } | Measure-Object -Property UtilizationPercentage -Maximum).Maximum
    if ($null -ne $sum3D) { [math]::Round($sum3D, 1) } else { 0 }
} else { "Unavailable" }

# Optional nvidia-smi check
$nvidiaSmiData = $null
if (Get-Command "nvidia-smi.exe" -ErrorAction SilentlyContinue) {
    try {
        $smiCsv = & nvidia-smi.exe --query-gpu=name,driver_version,temperature.gpu,utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits 2>$null
        if ($smiCsv) {
            $parts = ($smiCsv | Select-Object -First 1) -split ','
            if ($parts.Count -ge 6) {
                $nvidiaSmiData = [PSCustomObject]@{
                    Name         = $parts[0].Trim()
                    Driver       = $parts[1].Trim()
                    Temp_C       = [int]$parts[2].Trim()
                    Util_Pct     = [int]$parts[3].Trim()
                    VRAM_Used_MB = [int]$parts[4].Trim()
                    VRAM_Total_MB= [int]$parts[5].Trim()
                }
            }
        }
    } catch {}
}

foreach ($g in $rawGpus) {
    $isNvidia = $g.Name -match "NVIDIA"
    $gpus += [PSCustomObject]@{
        Name                  = $g.Name
        AdapterCompatibility  = $g.AdapterCompatibility
        DriverVersion         = $g.DriverVersion
        DriverDate            = if ($g.DriverDate) { ([DateTime]$g.DriverDate).ToString("yyyy-MM-dd") } else { "Unknown" }
        Status                = $g.Status
        ConfigManagerErrorCode= $g.ConfigManagerErrorCode
        VideoModeDescription  = if ($g.VideoModeDescription) { $g.VideoModeDescription } else { "Headless / Secondary" }
        RefreshRate_Hz        = if ($g.CurrentRefreshRate) { $g.CurrentRefreshRate } else { "N/A" }
        AdapterRAM_Reported_MB= if ($isNvidia -and $nvidiaSmiData) { $nvidiaSmiData.VRAM_Total_MB } elseif ($g.AdapterRAM) { [math]::Round($g.AdapterRAM / 1MB, 0) } else { "Shared/Dynamic" }
        DedicatedVRAM_Used_MB = if ($isNvidia -and $nvidiaSmiData) { $nvidiaSmiData.VRAM_Used_MB } elseif ($null -ne $totalDedicatedVRAM_MB) { $totalDedicatedVRAM_MB } else { "Unavailable" }
        SharedVRAM_Used_MB    = if ($null -ne $totalSharedVRAM_MB) { $totalSharedVRAM_MB } else { "Unavailable" }
        GPU_Utilization_Pct   = if ($isNvidia -and $nvidiaSmiData) { $nvidiaSmiData.Util_Pct } else { $gpuUtilPercent }
        Temperature_C         = if ($isNvidia -and $nvidiaSmiData) { $nvidiaSmiData.Temp_C } else { "Unavailable (No WMI GPU thermal counter)" }
    }
}

# 5. Connected Monitors
$monitors = @()
try {
    $wmiMons = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue
    foreach ($m in $wmiMons) {
        $mfg = if ($m.ManufacturerName) { -join ($m.ManufacturerName | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) } else { "Unknown" }
        $name = if ($m.UserFriendlyName) { -join ($m.UserFriendlyName | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) } else { "Generic PnP Monitor" }
        $serial = if ($m.SerialNumberID) { -join ($m.SerialNumberID | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) } else { "N/A" }
        $monitors += [PSCustomObject]@{
            InstanceName = $m.InstanceName
            Manufacturer = $mfg
            Model        = $name
            SerialNumber = $serial
            Active       = $m.Active
        }
    }
} catch {}

# 6. Storage Disks, SMART & Partitions
$physicalDisks = @()
try {
    $pDisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
    foreach ($pd in $pDisks) {
        $physicalDisks += [PSCustomObject]@{
            DeviceId          = $pd.DeviceId
            FriendlyName      = $pd.FriendlyName
            MediaType         = [string]$pd.MediaType
            BusType           = [string]$pd.BusType
            HealthStatus      = [string]$pd.HealthStatus
            OperationalStatus = [string]$pd.OperationalStatus
            Size_GB           = [math]::Round($pd.Size / 1GB, 2)
            FirmwareVersion   = $pd.FirmwareVersion
            SerialNumber      = ($pd.SerialNumber -replace '\s+', '').Trim()
        }
    }
} catch {}

$logicalVolumes = @()
$rawVols = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
foreach ($v in $rawVols) {
    $sizeGB = if ($v.Size) { [math]::Round($v.Size / 1GB, 2) } else { 0 }
    $freeGB = if ($v.FreeSpace) { [math]::Round($v.FreeSpace / 1GB, 2) } else { 0 }
    $usedGB = [math]::Round($sizeGB - $freeGB, 2)
    $logicalVolumes += [PSCustomObject]@{
        DriveLetter  = $v.DeviceID
        VolumeName   = $v.VolumeName
        FileSystem   = $v.FileSystem
        Size_GB      = $sizeGB
        Used_GB      = $usedGB
        Free_GB      = $freeGB
        Used_Percent = if ($sizeGB -gt 0) { [math]::Round(($usedGB / $sizeGB) * 100, 1) } else { 0 }
        VolumeSerial = $v.VolumeSerialNumber
    }
}

# 7. Network Adapters & Traffic Statistics
$netAdapters = @()
try {
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
    $ipConfigs = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue
    foreach ($a in $adapters) {
        $stats = Get-NetAdapterStatistics -Name $a.Name -ErrorAction SilentlyContinue
        $ipc = $ipConfigs | Where-Object { $_.InterfaceIndex -eq $a.ifIndex } | Select-Object -First 1
        $netAdapters += [PSCustomObject]@{
            Name                = $a.Name
            InterfaceDescription= $a.InterfaceDescription
            Status              = [string]$a.Status
            MacAddress          = $a.MacAddress
            LinkSpeed           = $a.LinkSpeed
            DriverVersion       = $a.DriverVersion
            DriverDate          = $a.DriverDate
            IPv4Addresses       = if ($ipc -and $ipc.IPAddress) { ($ipc.IPAddress | Where-Object { $_ -match '^\d+\.' }) -join ", " } else { "None" }
            DefaultGateway      = if ($ipc -and $ipc.DefaultIPGateway) { $ipc.DefaultIPGateway -join ", " } else { "None" }
            DNSServers          = if ($ipc -and $ipc.DNSServerSearchOrder) { $ipc.DNSServerSearchOrder -join ", " } else { "None" }
            Received_MB         = if ($stats) { [math]::Round($stats.ReceivedBytes / 1MB, 2) } else { 0 }
            Sent_MB             = if ($stats) { [math]::Round($stats.SentBytes / 1MB, 2) } else { 0 }
        }
    }
} catch {}

# 8. Connected Peripherals (USB, Bluetooth, Audio, HID Anomalies)
$peripherals = @()
try {
    $pnp = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue |
        Where-Object { $_.PNPClass -in @('USB', 'Bluetooth', 'Media', 'Monitor', 'Net', 'Display', 'HIDClass', 'Camera') -or $_.ConfigManagerErrorCode -ne 0 } |
        Select-Object -First 80
    foreach ($dev in $pnp) {
        $peripherals += [PSCustomObject]@{
            Name          = $dev.Name
            PNPClass      = $dev.PNPClass
            Manufacturer  = $dev.Manufacturer
            Status        = $dev.Status
            ErrorCode     = $dev.ConfigManagerErrorCode
            DeviceID      = $dev.DeviceID
        }
    }
} catch {}

# 9. Recent Windows Updates (Hotfixes)
$hotfixes = @()
try {
    $hfs = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 15
    foreach ($hf in $hfs) {
        $hotfixes += [PSCustomObject]@{
            HotFixID    = $hf.HotFixID
            Description = $hf.Description
            InstalledBy = $hf.InstalledBy
            InstalledOn = if ($hf.InstalledOn) { ([DateTime]$hf.InstalledOn).ToString("yyyy-MM-dd") } else { "Unknown" }
        }
    }
} catch {}

# 10. Platform Security Status (SecureBoot, TPM, BitLocker, VBS/DeviceGuard)
$secureBootStatus = "Unavailable (Requires elevation or Legacy BIOS)"
try {
    $sb = Confirm-SecureBootUEFI -ErrorAction Stop
    $secureBootStatus = if ($sb) { "Enabled" } else { "Disabled" }
} catch {
    $sbReg = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue).UEFISecureBootEnabled
    if ($null -ne $sbReg) {
        $secureBootStatus = if ($sbReg -eq 1) { "Enabled (Registry Verified)" } else { "Disabled (Registry Verified)" }
    }
}

$tpmStatus = "Unavailable (Requires Admin)"
try {
    $tpm = Get-Tpm -ErrorAction Stop
    $tpmStatus = if ($tpm.TpmPresent) { "Present (Ready: $($tpm.TpmReady), Enabled: $($tpm.TpmEnabled))" } else { "Not Present" }
} catch {
    $tpmPnp = Get-CimInstance -ClassName Win32_PnPEntity -Filter "Name LIKE '%Trusted Platform Module%'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($tpmPnp) {
        $tpmStatus = "Present ($($tpmPnp.Name) - Status: $($tpmPnp.Status))"
    }
}

$bitlockerStatus = "Unavailable (Requires Admin to query volume protectors)"
if ($isAdmin) {
    try {
        $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        $bitlockerStatus = "$($bl.VolumeStatus) (Protection: $($bl.ProtectionStatus))"
    } catch {}
}

$dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
$vbsStatus = if ($dg) {
    switch ($dg.VirtualizationBasedSecurityStatus) {
        0 { "Not Enabled" }
        1 { "Enabled (Not Running)" }
        2 { "Enabled and Running" }
        default { "Unknown ($($dg.VirtualizationBasedSecurityStatus))" }
    }
} else { "Unavailable" }

# 10. Local PowerShell Version Discovery & Version-Specific Command Matrix
$psMajor = [int]$PSVersionTable.PSVersion.Major
$psFullVer = $PSVersionTable.PSVersion.ToString()
$psEditionName = if ($PSVersionTable.PSEdition) { [string]$PSVersionTable.PSEdition } else { "Desktop" }
$clrVer = if ($PSVersionTable.CLRVersion) { $PSVersionTable.CLRVersion.ToString() } else { ".NET Core / Modern Runtime" }

$winPs51Path = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$winPs51Installed = Test-Path $winPs51Path

$pwshCmd = Get-Command "pwsh.exe" -ErrorAction SilentlyContinue
$pwshPath = if ($pwshCmd) { $pwshCmd.Source } else {
    $cand = Get-Item "C:\Program Files\PowerShell\*\pwsh.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
    if ($cand) { $cand.FullName } else { $null }
}
$pwshInstalled = [bool]($null -ne $pwshPath)
$pwshVer = if ($pwshInstalled) {
    try { (Get-Item $pwshPath).VersionInfo.ProductVersion } catch { "7.x" }
} else { "Not Installed" }

$detectedProfile = if ($psMajor -ge 7) { "PS7" } elseif ($psMajor -eq 5) { "PS51" } else { "PSLegacy" }
$detectedProfileLabel = switch ($detectedProfile) {
    "PS7"      { "PowerShell $psFullVer (Core Edition - pwsh.exe)" }
    "PS51"     { "Windows PowerShell $psFullVer (Desktop Edition - powershell.exe)" }
    default    { "Windows PowerShell $psFullVer (Legacy v3/v4 Compatibility Mode)" }
}

$execPolicies = @()
try {
    Get-ExecutionPolicy -List -ErrorAction SilentlyContinue | ForEach-Object {
        $execPolicies += [PSCustomObject]@{
            Scope           = [string]$_.Scope
            ExecutionPolicy = [string]$_.ExecutionPolicy
        }
    }
} catch {}

$rawCmdMatrix = @(
    @{
        OperationId  = "CMD-CORE-01"
        Category     = "Master Orchestrator"
        Title        = "Run Full System Forensic Snapshot (CORE-01)"
        Command_PS51 = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `".\Scripts\Core\Invoke-FullSystemSnapshot.ps1`""
        Command_PS7  = "pwsh.exe -NoProfile -ExecutionPolicy Bypass -File `".\Scripts\Core\Invoke-FullSystemSnapshot.ps1`""
        Command_PSLegacy = "powershell.exe -Version 3.0 -NoProfile -ExecutionPolicy Bypass -File `".\Scripts\Core\Invoke-FullSystemSnapshot.ps1`""
        VersionNotes = "PS 5.1 invokes built-in Desktop engine (powershell.exe); PS 7+ invokes Cross-Platform Core engine (pwsh.exe) with faster JSON serialization."
    },
    @{
        OperationId  = "CMD-PROC-01"
        Category     = "Process Forensics"
        Title        = "Enumerate Processes with Parent PID (PPID) & Command Line"
        Command_PS51 = "Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine"
        Command_PS7  = "Get-Process | Select-Object Id, @{N='PPID';E={`$_.Parent.Id}}, ProcessName, Path, CommandLine"
        Command_PSLegacy = "Get-WmiObject Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine"
        VersionNotes = "In PS 5.1, Get-Process does NOT expose .Parent or .CommandLine properties (requires Get-CimInstance Win32_Process). PS 7+ adds .Parent and .CommandLine natively to Get-Process. PS 3.0/Legacy uses Get-WmiObject."
    },
    @{
        OperationId  = "CMD-INT-01"
        Category     = "Binary Integrity"
        Title        = "Compute SHA-256 Hashes Across System32 Executables"
        Command_PS51 = "Get-ChildItem C:\Windows\System32\*.exe | ForEach-Object { Get-FileHash `$_.FullName -Algorithm SHA256 }"
        Command_PS7  = "Get-ChildItem C:\Windows\System32\*.exe | ForEach-Object -Parallel { Get-FileHash `$_.FullName -Algorithm SHA256 } -ThrottleLimit 8"
        Command_PSLegacy = "Get-ChildItem C:\Windows\System32\*.exe | ForEach-Object { certutil.exe -hashfile `$_.FullName SHA256 }"
        VersionNotes = "PS 7+ supports multi-threaded ForEach-Object -Parallel (-ThrottleLimit 8). PS 5.1 uses sequential pipeline. PS 3.0 lacks Get-FileHash (introduced in PS 4.0) and requires certutil -hashfile."
    },
    @{
        OperationId  = "CMD-EVT-01"
        Category     = "Event Log Forensics"
        Title        = "Query GPU TDR (LiveKernelEvent 141) & Explorer Crash Events"
        Command_PS51 = "Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName=@('Application Error','Application Hang','Windows Error Reporting'); StartTime=(Get-Date).AddDays(-14)} -MaxEvents 200"
        Command_PS7  = "Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName=@('Application Error','Application Hang','Windows Error Reporting'); StartTime=(Get-Date).AddDays(-14)} -MaxEvents 200"
        Command_PSLegacy = "Get-EventLog -LogName Application -EntryType Error,Information -After (Get-Date).AddDays(-14) -Newest 200 | Where-Object { `$_.Source -match 'Application Error|Hang|Windows Error Reporting' }"
        VersionNotes = "PS 5.1 and PS 7.1+ support server-side Get-WinEvent -FilterHashtable XPath filtering. Legacy PS 3.0 scripts often use Get-EventLog (which is removed in PS 7+ Core)."
    },
    @{
        OperationId  = "CMD-NET-02"
        Category     = "Network & IP Intel"
        Title        = "Query Public IP RDAP / WHOIS Metadata via HTTPS"
        Command_PS51 = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-RestMethod -Uri 'https://rdap.arin.net/registry/ip/8.8.8.8' -UseBasicParsing -TimeoutSec 5"
        Command_PS7  = "Invoke-RestMethod -Uri 'https://rdap.arin.net/registry/ip/8.8.8.8' -TimeoutSec 5 -SkipHttpErrorCheck"
        Command_PSLegacy = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object System.Net.WebClient).DownloadString('https://rdap.arin.net/registry/ip/8.8.8.8')"
        VersionNotes = "PS 5.1 requires explicit TLS 1.2 activation on older .NET configs and -UseBasicParsing (to avoid IE DOM dependency). In PS 7+, -UseBasicParsing is default/deprecated and -SkipHttpErrorCheck is supported."
    },
    @{
        OperationId  = "CMD-SVC-01"
        Category     = "Service Forensics"
        Title        = "Inspect Service BinaryPath, StartupType & Hosting Process"
        Command_PS51 = "Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, ProcessId, PathName"
        Command_PS7  = "Get-Service | Select-Object Name, DisplayName, Status, StartType, BinaryPathName"
        Command_PSLegacy = "Get-WmiObject Win32_Service | Select-Object Name, DisplayName, State, StartMode, ProcessId, PathName"
        VersionNotes = "In PS 5.1, Get-Service does not expose .BinaryPathName (requires Get-CimInstance Win32_Service). PS 7+ adds .BinaryPathName and .StartupType directly to Get-Service output."
    },
    @{
        OperationId  = "CMD-APPX-01"
        Category     = "Remediation & Bloatware"
        Title        = "Audit or Remove Provisioned UWP / Appx Packages"
        Command_PS51 = "Get-AppxPackage -AllUsers *YourPhone* | Remove-AppxPackage -AllUsers"
        Command_PS7  = "Import-Module Appx -UseWindowsPowerShell; Get-AppxPackage -AllUsers *YourPhone* | Remove-AppxPackage -AllUsers"
        Command_PSLegacy = "dism.exe /Online /Get-ProvisionedAppxPackages"
        VersionNotes = "On Windows 10/11, the Appx module uses Desktop WinRT APIs; PS 7+ requires 'Import-Module Appx -UseWindowsPowerShell' to proxy the module through a Windows PowerShell 5.1 session."
    },
    @{
        OperationId  = "CMD-REM-EXP"
        Category     = "Shell Stability Remediation"
        Title        = "Isolate File Explorer Windows in Separate Process (REM-EXP-01)"
        Command_PS51 = "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'SeparateProcess' -Value 1 -Type DWord"
        Command_PS7  = "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'SeparateProcess' -Value 1 -Type DWord"
        Command_PSLegacy = "reg.exe add `"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`" /v SeparateProcess /t REG_DWORD /d 1 /f"
        VersionNotes = "Registry provider Set-ItemProperty -Type DWord works identically in PS 5.1 and PS 7+; reg.exe provides universal fallback."
    },
    @{
        OperationId  = "CMD-REM-GPU"
        Category     = "GPU TDR Remediation"
        Title        = "Increase DirectX Kernel GPU Watchdog Timeout to 8s (REM-GPU-01)"
        Command_PS51 = "Start-Process powershell.exe -Verb RunAs -ArgumentList `"-NoProfile -Command Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -Name 'TdrDelay' -Value 8 -Type DWord`""
        Command_PS7  = "Start-Process pwsh.exe -Verb RunAs -ArgumentList `"-NoProfile -Command Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -Name 'TdrDelay' -Value 8 -Type DWord`""
        Command_PSLegacy = "reg.exe add `"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers`" /v TdrDelay /t REG_DWORD /d 8 /f"
        VersionNotes = "Requires Administrator elevation (HKLM). Uses powershell.exe on PS 5.1 and pwsh.exe on PS 7+."
    }
)

$versionSpecificCommands = @()
foreach ($row in $rawCmdMatrix) {
    $activeCmd = switch ($detectedProfile) {
        "PS7"   { $row.Command_PS7 }
        "PS51"  { $row.Command_PS51 }
        default { $row.Command_PSLegacy }
    }
    $versionSpecificCommands += [PSCustomObject]@{
        OperationId        = $row.OperationId
        Category           = $row.Category
        Operation          = $row.Title
        Title              = $row.Title
        DetectedProfile    = $detectedProfile
        ActiveLocalCommand = $activeCmd
        Command_PS51       = $row.Command_PS51
        Command_PS7        = $row.Command_PS7
        Command_PSLegacy   = $row.Command_PSLegacy
        VersionNotes       = $row.VersionNotes
    }
}

$psEnvironment = [PSCustomObject]@{
    ActiveVersion             = $psFullVer
    MajorVersion              = $psMajor
    PSEdition                 = $psEditionName
    CLRVersion                = $clrVer
    DetectedProfile           = $detectedProfile
    DetectedProfileLabel      = $detectedProfileLabel
    WindowsPowerShell51_Path  = if ($winPs51Installed) { $winPs51Path } else { "Not Found" }
    PowerShell7_Installed     = $pwshInstalled
    PowerShell7_Version       = $pwshVer
    PowerShell7_Path          = if ($pwshInstalled) { $pwshPath } else { "Not Installed (Using Windows PowerShell $psFullVer)" }
    ExecutionPolicies         = $execPolicies
    VersionSpecificCommands   = $versionSpecificCommands
}

$inventory = [PSCustomObject]@{
    ScriptId              = "HW-01"
    ScriptName            = "Get-HardwareInventory.ps1"
    CollectedAtLocal      = $nowLocal
    CollectedAtUtc        = $nowUtc
    IsElevatedAdmin       = $isAdmin
    PowerShellEnvironment = $psEnvironment
    SystemOverview        = [PSCustomObject]@{
        ComputerName       = $cs.Name
        DomainOrWorkgroup  = $cs.Domain
        UserName           = $cs.UserName
        Manufacturer       = $cs.Manufacturer
        Model              = $cs.Model
        SystemType         = $cs.SystemType
        OSName             = $os.Caption
        OSVersion          = $os.Version
        OSBuild            = $os.BuildNumber
        OSArchitecture     = $os.OSArchitecture
        InstallDate        = if ($os.InstallDate) { ([DateTime]$os.InstallDate).ToString("yyyy-MM-ddTHH:mm:sszzz") } else { "Unknown" }
        LastBootUpTime     = if ($os.LastBootUpTime) { ([DateTime]$os.LastBootUpTime).ToString("yyyy-MM-ddTHH:mm:sszzz") } else { "Unknown" }
        UptimeHours        = [math]::Round($uptimeSpan.TotalHours, 2)
        UptimeFormatted    = "$($uptimeSpan.Days)d $($uptimeSpan.Hours)h $($uptimeSpan.Minutes)m"
        TotalRAM_GB        = $totalRamGB
        UsedRAM_GB         = $usedRamGB
        FreeRAM_GB         = $freeRamGB
        UsedRAM_Percent    = $ramPercent
    }
    MotherboardAndBIOS = [PSCustomObject]@{
        BoardManufacturer  = $board.Manufacturer
        BoardProduct       = $board.Product
        BoardVersion       = $board.Version
        BoardSerial        = $board.SerialNumber
        BIOSManufacturer   = $bios.Manufacturer
        BIOSVersion        = $bios.SMBIOSBIOSVersion
        BIOSReleaseDate    = if ($bios.ReleaseDate) { ([DateTime]$bios.ReleaseDate).ToString("yyyy-MM-dd") } else { "Unknown" }
        BIOSSerialNumber   = $bios.SerialNumber
    }
    PlatformSecurity  = [PSCustomObject]@{
        SecureBoot         = $secureBootStatus
        TPM                = $tpmStatus
        BitLocker_OSDrive  = $bitlockerStatus
        VirtualizationBasedSecurity = $vbsStatus
    }
    CPUs              = $cpus
    MemoryModules     = $dimms
    GPUs              = $gpus
    Monitors          = $monitors
    PhysicalDisks     = $physicalDisks
    LogicalVolumes    = $logicalVolumes
    NetworkAdapters   = $netAdapters
    RecentHotfixes    = $hotfixes
    Peripherals       = $peripherals
}

$outDir = Split-Path -Path $OutputPath -Parent
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$inventory | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Output "Hardware inventory written to $OutputPath"
