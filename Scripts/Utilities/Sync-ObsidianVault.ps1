<#
.SYNOPSIS
    Obsidian Vault Knowledge Repository Synchronizer (UTIL-01)
.DESCRIPTION
    Automatically generates and updates Obsidian-compatible Markdown records
    in ObsidianVault\ with YAML frontmatter, [[WikiLinks]], system baseline
    snapshots, security findings, and incident investigation logs.
    Compatible with Windows PowerShell 3.0, 4.0, 5.1 (Desktop) and PowerShell 7+ (Core).
#>
param(
    [string]$VaultRoot = ""
)

$ErrorActionPreference = 'Continue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($VaultRoot)) {
    $VaultRoot = Join-Path $baseDir "ObsidianVault"
}

$nowLocal = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
$nowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$dateStamp = Get-Date -Format "yyyy-MM-dd"
$bt = [char]96

$syncedFiles = @()
$warnings = @()

try {
    foreach ($sub in @("SystemBaselines", "ThreatFindings", "Investigations", "RemediationHistory", "Architecture")) {
        $p = Join-Path $VaultRoot $sub
        if (!(Test-Path $p)) {
            New-Item -ItemType Directory -Path $p -Force -ErrorAction Stop | Out-Null
        }
    }
} catch {
    $errOut = [PSCustomObject]@{
        ScriptId       = "UTIL-01"
        ScriptName     = "Sync-ObsidianVault.ps1"
        Status         = "Error"
        ErrorMessage   = "Failed to create ObsidianVault directory structure at '$VaultRoot': $($_.Exception.Message)"
        Explanation    = "The script could not create or write to the ObsidianVault subfolder due to directory permissions or a file lock."
        RecommendedFix = "Verify that the current user ($env:USERNAME) has Write permissions to '$VaultRoot' and that no files are locked exclusively."
    }
    $errOut | ConvertTo-Json -Depth 4
    exit 1
}

function Read-SafeJson([string]$path) {
    if (Test-Path $path) {
        try {
            return (Get-Content -Path $path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json)
        } catch {
            $script:warnings += "Could not parse JSON at ${path}: $($_.Exception.Message)"
            return $null
        }
    }
    return $null
}

$hwPath   = Join-Path $baseDir "Data\Inventory\hardware_inventory_latest.json"
$corrPath = Join-Path $baseDir "Data\Inventory\correlated_entities_latest.json"
$intPath  = Join-Path $baseDir "Data\Inventory\binary_integrity_latest.json"
$secPath  = Join-Path $baseDir "Data\Investigations\security_findings_latest.json"
$memPath  = Join-Path $baseDir "Data\Investigations\memory_crash_forensics_latest.json"
$incPath  = Join-Path $baseDir "Data\Investigations\incident_investigation_latest.json"

$hw   = Read-SafeJson $hwPath
$corr = Read-SafeJson $corrPath
$int  = Read-SafeJson $intPath
$sec  = Read-SafeJson $secPath
$mem  = Read-SafeJson $memPath
$inc  = Read-SafeJson $incPath

$hostName = if ($hw -and $hw.SystemOverview -and $hw.SystemOverview.ComputerName) { $hw.SystemOverview.ComputerName } else { $env:COMPUTERNAME }

# 1. Update System Baseline Note
if ($hw -and $hw.SystemOverview) {
    try {
        $sys = $hw.SystemOverview
        $cpuLines = ($hw.CPUs | ForEach-Object { "- **CPU:** $($_.Name) ($($_.PhysicalCores) Cores / $($_.LogicalProcessors) Threads @ $($_.MaxClockSpeed_MHz) MHz, Load: $($_.LoadPercentage)%)" }) -join "`r`n"
        $gpuLines = ($hw.GPUs | ForEach-Object { "- **GPU:** $($_.Name) | Driver: ${bt}$($_.DriverVersion)${bt} ($($_.DriverDate)) | Status: $($_.Status)" }) -join "`r`n"
        $volLines = ($hw.LogicalVolumes | ForEach-Object { "| ${bt}$($_.DriveLetter)${bt} | $($_.VolumeName) | $($_.FileSystem) | $($_.Size_GB) | $($_.Used_GB) | $($_.Free_GB) | $($_.Used_Percent)% |" }) -join "`r`n"

        $baselineMd = @"
---
id: BASELINE-$dateStamp
title: "System Hardware & OS Baseline ($hostName)"
date: $nowLocal
host: $hostName
os_build: $($sys.OSBuild)
tags:
  - baseline
  - hardware
  - system-state
---

# System Baseline: $hostName ($dateStamp)

## 1. Host Overview
- **Hostname:** ${bt}$($sys.ComputerName)${bt}
- **User:** ${bt}$($sys.UserName)${bt}
- **Operating System:** $($sys.OSName) (Version ${bt}$($sys.OSVersion)${bt}, Build ${bt}$($sys.OSBuild)${bt})
- **Last Boot Time:** ${bt}$($sys.LastBootUpTime)${bt} (Uptime: ${bt}$($sys.UptimeFormatted)${bt})
- **Physical RAM:** ${bt}$($sys.UsedRAM_GB) GB${bt} used / ${bt}$($sys.TotalRAM_GB) GB${bt} total (${bt}$($sys.UsedRAM_Percent)%${bt})
- **Platform Security:**
  - **Secure Boot:** $($hw.PlatformSecurity.SecureBoot)
  - **TPM:** $($hw.PlatformSecurity.TPM)
  - **VBS / DeviceGuard:** $($hw.PlatformSecurity.VirtualizationBasedSecurity)

## 2. Processors & GPUs
$cpuLines
$gpuLines

## 3. Storage Volumes
| Drive | Label | FileSystem | Size (GB) | Used (GB) | Free (GB) | Usage % |
|---|---|---|---:|---:|---:|---:|
$volLines

## 4. Related Vault Records
- [[INV-$dateStamp-Stability-Report]]
- [[THREAT-$dateStamp-Summary]]
"@
        $baseOutPath = Join-Path $VaultRoot "SystemBaselines\BASELINE-$dateStamp.md"
        $baselineMd | Set-Content -Path $baseOutPath -Encoding UTF8 -ErrorAction Stop
        $syncedFiles += $baseOutPath
    } catch {
        $warnings += "Failed writing SystemBaseline note: $($_.Exception.Message)"
    }
}

# 2. Update Threat & Security Findings Note
if ($sec) {
    try {
        $totBin = if ($int -and $int.Summary) { $int.Summary.TotalVerifiedBinaries } else { 'N/A' }
        $valBin = if ($int -and $int.Summary) { $int.Summary.VerifiedValidCount } else { 'N/A' }
        $basMat = if ($int -and $int.Summary) { $int.Summary.BaselineMatchCount } else { 'N/A' }
        $basMis = if ($int -and $int.Summary) { $int.Summary.BaselineMismatchCount } else { 0 }
        $unsBin = if ($int -and $int.Summary) { $int.Summary.UnsignedCount } else { 0 }

        $secRows = ($sec.Findings | ForEach-Object {
            $safeEv = ($_.Evidence -replace '\|', '/') -replace '\r?\n', ' '
            "| ${bt}$($_.FindingId)${bt} | $($_.Title) | $($_.Category) | **$($_.ThreatAssessment)** | **$($_.RiskAssessment)** | $($_.Confidence) | $safeEv |"
        }) -join "`r`n"

        $threatMd = @"
---
id: THREAT-$dateStamp
title: "Automated Security, Persistence & Integrity Findings ($hostName - $dateStamp)"
date: $nowLocal
host: $hostName
tags:
  - threat-findings
  - risk-assessment
  - persistence
  - integrity
---

# Threat & Risk Assessment Findings ($hostName - $dateStamp)

> [!NOTE]
> **$($sec.RootkitDisclaimer)**

## 1. Windows Defender Posture
- **Antivirus Enabled:** ${bt}$($sec.DefenderStatus.AntivirusEnabled)${bt}
- **Real-Time Protection:** ${bt}$($sec.DefenderStatus.RealTimeProtectionEnabled)${bt}
- **Signature Version:** ${bt}$($sec.DefenderStatus.SignatureVersion)${bt} (Updated: ${bt}$($sec.DefenderStatus.SignatureLastUpdated)${bt})
- **Historical Threat Detections:** ${bt}$($sec.DefenderStatus.ActiveThreatCount)${bt}

## 2. Binary Integrity Summary
- **Total Verified Binaries:** ${bt}$totBin${bt}
- **Verified Valid Signatures:** ${bt}$valBin${bt}
- **Baseline Matches:** ${bt}$basMat${bt}
- **Baseline Mismatches:** ${bt}$basMis${bt}
- **Unsigned Binaries:** ${bt}$unsBin${bt}

## 3. Evidence-Based Findings Table
| ID | Title | Category | Threat | Risk | Confidence | Evidence |
|---|---|---|---|---|---|---|
$secRows

## 4. Linked Records
- [[BASELINE-$dateStamp]]
- [[INV-$dateStamp-Stability-Report]]
"@
        $threatOutPath = Join-Path $VaultRoot "ThreatFindings\THREAT-$dateStamp-Summary.md"
        $threatMd | Set-Content -Path $threatOutPath -Encoding UTF8 -ErrorAction Stop
        $syncedFiles += $threatOutPath
    } catch {
        $warnings += "Failed writing ThreatFindings note: $($_.Exception.Message)"
    }
}

# 3. Update Dynamic System Stability & Incident Investigation Note
if ($inc) {
    try {
        $incRows = ($inc.DiagnosticFindings | ForEach-Object {
            $sc = ($_.SuspectedCause -replace '\|', '/') -replace '\r?\n', ' '
            $ev = ($_.Evidence -replace '\|', '/') -replace '\r?\n', ' '
            $ra = ($_.RecommendedAction -replace '\|', '/') -replace '\r?\n', ' '
            "| **$($_.Incident)** | $sc | $ev | $($_.Confidence) | **$($_.RiskAssessment)** | $ra |"
        }) -join "`r`n"

        $crashSectionMd = ""
        if ($mem -and $mem.LatestCrashAnalysis) {
            $lca = $mem.LatestCrashAnalysis
            $preCorrMd = if ($lca.PreCrashActivitySummary) { $lca.PreCrashActivitySummary } else { "None recorded in the 30-minute pre-crash window." }
            $crashSectionMd = @"

## 2. Full System Crash & BugCheck Root-Cause Analysis (MEM-01)
- **Stop Code / BugCheck:** ${bt}$($lca.BugCheckHex) ($($lca.StopCodeName))${bt}
- **Crash Reboot Timestamp:** ${bt}$($lca.CrashTimeLocal)${bt} (Event RecordId: ${bt}$($lca.EventRecordId)${bt})
- **Suspected Fault Module / Subsystem:** ${bt}$($lca.FaultModule)${bt}
- **Sub-Status / Exception:** ${bt}$($lca.SubStatusHex) ($($lca.SubStatusName))${bt}
- **Decoded 64-Bit BugCheck Parameters:**
  - **Parameter 1:** ${bt}$($lca.Param1Hex)${bt} -- $($lca.Param1Meaning)
  - **Parameter 2:** ${bt}$($lca.Param2Hex)${bt} -- $($lca.Param2Meaning)
  - **Parameter 3:** ${bt}$($lca.Param3Hex)${bt} -- $($lca.Param3Meaning)
  - **Parameter 4:** ${bt}$($lca.Param4Hex)${bt} -- $($lca.Param4Meaning)
- **Kernel Dump Status:** ${bt}$($lca.DumpFileStatus)${bt}
- **30-Minute Pre-Crash Activity Correlation:** $preCorrMd
- **Primary Root-Cause Diagnosis:** $($lca.PrimaryDiagnosis)
- **Recommended Remediation:** $($lca.RemediationSteps)
"@
        }

        $incMd = @"
---
id: INV-$dateStamp-Stability-Report
title: "System Stability, GPU TDR & Shell Crash Diagnostic Report ($hostName)"
date: $nowLocal
host: $hostName
tags:
  - investigation
  - stability
  - crash-dumps
  - gpu-tdr
---

# System Stability & Incident Diagnostic Report: $hostName ($dateStamp)

## 1. Automated Diagnostic Findings
| Incident / Subsystem | Suspected Cause | Supporting Forensic Evidence | Confidence | Risk | Recommended Safe Action |
|---|---|---|---|---|---|
$incRows
$crashSectionMd

## 3. Telemetry Summary Counts (Last $($inc.LookbackDays) Days)
- **Application Error / Hang / WER Events:** ${bt}$($inc.SummaryCounts.ApplicationErrorEvents)${bt}
- **Explorer / Shell Related Events:** ${bt}$($inc.SummaryCounts.ExplorerRelatedEvents)${bt}
- **Display / GPU / Browser Events:** ${bt}$($inc.SummaryCounts.DisplayBrowserEvents)${bt}
- **Crash Dumps on Disk:** ${bt}$($inc.SummaryCounts.CrashDumpFiles)${bt}
- **Shell Context Menu Handlers:** ${bt}$($inc.SummaryCounts.ShellContextHandlers)${bt}
- **IFEO Debugger Hooks:** ${bt}$($inc.SummaryCounts.IFEODebuggerHooks)${bt}

## 4. Linked Records
- [[BASELINE-$dateStamp]]
- [[THREAT-$dateStamp-Summary]]
"@
        $incOutPath = Join-Path $VaultRoot "Investigations\INV-$dateStamp-Stability-Report.md"
        $incMd | Set-Content -Path $incOutPath -Encoding UTF8 -ErrorAction Stop
        $syncedFiles += $incOutPath
    } catch {
        $warnings += "Failed writing Incident Investigation note: $($_.Exception.Message)"
    }
}

# 4. Create Vault Index / Home Note
try {
    $indexMd = @"
---
id: VAULT-INDEX
title: "CROW INNOVATIONS Windows System Analysis & Forensics Knowledge Vault ($hostName)"
date: $nowLocal
host: $hostName
tags:
  - index
  - moc
  - forensics
---

# CROW INNOVATIONS Windows System Analysis & Forensics Obsidian Vault

Welcome to the persistent forensic investigation knowledge repository for host **${bt}$hostName${bt}** (powered by **CROW INNOVATIONS** -- https://crowinnovations.com/tools.html).

## Active Investigations & Baselines
- [[INV-$dateStamp-Stability-Report]] -- Automated Display/GPU TDR, Browser Stability & Shell/Application Crash Diagnostic Report.
- [[BASELINE-$dateStamp]] -- Hardware, OS, storage, GPU, and security baseline for ${bt}$hostName${bt}.
- [[THREAT-$dateStamp-Summary]] -- Deterministic Threat Assessment & Risk Assessment findings.

## Raw Evidence Artifacts (Relative to Workstation Root)
- ${bt}Data/Investigations/incident_investigation_latest.json${bt}
- ${bt}Data/Inventory/correlated_entities_latest.json${bt}
- ${bt}Data/Inventory/binary_integrity_latest.json${bt}
- ${bt}Data/Investigations/memory_crash_forensics_latest.json${bt}
"@
    $idxOutPath = Join-Path $VaultRoot "README_Vault_Index.md"
    $indexMd | Set-Content -Path $idxOutPath -Encoding UTF8 -ErrorAction Stop
    $syncedFiles += $idxOutPath
} catch {
    $warnings += "Failed writing Vault Index note: $($_.Exception.Message)"
}

$result = [PSCustomObject]@{
    ScriptId        = "UTIL-01"
    ScriptName      = "Sync-ObsidianVault.ps1"
    Status          = "Success"
    SyncedAtLocal   = $nowLocal
    SyncedAtUtc     = $nowUtc
    HostName        = $hostName
    VaultRoot       = $VaultRoot
    SyncedFileCount = $syncedFiles.Count
    SyncedFiles     = $syncedFiles
    Warnings        = $warnings
}
$result | ConvertTo-Json -Depth 5
exit 0
