<#
.SYNOPSIS
    Master Forensic & Diagnostic Orchestrator Script (CORE-01)
.DESCRIPTION
    Executes the read-only forensic script suite across Hardware, Performance,
    Processes, Services, Drivers, Registry, Network (+ IP Intelligence),
    Event Logs, Incident Investigation, Binary Integrity, Malware/Persistence,
    Crash Dumps, Entity Correlation, and Obsidian Vault synchronization.
    Compiles a unified master dataset (Data\Telemetry\master_dashboard_data.json)
    and updates data.js for immediate Dashboard rendering.
#>
param(
    [switch]$QuickMode = $false
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$startClock = Get-Date

$steps = @(
    @{ Id = "HW-01";   Path = "$baseDir\Scripts\Hardware\Get-HardwareInventory.ps1" },
    @{ Id = "PERF-01"; Path = "$baseDir\Scripts\Performance\Get-PerformanceTelemetry.ps1" },
    @{ Id = "PROC-01"; Path = "$baseDir\Scripts\Processes\Get-ProcessInventory.ps1" },
    @{ Id = "SVC-01";  Path = "$baseDir\Scripts\Services\Get-ServiceInventory.ps1" },
    @{ Id = "DRV-01";  Path = "$baseDir\Scripts\Drivers\Get-DriverInventory.ps1" },
    @{ Id = "REG-01";  Path = "$baseDir\Scripts\Registry\Get-RegistryPersistence.ps1" },
    @{ Id = "NET-01";  Path = "$baseDir\Scripts\Networking\Get-NetworkForensics.ps1" },
    @{ Id = "EVT-01";  Path = "$baseDir\Scripts\EventLogs\Get-WindowsEventForensics.ps1" },
    @{ Id = "INC-01";  Path = "$baseDir\Scripts\EventLogs\Invoke-IncidentInvestigation.ps1" },
    @{ Id = "CORR-01"; Path = "$baseDir\Scripts\Core\Invoke-EntityCorrelation.ps1" },
    @{ Id = "INT-01";  Path = "$baseDir\Scripts\Integrity\Test-SystemBinaryIntegrity.ps1" },
    @{ Id = "MAL-01";  Path = "$baseDir\Scripts\Malware\Invoke-MalwarePersistenceAudit.ps1" },
    @{ Id = "MAL-02";  Path = "$baseDir\Scripts\Malware\Invoke-DeepPersistenceAndScriptBlockAudit.ps1" },
    @{ Id = "MEM-01";  Path = "$baseDir\Scripts\Memory\Get-CrashDumpForensics.ps1" },
    @{ Id = "UTIL-04"; Path = "$baseDir\Scripts\Utilities\Export-SuperTimeline.ps1" },
    @{ Id = "UTIL-03"; Path = "$baseDir\Scripts\Utilities\Install-BrowserDiagSnippet.ps1" },
    @{ Id = "UTIL-01"; Path = "$baseDir\Scripts\Utilities\Sync-ObsidianVault.ps1" },
    @{ Id = "UTIL-02"; Path = "$baseDir\Scripts\Utilities\Export-ForensicReport.ps1" }
)

$executionResults = @()
foreach ($st in $steps) {
    if ($QuickMode -and $st.Id -in @("INT-01", "DRV-01")) { continue }
    $t0 = Get-Date
    $status = "Success"
    try {
        & $st.Path | Out-Null
    } catch {
        $status = "Error: $($_.Exception.Message)"
    }
    $dur = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
    $executionResults += [PSCustomObject]@{
        ScriptId    = $st.Id
        ScriptPath  = $st.Path
        DurationSec = $dur
        Status      = $status
    }
}

# Load all generated JSON datasets and legacy diagnostics_data.json
function Read-JsonSafe([string]$p) {
    if (Test-Path $p) {
        try { return (Get-Content $p -Raw | ConvertFrom-Json) } catch { return $null }
    }
    return $null
}

$legacyData = Read-JsonSafe "$baseDir\Data\Baselines\Initial_Backup_20261025\diagnostics_data.json"
if (!$legacyData) { $legacyData = Read-JsonSafe "$baseDir\diagnostics_data.json" }

$obsidianNotes = @()
$vaultPath = Join-Path $baseDir "ObsidianVault"
if (Test-Path $vaultPath) {
    Get-ChildItem -Path $vaultPath -Filter "*.md" -Recurse -ErrorAction SilentlyContinue | Sort-Object FullName | ForEach-Object {
        $relFolder = $_.Directory.FullName.Replace($vaultPath, "").Trim("\")
        if ([string]::IsNullOrWhiteSpace($relFolder)) { $relFolder = "Root" }
        $obsidianNotes += [PSCustomObject]@{
            fileName  = $_.Name
            folder    = $relFolder
            sizeBytes = $_.Length
            modified  = $_.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:sszzz")
            content   = (Get-Content -Path $_.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue)
        }
    }
}

$masterPayload = [PSCustomObject]@{
    GeneratedAtLocal    = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
    GeneratedAtUtc      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    TotalDurationSec    = [math]::Round(((Get-Date) - $startClock).TotalSeconds, 2)
    ScriptRunSummary    = $executionResults
    Hardware            = Read-JsonSafe "$baseDir\Data\Inventory\hardware_inventory_latest.json"
    Performance         = Read-JsonSafe "$baseDir\Data\Telemetry\performance_telemetry_latest.json"
    Processes           = Read-JsonSafe "$baseDir\Data\Inventory\process_inventory_latest.json"
    Services            = Read-JsonSafe "$baseDir\Data\Inventory\service_inventory_latest.json"
    Drivers             = Read-JsonSafe "$baseDir\Data\Inventory\driver_inventory_latest.json"
    Registry            = Read-JsonSafe "$baseDir\Data\Inventory\registry_persistence_latest.json"
    Network             = Read-JsonSafe "$baseDir\Data\Inventory\network_forensics_latest.json"
    Events              = Read-JsonSafe "$baseDir\Data\Telemetry\event_forensics_latest.json"
    Incidents           = Read-JsonSafe "$baseDir\Data\Investigations\incident_investigation_latest.json"
    CorrelatedEntities  = Read-JsonSafe "$baseDir\Data\Inventory\correlated_entities_latest.json"
    BinaryIntegrity     = Read-JsonSafe "$baseDir\Data\Inventory\binary_integrity_latest.json"
    SecurityFindings    = Read-JsonSafe "$baseDir\Data\Investigations\security_findings_latest.json"
    DeepPersistence     = Read-JsonSafe "$baseDir\Data\Investigations\deep_persistence_scriptblock_latest.json"
    SuperTimeline       = Read-JsonSafe "$baseDir\Data\Investigations\super_timeline_latest.json"
    MemoryForensics     = Read-JsonSafe "$baseDir\Data\Investigations\memory_crash_forensics_latest.json"
    ObsidianNotes       = $obsidianNotes
    LegacyBaselineAudit = [PSCustomObject]@{
        ReportTitle             = $legacyData.ReportTitle
        GeneratedDate           = $legacyData.GeneratedDate
        SystemSummary           = $legacyData.SystemSummary
        ExecutiveFindings       = $legacyData.ExecutiveFindings
        LogonLagDetails         = $legacyData.LogonLagDetails
        ShutdownLagDetails      = $legacyData.ShutdownLagDetails
        ResourceBloatAnalysis   = $legacyData.ResourceBloatAnalysis
        NetworkSecurityAnalysis = $legacyData.NetworkSecurityAnalysis
        ActionPlan              = $legacyData.ActionPlan
    }
}

$masterJsonPath = "$baseDir\Data\Telemetry\master_dashboard_data.json"
$masterJsonStr = $masterPayload | ConvertTo-Json -Depth 7
$masterJsonStr | Set-Content -Path $masterJsonPath -Encoding UTF8

# Also update data.js so both window.DIAGNOSTIC_DATA (preserved legacy compatibility) and window.FORENSIC_DATA (expanded platform) are populated
$legacyCompact = $masterPayload.LegacyBaselineAudit | ConvertTo-Json -Depth 6
$jsContent = "// Auto-generated by Invoke-FullSystemSnapshot.ps1 at $((Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz'))`r`n" +
             "window.DIAGNOSTIC_DATA = $legacyCompact;`r`n" +
             "window.FORENSIC_DATA = $masterJsonStr;`r`n"
$jsContent | Set-Content -Path "$baseDir\data.js" -Encoding UTF8

Write-Output "Full system snapshot completed in $($masterPayload.TotalDurationSec)s. Master JSON saved to $masterJsonPath"
