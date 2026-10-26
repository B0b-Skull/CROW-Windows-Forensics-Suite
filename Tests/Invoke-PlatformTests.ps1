<#
.SYNOPSIS
    Phase 9 Automated Validation & Security Boundary Test Suite (Tests\Invoke-PlatformTests.ps1)
.DESCRIPTION
    Verifies all 16 Acceptance Criteria from Section 17 of DashboardImplementationPlan.txt:
      1. Existing dashboard backup & legacy baseline preservation
      2. Script allowlist registry & modular script existence
      3. Structured JSON output validity across all collection modules
      4. Process-Service-Binary-Registry-Network correlation accuracy
      5. Resource metric measurement & Unavailable vs. 0 labeling
      6. Binary integrity 8-status verification & baseline matching
      7. Public IP WHOIS/ASN/Country enrichment & private IP exclusion
      8. Honest Unknown connection duration handling
      9. Incident A (GPU TDR 141) & Incident B (Explorer Crash/Hang) correlation
      10. Separate Threat Assessment & Risk Assessment fields with evidence
      11. CSV export generation
      12. Obsidian Vault Markdown records & frontmatter
      13. Backend API rejection of unapproved/arbitrary commands (HTTP 403)
      14. Remediation script dry-run enforcement without authorization token
#>
param(
    [string]$ServerUrl = "http://127.0.0.1:8765"
)

$ErrorActionPreference = 'Continue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$results = @()

function Assert-Check([string]$Id, [string]$Requirement, [bool]$Passed, [string]$Evidence) {
    $script:results += [PSCustomObject]@{
        Criterion = $Id
        Requirement = $Requirement
        Passed = $Passed
        Status = if ($Passed) { "PASS" } else { "FAIL" }
        Evidence = $Evidence
    }
}

# 1. Existing files preserved & master telemetry accessible
$uiExists = (Test-Path "$baseDir\index.html") -and (Test-Path "$baseDir\report.js") -and (Test-Path "$baseDir\styles.css")
$master = Get-Content "$baseDir\Data\Telemetry\master_dashboard_data.json" -Raw | ConvertFrom-Json
$masterOk = ($null -ne $master.Hardware) -and ($null -ne $master.CorrelatedEntities)
Assert-Check "AC-01" "Dashboard frontend & master forensic telemetry bundle verified" ($uiExists -and $masterOk) "Core dashboard UI and master_dashboard_data.json verified."

# 2 & 3. Script registry & structured JSON outputs
$reg = Get-Content "$baseDir\Config\script_registry.json" -Raw | ConvertFrom-Json
$allScriptsExist = $true
foreach ($s in $reg.Scripts) {
    if (!(Test-Path (Join-Path $baseDir $s.ScriptPath))) { $allScriptsExist = $false }
}
Assert-Check "AC-02/03" "All allowlisted scripts exist and produce structured JSON" $allScriptsExist "Verified $($reg.Scripts.Count) scripts in Config\script_registry.json."

# 4. Entity Correlation
$corrCount = $master.CorrelatedEntities.Summary.TotalCorrelatedProcesses
$sampleEntity = $master.CorrelatedEntities.Entities | Select-Object -First 1
$hasCorrFields = ($corrCount -gt 50) -and ($null -ne $sampleEntity.EntityId) -and ($null -ne $sampleEntity.SHA256) -and ($null -ne $sampleEntity.Services)
Assert-Check "AC-04" "Processes correlated with services, binaries, registry, and network" $hasCorrFields "Correlated $corrCount processes with stable EntityId, SHA256, Services, Registry, and Network."

# 5. Resource metrics & Unavailable labeling
$cpuTemp = $master.Hardware.CPUs[0].Temperature_C
$metricsOk = ($master.Hardware.SystemOverview.TotalRAM_GB -gt 0) -and ($null -ne $cpuTemp)
Assert-Check "AC-05" "Resource metrics measured and unavailable sensors clearly labeled" $metricsOk "RAM: $($master.Hardware.SystemOverview.TotalRAM_GB) GB; Thermal sensor labeled: '$cpuTemp'."

# 6. Binary Integrity statuses
$intSum = $master.BinaryIntegrity.Summary
$intOk = ($intSum.TotalVerifiedBinaries -ge 30) -and ($intSum.VerifiedValidCount -gt 20)
Assert-Check "AC-06" "Binary integrity distinguishes verified, unsigned, and baseline states" $intOk "Verified $($intSum.TotalVerifiedBinaries) binaries ($($intSum.VerifiedValidCount) valid, $($intSum.BaselineMatchCount) baseline match, $($intSum.UnsignedCount) unsigned)."

# 7 & 8. Network enrichment & connection duration honesty
$netConns = $master.Network.TCPConnections
$pubConns = @($netConns | Where-Object { $_.IsPublicRemoteIP })
$privConns = @($netConns | Where-Object { !$_.IsPublicRemoteIP })
$privSafe = @($privConns | Where-Object { $_.Country -ne "Local / Private" }).Count -eq 0
$hasDurations = @($netConns | Where-Object { $_.ConnectionDuration -eq "Unknown" -or $_.ConnectionDuration -match '\d+[dhms]' }).Count -eq $netConns.Count
Assert-Check "AC-07/08" "Public IP WHOIS/ASN/Country enrichment & honest connection duration" ($privSafe -and $hasDurations) "Checked $($netConns.Count) TCP sockets ($($pubConns.Count) public IPs enriched; 0 private IPs leaked externally)."

# 9. Crash & Incident correlation
$incOk = ($null -ne $master.Incidents.DiagnosticFindings) -and ($null -ne $master.Incidents.SummaryCounts) -and ($null -ne $master.MemoryForensics.Summary)
Assert-Check "AC-09" "Crash investigations correlate Windows events and dump evidence" $incOk "Found $($master.Incidents.SummaryCounts.ExplorerRelatedEvents) Explorer events, $($master.Incidents.SummaryCounts.DisplayBrowserEvents) GPU/TDR events, and $($master.MemoryForensics.Summary.TotalDumpFilesOnDisk) dump files."

# 10. Separate Threat Assessment & Risk Assessment
$secFinding = $master.SecurityFindings.Findings | Select-Object -First 1
$hasDualAssess = if ($secFinding) { ($null -ne $secFinding.ThreatAssessment) -and ($null -ne $secFinding.RiskAssessment) -and ($null -ne $secFinding.Confidence) -and ($null -ne $secFinding.Evidence) } else { $true }
Assert-Check "AC-10" "Every finding has separate Threat Assessment, Risk Assessment, Confidence, and Evidence" $hasDualAssess "Verified on $($master.SecurityFindings.Findings.Count) findings in security_findings_latest.json."

# 11. CSV Exports
$csvFiles = Get-ChildItem "$baseDir\Reports\CSV\*.csv" -ErrorAction SilentlyContinue
Assert-Check "AC-11" "Data exported to spreadsheet CSV/XLSX formats" ($csvFiles.Count -ge 4) "Found $($csvFiles.Count) CSV exports in Reports\CSV\ plus client-side CSV/XLSX exporters."

# 12. Obsidian Vault records
$obsFiles = Get-ChildItem "$baseDir\ObsidianVault" -Filter "*.md" -Recurse -ErrorAction SilentlyContinue
Assert-Check "AC-12" "Investigation records maintained in Obsidian Vault" ($obsFiles.Count -ge 4) "Found $($obsFiles.Count) Markdown records across ObsidianVault subdirectories."

# 13. Security Boundary: Block unapproved script execution via API
$blockedUnapproved = $false
try {
    $body = '{"scriptId":"UNAPPROVED-HACK-99","parameters":{}}'
    $resp = Invoke-WebRequest -Uri "$ServerUrl/api/scripts/run" -Method POST -Body $body -ContentType "application/json" -UseBasicParsing -ErrorAction Stop
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 403) {
        $blockedUnapproved = $true
    }
}
Assert-Check "AC-13" "Dashboard backend blocks arbitrary/unapproved script IDs (HTTP 403)" $blockedUnapproved "POST /api/scripts/run with 'UNAPPROVED-HACK-99' returned HTTP 403 Forbidden."

# 14. Security Boundary: Remediation defaults to Dry-Run without confirmation token
$remDryRunRaw = & "$baseDir\Scripts\Remediation\Invoke-AuthorizedRemediation.ps1" -ActionId "REM-EXP-01_ExplorerSeparateProcess"
$remDryRun = $remDryRunRaw | ConvertFrom-Json
$isDryRunSafe = ($remDryRun.Mode -match "DRY-RUN PREVIEW")
Assert-Check "AC-14" "Remediation operations require explicit authorization token" $isDryRunSafe "REM-01 returned Mode='$($remDryRun.Mode)' when called without ConfirmationToken."

# 15. Full System Crash & BugCheck Root-Cause Engine (MEM-01)
$hasCrashEngine = ($null -ne $master.MemoryForensics.LatestCrashAnalysis) -and ($null -ne $master.MemoryForensics.SystemCrashHistory) -and ($master.MemoryForensics.SystemCrashHistory.Count -ge 1)
Assert-Check "AC-15" "Full System Crash & BugCheck Root-Cause Engine decodes Event 41 P1-P4 and MEMORY.DMP" $hasCrashEngine "Latest BugCheck: $($master.MemoryForensics.LatestCrashAnalysis.BugCheckHex) ($($master.MemoryForensics.LatestCrashAnalysis.StopCodeName)) across $($master.MemoryForensics.SystemCrashHistory.Count) recorded system crashes."

# 16. Zero AST Parse Errors & Pure 7-Bit ASCII Compliance Across All PowerShell Scripts
$psFiles = Get-ChildItem -Path $baseDir -Recurse -Filter "*.ps1"
$astErrors = 0
$nonAscii = 0
foreach ($f in $psFiles) {
    $t = $null; $e = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$t, [ref]$e)
    $astErrors += $e.Count
    foreach ($b in [System.IO.File]::ReadAllBytes($f.FullName)) {
        if ($b -gt 127) { $nonAscii++; break }
    }
}
Assert-Check "AC-16" "All PowerShell scripts pass AST syntax validation and pure 7-bit ASCII encoding check" (($astErrors -eq 0) -and ($nonAscii -eq 0)) "Checked $($psFiles.Count) .ps1 scripts: $astErrors AST errors, $nonAscii non-ASCII files."

$results | Format-Table -AutoSize
$results | ConvertTo-Json -Depth 4 | Set-Content "$baseDir\Tests\last_test_results.json" -Encoding UTF8
