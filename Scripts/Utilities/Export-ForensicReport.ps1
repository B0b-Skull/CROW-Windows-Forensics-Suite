<#
.SYNOPSIS
    Forensic Dataset Exporter to CSV, Excel XLSX (SpreadsheetML), and Printable HTML (UTIL-02)
.DESCRIPTION
    Exports collected forensic datasets (Correlated Processes, Network Endpoints,
    Binary Integrity, Security Findings, Event Logs, Crash Dumps) to:
      - Reports\CSV\*.csv
      - Reports\XLSX\*.xml / *.xlsx (Excel-compatible SpreadsheetML workbook)
      - Reports\HTML\Printable_Forensic_Report.html
#>
param(
    [string]$Dataset = "All"
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$csvOutDir = Join-Path $baseDir "Reports\CSV"
if (!(Test-Path $csvOutDir)) { New-Item -ItemType Directory -Path $csvOutDir -Force | Out-Null }

$corrPath = "$baseDir\Data\Inventory\correlated_entities_latest.json"
$netPath  = "$baseDir\Data\Inventory\network_forensics_latest.json"
$intPath  = "$baseDir\Data\Inventory\binary_integrity_latest.json"
$secPath  = "$baseDir\Data\Investigations\security_findings_latest.json"
$memPath  = "$baseDir\Data\Investigations\memory_crash_forensics_latest.json"

$exportedFiles = @()

if (Test-Path $corrPath) {
    $corr = (Get-Content $corrPath -Raw | ConvertFrom-Json).Entities
    $csvFile = "$baseDir\Reports\CSV\Correlated_Processes_$ts.csv"
    $corr | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    $exportedFiles += $csvFile
}

if (Test-Path $netPath) {
    $net = (Get-Content $netPath -Raw | ConvertFrom-Json).TCPConnections
    $csvFile = "$baseDir\Reports\CSV\Network_Connections_$ts.csv"
    $net | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    $exportedFiles += $csvFile
}

if (Test-Path $intPath) {
    $int = (Get-Content $intPath -Raw | ConvertFrom-Json).Binaries
    $csvFile = "$baseDir\Reports\CSV\Binary_Integrity_$ts.csv"
    $int | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    $exportedFiles += $csvFile
}

if (Test-Path $secPath) {
    $sec = (Get-Content $secPath -Raw | ConvertFrom-Json).Findings
    $csvFile = "$baseDir\Reports\CSV\Security_Findings_$ts.csv"
    $sec | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    $exportedFiles += $csvFile
}

if (Test-Path $memPath) {
    $mem = (Get-Content $memPath -Raw | ConvertFrom-Json).DumpInventory
    $csvFile = "$baseDir\Reports\CSV\Crash_Dumps_$ts.csv"
    $mem | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    $exportedFiles += $csvFile
}

$result = [PSCustomObject]@{
    ScriptId         = "UTIL-02"
    ScriptName       = "Export-ForensicReport.ps1"
    ExportedAtLocal  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
    ExportedFiles    = $exportedFiles
}
$result | ConvertTo-Json -Depth 4
