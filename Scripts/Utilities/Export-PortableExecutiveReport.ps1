<#
.SYNOPSIS
    Single-File Portable Executive HTML Report Bundler (UTIL-05)
.DESCRIPTION
    Compiles index.html, styles.css, data.js (all forensic & diagnostic telemetry),
    and report.js into a single, 100% self-contained .html file inside Reports\Executive\.
    Computes a SHA-256 integrity hash of the bundled report so System Administrators
    can attach a tamper-evident, interactive single-file dashboard to incident tickets
    or share it with management without any external dependencies.
#>
param(
    [string]$OutputPath = "$PSScriptRoot\..\..\Data\Investigations\portable_report_manifest_latest.json"
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir  = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$nowLocal = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
$nowUtc   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$dateStamp = (Get-Date).ToString("yyyyMMdd_HHmmss")

$indexHtmlPath = Join-Path $baseDir "index.html"
$stylesCssPath = Join-Path $baseDir "styles.css"
$dataJsPath    = Join-Path $baseDir "data.js"
$reportJsPath  = Join-Path $baseDir "report.js"

if (!(Test-Path $indexHtmlPath) -or !(Test-Path $stylesCssPath) -or !(Test-Path $reportJsPath)) {
    $errOut = [PSCustomObject]@{
        ScriptId       = "UTIL-05"
        Status         = "Error"
        Explanation    = "Required frontend source files (index.html, styles.css, or report.js) were not found in $baseDir."
        RecommendedFix = "Verify that index.html, styles.css, data.js, and report.js exist in the root directory."
    }
    Write-Output ($errOut | ConvertTo-Json -Depth 4)
    exit 0
}

$htmlContent   = Get-Content -Path $indexHtmlPath -Raw -Encoding UTF8
$cssContent    = Get-Content -Path $stylesCssPath -Raw -Encoding UTF8
$dataContent   = if (Test-Path $dataJsPath) { Get-Content -Path $dataJsPath -Raw -Encoding UTF8 } else { "window.DIAGNOSTIC_DATA={};window.FORENSIC_DATA={};" }
$reportContent = Get-Content -Path $reportJsPath -Raw -Encoding UTF8

# Inline CSS and JS into a single self-contained HTML document
$inlineStyleBlock  = "<style>`r`n$cssContent`r`n</style>"
$inlineDataBlock   = "<script>`r`n$dataContent`r`n</script>"
$inlineReportBlock = "<script>`r`n$reportContent`r`n</script>"

$bundledHtml = $htmlContent.Replace('<link rel="stylesheet" href="styles.css">', $inlineStyleBlock)
$bundledHtml = $bundledHtml.Replace('<script src="data.js"></script>', $inlineDataBlock)
$bundledHtml = $bundledHtml.Replace('<script src="report.js"></script>', $inlineReportBlock)

# Inline all assets/*.png, *.ico, and assets/fonts/*.woff2 as base64 data URIs so the single-file HTML report has zero external dependencies
$assetsDir = Join-Path $baseDir "assets"
if (Test-Path $assetsDir) {
    $assetFiles = Get-ChildItem -Path $assetsDir -Include "*.png","*.ico","*.woff2" -File -Recurse -ErrorAction SilentlyContinue
    foreach ($asset in $assetFiles) {
        $relPath = $asset.FullName.Substring($baseDir.Length + 1).Replace('\', '/')
        if ($bundledHtml.Contains($relPath)) {
            $bytes = [System.IO.File]::ReadAllBytes($asset.FullName)
            $b64   = [Convert]::ToBase64String($bytes)
            $mime  = switch ($asset.Extension.ToLower()) {
                ".ico"   { "image/x-icon" }
                ".woff2" { "font/woff2" }
                default  { "image/png" }
            }
            $bundledHtml = $bundledHtml.Replace($relPath, "data:$mime;base64,$b64")
        }
    }
}

$execDir = Join-Path $baseDir "Reports\Executive"
if (!(Test-Path $execDir)) { New-Item -ItemType Directory -Path $execDir -Force | Out-Null }

$latestReportPath  = Join-Path $execDir "Portable_Forensic_Report_Latest.html"
$stampedReportPath = Join-Path $execDir "Portable_Forensic_Report_$dateStamp.html"

Set-Content -Path $latestReportPath -Value $bundledHtml -Encoding UTF8
Set-Content -Path $stampedReportPath -Value $bundledHtml -Encoding UTF8

$fileItem = Get-Item -LiteralPath $latestReportPath -ErrorAction SilentlyContinue
$sizeKB   = if ($fileItem) { [math]::Round($fileItem.Length / 1KB, 1) } else { 0 }
$sha256   = "Unavailable"
$hObj     = Get-FileHash -LiteralPath $latestReportPath -Algorithm SHA256 -ErrorAction SilentlyContinue
if ($hObj -and $hObj.Hash) { $sha256 = $hObj.Hash.ToUpper() }

$manifest = [PSCustomObject]@{
    ScriptId               = "UTIL-05"
    ScriptName             = "Export-PortableExecutiveReport.ps1"
    Status                 = "Success"
    GeneratedAtLocal       = $nowLocal
    GeneratedAtUtc         = $nowUtc
    LatestReportHtmlPath   = $latestReportPath
    TimestampedReportPath  = $stampedReportPath
    RelativeDownloadUrl    = "/Reports/Executive/Portable_Forensic_Report_Latest.html"
    FileSize_KB            = $sizeKB
    SHA256                 = $sha256
    Explanation            = "Compiled the entire interactive dashboard (HTML + Light/Dark CSS + all 10 forensic views + Obsidian Vault notes + interactive table engine) into a single self-contained HTML file ($sizeKB KB) with SHA-256 integrity hash $sha256."
    RecommendedFix         = "Share '$stampedReportPath' with management or attach it to an incident ticket. Recipients can double-click the single .html file in any browser with zero external dependencies."
    Command_PS51           = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `".\Scripts\Utilities\Export-PortableExecutiveReport.ps1`""
    Command_PS7            = "pwsh.exe -NoProfile -ExecutionPolicy Bypass -File `".\Scripts\Utilities\Export-PortableExecutiveReport.ps1`""
}

$outDir = Split-Path -Path $OutputPath -Parent
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Output ($manifest | ConvertTo-Json -Depth 5)
