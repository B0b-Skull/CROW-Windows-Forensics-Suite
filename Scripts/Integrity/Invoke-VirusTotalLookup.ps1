<#
.SYNOPSIS
    On-Demand Binary, Service, Driver & DLL Hash Computation and VirusTotal Threat Intelligence Lookup (INT-03)
.DESCRIPTION
    Resolves any Windows executable (.exe), dynamic-link library (.dll), kernel driver (.sys),
    service command line, or raw SHA-256 hash.
    1. Safely normalizes service/registry command strings to locate the underlying file on disk.
    2. Computes cryptographic hashes (SHA-256, SHA-1, MD5), PE VersionInfo metadata, and Authenticode signature status.
    3. Queries the VirusTotal v3 REST API by SHA-256 hash ONLY (never uploads raw file bytes automatically)
       if an API key is configured in $env:VT_API_KEY or Config\vt_config.json.
    4. Generates direct browser lookup links for VirusTotal GUI, Hybrid-Analysis, and LOLBAS,
       plus plain-English Explanations, Recommended Fixes, and PowerShell 5.1 / 7+ commands.
#>
param(
    [string]$TargetPath = "",
    [string]$SHA256 = "",
    [string]$EntityName = "",
    [string]$OutputPath = "$PSScriptRoot\..\..\Data\Inventory\virustotal_lookup_latest.json"
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$psMajor = [int]$PSVersionTable.PSVersion.Major

function Resolve-CleanFilePath([string]$rawPath) {
    if ([string]::IsNullOrWhiteSpace($rawPath)) { return $null }
    $p = [Environment]::ExpandEnvironmentVariables($rawPath.Trim())

    # Strip kernel driver prefixes like \SystemRoot\ or \??\
    if ($p -match '^\\SystemRoot\\(.*)$') {
        $p = Join-Path $env:SystemRoot $Matches[1]
    } elseif ($p -match '^\\\?\?\\(.*)$') {
        $p = $Matches[1]
    } elseif ($p -match '^system32\\(.*)$' -or $p -match '^System32\\(.*)$') {
        $p = Join-Path $env:SystemRoot $p
    }

    if (Test-Path -LiteralPath $p -PathType Leaf) {
        return (Resolve-Path -LiteralPath $p).Path
    }

    # Handle quoted executable path with arguments: "C:\Path\file.exe" --arg1
    if ($p -match '^"([^"]+)"') {
        $candidate = $Matches[1]
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    # Handle unquoted executable/dll/sys path with arguments
    if ($p -match '^([a-zA-Z]:\\[^\r\n]*?\.(?:exe|dll|sys|ocx|cpl|scr))\b') {
        $candidate = $Matches[1]
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    # Check System32 if bare filename was passed (e.g. explorer.exe or ntoskrnl.exe)
    $sys32Candidate = Join-Path "$env:SystemRoot\System32" $p
    if (Test-Path -LiteralPath $sys32Candidate -PathType Leaf) {
        return (Resolve-Path -LiteralPath $sys32Candidate).Path
    }

    return $null
}

$resolvedFile = Resolve-CleanFilePath -rawPath $TargetPath
$cleanSha256 = if ($SHA256 -and $SHA256 -match '^[A-Fa-f0-9]{64}$') { $SHA256.ToUpper() } else { "" }
$sha1Hash = "Unavailable"
$md5Hash = "Unavailable"
$fileSize = 0
$fileVersion = "Unknown"
$productName = "Unknown"
$companyName = "Unknown"
$originalFileName = "Unknown"
$fileDescription = "Unknown"
$sigStatus = "Unknown"
$sigPublisher = "Unknown"
$sigThumbprint = "None"
$isOSBinary = $false

if ($resolvedFile -and (Test-Path -LiteralPath $resolvedFile -PathType Leaf)) {
    try {
        $item = Get-Item -LiteralPath $resolvedFile -Force -ErrorAction SilentlyContinue
        if ($item) {
            $fileSize = $item.Length
            if ([string]::IsNullOrWhiteSpace($EntityName)) { $EntityName = $item.Name }
            if ($item.VersionInfo) {
                $fileVersion      = [string]$item.VersionInfo.FileVersion
                $productName      = [string]$item.VersionInfo.ProductName
                $companyName      = [string]$item.VersionInfo.CompanyName
                $originalFileName = [string]$item.VersionInfo.OriginalFilename
                $fileDescription  = [string]$item.VersionInfo.FileDescription
            }
        }
        $h256 = Get-FileHash -LiteralPath $resolvedFile -Algorithm SHA256 -ErrorAction SilentlyContinue
        if ($h256 -and $h256.Hash) { $cleanSha256 = $h256.Hash.ToUpper() }

        $h1 = Get-FileHash -LiteralPath $resolvedFile -Algorithm SHA1 -ErrorAction SilentlyContinue
        if ($h1 -and $h1.Hash) { $sha1Hash = $h1.Hash.ToUpper() }

        $hMd5 = Get-FileHash -LiteralPath $resolvedFile -Algorithm MD5 -ErrorAction SilentlyContinue
        if ($hMd5 -and $hMd5.Hash) { $md5Hash = $hMd5.Hash.ToUpper() }

        $sig = Get-AuthenticodeSignature -LiteralPath $resolvedFile -ErrorAction SilentlyContinue
        if ($sig) {
            $sigStatus = [string]$sig.Status
            if ($sig.SignerCertificate) {
                $sigPublisher = [string]$sig.SignerCertificate.Subject
                $sigThumbprint = [string]$sig.SignerCertificate.Thumbprint
            }
            if ($null -ne $sig.IsOSBinary) {
                $isOSBinary = [bool]$sig.IsOSBinary
            }
        }
    } catch {}
}

if ([string]::IsNullOrWhiteSpace($cleanSha256)) {
    $errPayload = [PSCustomObject]@{
        ScriptId        = "INT-03"
        Status          = "FileNotFoundOrNoHash"
        TargetPathInput = $TargetPath
        SHA256Input     = $SHA256
        Explanation     = "Could not compute a SHA-256 hash because no valid SHA-256 hash was provided and the file path '$TargetPath' could not be resolved on disk (or is a protected kernel pseudo-path)."
        RecommendedFix  = "Provide a valid full file path (for example C:\Windows\System32\ntoskrnl.exe or a Service/DLL path) or a 64-character SHA-256 hash."
        Command_PS51    = "Get-FileHash -Path `"$TargetPath`" -Algorithm SHA256; Get-AuthenticodeSignature -FilePath `"$TargetPath`""
        Command_PS7     = "Get-FileHash -Path `"$TargetPath`" -Algorithm SHA256; Get-AuthenticodeSignature -FilePath `"$TargetPath`""
    }
    $outDir = Split-Path -Path $OutputPath -Parent
    if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    $errPayload | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Output ($errPayload | ConvertTo-Json -Depth 5)
    exit 0
}

# Build external Threat Intelligence URLs (Privacy-First: Hash-Only Lookup)
$vtGuiUrl        = "https://www.virustotal.com/gui/file/$cleanSha256"
$vtSearchUrl     = "https://www.virustotal.com/gui/search/$cleanSha256"
$hybridUrl       = "https://www.hybrid-analysis.com/search?query=$cleanSha256"
$msSecIntelUrl   = "https://www.microsoft.com/en-us/wdsi/filesubmission"
$lolbasUrl       = "https://lolbas-project.github.io/"

# Optional VirusTotal v3 REST API lookup if VT_API_KEY or Config\vt_config.json is present
$vtApiKey = $env:VT_API_KEY
$vtConfigPath = Join-Path $baseDir "Config\vt_config.json"
if ([string]::IsNullOrWhiteSpace($vtApiKey) -and (Test-Path $vtConfigPath)) {
    try {
        $vtCfg = Get-Content $vtConfigPath -Raw | ConvertFrom-Json
        if ($vtCfg.VirusTotalApiKey) { $vtApiKey = [string]$vtCfg.VirusTotalApiKey }
    } catch {}
}

$vtApiQueried = $false
$vtApiStatus = "HashReady_BrowserLookup (No API Key Configured - Click 'Open on VirusTotal' for instant web report)"
$vtMaliciousCount = $null
$vtSuspiciousCount = $null
$vtHarmlessCount = $null
$vtUndetectedCount = $null
$vtTotalEngines = $null
$vtReputation = $null
$vtMeaningfulName = $null
$vtThreatLabel = "Pending Web Lookup"

if (-not [string]::IsNullOrWhiteSpace($vtApiKey) -and $vtApiKey.Length -ge 32) {
    $vtApiQueried = $true
    try {
        $headers = @{ "x-apikey" = $vtApiKey.Trim(); "Accept" = "application/json" }
        $apiUrl = "https://www.virustotal.com/api/v3/files/$cleanSha256"
        if ($psMajor -le 5) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $vtResp = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get -TimeoutSec 8 -UseBasicParsing -ErrorAction Stop
        } else {
            $vtResp = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get -TimeoutSec 8 -ErrorAction Stop
        }
        if ($vtResp -and $vtResp.data -and $vtResp.data.attributes) {
            $attr = $vtResp.data.attributes
            $stats = $attr.last_analysis_stats
            if ($stats) {
                $vtMaliciousCount  = [int]$stats.malicious
                $vtSuspiciousCount = [int]$stats.suspicious
                $vtHarmlessCount   = [int]$stats.harmless
                $vtUndetectedCount = [int]$stats.undetected
                $vtTotalEngines    = $vtMaliciousCount + $vtSuspiciousCount + $vtHarmlessCount + $vtUndetectedCount
            }
            $vtReputation     = $attr.reputation
            $vtMeaningfulName = $attr.meaningful_name
            if ($attr.popular_threat_classification -and $attr.popular_threat_classification.suggested_threat_label) {
                $vtThreatLabel = [string]$attr.popular_threat_classification.suggested_threat_label
            } elseif ($vtMaliciousCount -eq 0) {
                $vtThreatLabel = "Clean (0 Malicious Detections)"
            } else {
                $vtThreatLabel = "$vtMaliciousCount / $vtTotalEngines Engines Flagged"
            }
            $vtApiStatus = "API_Verified ($vtMaliciousCount / $vtTotalEngines malicious)"
        }
    } catch {
        $httpCode = $null
        try { $httpCode = [int]$_.Exception.Response.StatusCode } catch {}
        if ($httpCode -eq 404) {
            $vtApiStatus = "HashNotFoundInVT (Unknown / Never Uploaded to VirusTotal)"
            $vtThreatLabel = "Unseen Hash on VirusTotal"
        } else {
            $vtApiStatus = "API_Error ($($_.Exception.Message)) - Use Direct Browser Link"
        }
    }
}

$displayTarget = if ($resolvedFile) { $resolvedFile } elseif ($TargetPath) { $TargetPath } else { "SHA256:$cleanSha256" }

$explanation = if ($sigStatus -eq "Valid") {
    "Binary '$displayTarget' (SHA-256: $cleanSha256) carries a valid Authenticode digital signature ($sigPublisher). Hash-only VirusTotal lookup preserves operational security by querying reputation without uploading local binaries."
} else {
    "Binary '$displayTarget' (SHA-256: $cleanSha256) has Authenticode status '$sigStatus'. Verify this SHA-256 hash on VirusTotal and Hybrid-Analysis before trusting the binary."
}

$recommendedFix = "Click 'Open on VirusTotal.com' to inspect multi-engine AV detections for SHA-256 $cleanSha256. To enable automatic API v3 queries inside this dashboard, set environment variable VT_API_KEY or save {'VirusTotalApiKey': 'YOUR_KEY'} in Config\vt_config.json."

$cmdPS51 = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Get-FileHash -Path `"$displayTarget`" -Algorithm SHA256; Start-Process `"$vtGuiUrl`""
$cmdPS7  = "Get-FileHash -Path `"$displayTarget`" -Algorithm SHA256; Start-Process `"$vtGuiUrl`""

$result = [PSCustomObject]@{
    ScriptId               = "INT-03"
    ScriptName             = "Invoke-VirusTotalLookup.ps1"
    Status                 = "Success"
    CheckedAtLocal         = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
    CheckedAtUtc           = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    EntityName             = if ($EntityName) { $EntityName } else { Split-Path $displayTarget -Leaf }
    TargetPathInput        = $TargetPath
    ResolvedFilePath       = if ($resolvedFile) { $resolvedFile } else { "Hash-Only Lookup" }
    FileSize_Bytes         = $fileSize
    SHA256                 = $cleanSha256
    SHA1                   = $sha1Hash
    MD5                    = $md5Hash
    SignatureStatus        = $sigStatus
    Publisher              = $sigPublisher
    CertificateThumbprint  = $sigThumbprint
    IsOSBinary             = $isOSBinary
    FileVersion            = $fileVersion
    ProductName            = $productName
    CompanyName            = $companyName
    OriginalFilename       = $originalFileName
    FileDescription        = $fileDescription
    VirusTotal_GUI_URL     = $vtGuiUrl
    VirusTotal_Search_URL  = $vtSearchUrl
    HybridAnalysis_URL     = $hybridUrl
    MicrosoftSubmit_URL    = $msSecIntelUrl
    LOLBAS_Reference_URL   = $lolbasUrl
    VT_API_Queried         = $vtApiQueried
    VT_API_Status          = $vtApiStatus
    VT_ThreatLabel         = $vtThreatLabel
    VT_MaliciousDetections = $vtMaliciousCount
    VT_SuspiciousDetections= $vtSuspiciousCount
    VT_HarmlessCount       = $vtHarmlessCount
    VT_UndetectedCount     = $vtUndetectedCount
    VT_TotalEngines        = $vtTotalEngines
    VT_ReputationScore     = $vtReputation
    Explanation            = $explanation
    RecommendedFix         = $recommendedFix
    Command_PS51           = $cmdPS51
    Command_PS7            = $cmdPS7
}

$outDir = Split-Path -Path $OutputPath -Parent
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$result | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8

# Append to lookup history cache (keep latest 50 lookups)
$historyPath = Join-Path $outDir "virustotal_lookup_history.json"
$historyList = @()
if (Test-Path $historyPath) {
    try {
        $existing = Get-Content $historyPath -Raw | ConvertFrom-Json
        if ($existing) { $historyList = @($existing | Where-Object { $_.SHA256 -ne $cleanSha256 }) }
    } catch {}
}
$historyList = @($result) + $historyList | Select-Object -First 50
$historyList | ConvertTo-Json -Depth 5 | Set-Content -Path $historyPath -Encoding UTF8

Write-Output ($result | ConvertTo-Json -Depth 5)
