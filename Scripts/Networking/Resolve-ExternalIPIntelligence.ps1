<#
.SYNOPSIS
    Public IP WHOIS/RDAP, ASN, Geolocation & Reverse DNS Enrichment Script (NET-02)
.DESCRIPTION
    Enriches public IPv4/IPv6 addresses with Reverse DNS (PTR), ASN, Organization,
    Country, and RDAP/WHOIS metadata. Strictly skips private/RFC1918/internal IPs.
    Caches results in Data\Cache\ip_intel_cache.json to prevent redundant external queries.
#>
param(
    [string[]]$IPAddresses = @(),
    [string]$CachePath = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($CachePath)) { $CachePath = Join-Path $baseDir "Data\Cache\ip_intel_cache.json" }

function Test-IsPrivateIP([string]$ip) {
    if ([string]::IsNullOrWhiteSpace($ip)) { return $true }
    if ($ip -in @('0.0.0.0', '::', '127.0.0.1', '::1', '*')) { return $true }
    if ($ip -match '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.)') { return $true }
    if ($ip -match '^(fe80:|fc00:|fd00:|ff00:)') { return $true }
    return $false
}

# If no IPs passed, gather active public IPs from current TCP connections
if ($IPAddresses.Count -eq 0) {
    $IPAddresses = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty RemoteAddress -Unique |
        Where-Object { !(Test-IsPrivateIP $_) }
}

$cacheObj = @{}
if (Test-Path $CachePath) {
    try {
        $loaded = Get-Content $CachePath -Raw | ConvertFrom-Json
        foreach ($p in $loaded.PSObject.Properties) {
            $cacheObj[$p.Name] = $p.Value
        }
    } catch {}
}

$psMajor = [int]$PSVersionTable.PSVersion.Major
if ($psMajor -le 5) {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
}

function Invoke-VersionSafeRestMethod([string]$Uri, [int]$TimeoutSec = 2) {
    if ($script:psMajor -ge 6) {
        return (Invoke-RestMethod -Uri $Uri -TimeoutSec $TimeoutSec -ErrorAction Stop)
    } else {
        return (Invoke-RestMethod -Uri $Uri -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop)
    }
}

$enrichedResults = @()
$newLookupsCount = 0
foreach ($ip in ($IPAddresses | Select-Object -Unique)) {
    if (Test-IsPrivateIP $ip) { continue }

    if ($cacheObj.ContainsKey($ip) -and $cacheObj[$ip].Country -and $cacheObj[$ip].Country -ne "Unknown") {
        $enrichedResults += $cacheObj[$ip]
        continue
    }

    if ($newLookupsCount -ge 15) { continue }
    $newLookupsCount++

    # 1. Fast Reverse DNS (PTR) with 750ms async timeout
    $ptr = "No PTR Record"
    try {
        $task = [System.Net.Dns]::GetHostEntryAsync($ip)
        if ($task.Wait(750) -and $task.Result -and $task.Result.HostName) {
            $ptr = $task.Result.HostName
        }
    } catch {}

    # 2. Query ipwho.is (HTTPS JSON - 2s timeout)
    $country = "Unknown"
    $countryCode = "--"
    $region = ""
    $city = ""
    $asn = "Unknown"
    $org = "Unknown"
    $source = "LocalDNS"

    try {
        $resp = Invoke-VersionSafeRestMethod -Uri "https://ipwho.is/$ip" -TimeoutSec 2
        if ($resp -and $resp.success -eq $true) {
            $country     = if ($resp.country) { "$($resp.country) ($($resp.country_code))" } else { "Unknown" }
            $countryCode = $resp.country_code
            $region      = $resp.region
            $city        = $resp.city
            $asn         = if ($resp.connection -and $resp.connection.asn) { "AS$($resp.connection.asn)" } else { "N/A" }
            $org         = if ($resp.connection -and $resp.connection.org) { $resp.connection.org } elseif ($resp.connection.isp) { $resp.connection.isp } else { "Unknown" }
            $source      = "WHOIS/IPWhois"
        }
    } catch {}

    if ($org -eq "Unknown") {
        try {
            $rdap = Invoke-VersionSafeRestMethod -Uri "https://rdap.arin.net/registry/ip/$ip" -TimeoutSec 2
            if ($rdap) {
                $org = if ($rdap.name) { $rdap.name } else { "RDAP Registered Block" }
                $country = if ($rdap.country) { $rdap.country } else { $country }
                $source = "ARIN-RDAP"
            }
        } catch {}
    }

    $record = [PSCustomObject]@{
        IPAddress    = $ip
        ReverseDNS   = $ptr
        ASN          = $asn
        Organization = "$asn $org".Trim()
        Country      = $country
        CountryCode  = $countryCode
        CityRegion   = "$city, $region".Trim(", ")
        LookupSource = $source
        QueriedAtUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    $cacheObj[$ip] = $record
    $enrichedResults += $record
}

$outDir = Split-Path -Path $CachePath -Parent
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$cacheObj | ConvertTo-Json -Depth 5 | Set-Content -Path $CachePath -Encoding UTF8
Write-Output "Enriched $($enrichedResults.Count) public IP addresses."
