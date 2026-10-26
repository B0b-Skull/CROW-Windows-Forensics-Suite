<#
.SYNOPSIS
    Network Forensics & Endpoint Correlation Script (NET-01)
.DESCRIPTION
    Collects all active TCP connections, listening TCP/UDP sockets, owning PIDs,
    executable paths, associated Windows services, DNS client cache, firewall profile
    status, and interface byte counters.
    Calculates connection duration ONLY when a valid OS socket creation timestamp
    (> LastBootUpTime) is exposed by MSFT_NetTCPConnection; otherwise reports
    "Unknown (Snapshot Only)" per forensic accuracy standards. Read-only.
#>
param(
    [switch]$ResolveIPIntel = $true,
    [string]$OutputPath = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $baseDir "Data\Inventory\network_forensics_latest.json" }
$now = Get-Date
$nowLocal = $now.ToString("yyyy-MM-ddTHH:mm:sszzz")
$nowUtc = $now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$bootTime = if ($os -and $os.LastBootUpTime) { [DateTime]$os.LastBootUpTime } else { $now.AddDays(-30) }

# 1. Process & Service Lookup Maps
$procMap = @{}
Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
    $procMap[[int]$_.ProcessId] = @{
        Name = $_.Name
        Path = $_.ExecutablePath
        Cmd  = $_.CommandLine
    }
}

$svcByPid = @{}
Get-CimInstance -ClassName Win32_Service -Filter "ProcessId > 0" -ErrorAction SilentlyContinue | ForEach-Object {
    $p = [int]$_.ProcessId
    if (!$svcByPid.ContainsKey($p)) { $svcByPid[$p] = @() }
    $svcByPid[$p] += $_.Name
}

function Test-IsPrivateOrReservedIP([string]$ip) {
    if ([string]::IsNullOrWhiteSpace($ip)) { return $true }
    if ($ip -in @('0.0.0.0', '::', '127.0.0.1', '::1', '*')) { return $true }
    if ($ip -match '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.)') { return $true }
    if ($ip -match '^(fe80:|fc00:|fd00:|ff00:)') { return $true }
    return $false
}

# 2. Load or Refresh IP Intelligence Cache
$ipCachePath = Join-Path $baseDir "Data\Cache\ip_intel_cache.json"
$ipCache = @{}
if (Test-Path $ipCachePath) {
    try {
        $rawCache = Get-Content $ipCachePath -Raw | ConvertFrom-Json
        foreach ($prop in $rawCache.PSObject.Properties) {
            $ipCache[$prop.Name] = $prop.Value
        }
    } catch {}
}

# 3. Collect TCP Connections
$tcpConns = Get-NetTCPConnection -ErrorAction SilentlyContinue
$publicIpsToResolve = @()

foreach ($tc in $tcpConns) {
    $remIp = $tc.RemoteAddress
    if (!(Test-IsPrivateOrReservedIP $remIp) -and ($remIp -notin $publicIpsToResolve)) {
        $publicIpsToResolve += $remIp
    }
}

# Run IP Intelligence enrichment script if requested and public IPs exist
if ($ResolveIPIntel -and $publicIpsToResolve.Count -gt 0) {
    $intelScript = Join-Path $baseDir "Scripts\Networking\Resolve-ExternalIPIntelligence.ps1"
    if (Test-Path $intelScript) {
        & $intelScript -IPAddresses $publicIpsToResolve | Out-Null
        if (Test-Path $ipCachePath) {
            try {
                $rawCache = Get-Content $ipCachePath -Raw | ConvertFrom-Json
                foreach ($prop in $rawCache.PSObject.Properties) {
                    $ipCache[$prop.Name] = $prop.Value
                }
            } catch {}
        }
    }
}

$tcpRecords = @()
foreach ($tc in $tcpConns) {
    $pidVal = [int]$tc.OwningProcess
    $pInfo  = if ($procMap.ContainsKey($pidVal)) { $procMap[$pidVal] } else { @{ Name = if ($pidVal -eq 4) { "System" } elseif ($pidVal -eq 0) { "Idle" } else { "PID-$pidVal" }; Path = ""; Cmd = "" } }
    $svcs   = if ($svcByPid.ContainsKey($pidVal)) { ($svcByPid[$pidVal] -join ", ") } else { "None" }

    # Connection Duration Validation (Section 8)
    $connStartStr = "Unknown"
    $durationStr  = "Unknown"
    if ($tc.CreationTime) {
        $ct = [DateTime]$tc.CreationTime
        if ($ct -ge $bootTime -and $ct -le $now.AddMinutes(5) -and $ct.Year -gt 2000) {
            $connStartStr = $ct.ToString("yyyy-MM-ddTHH:mm:sszzz")
            $span = $now - $ct
            if ($span.TotalDays -ge 1) {
                $durationStr = "{0}d {1}h {2}m" -f [int]$span.Days, $span.Hours, $span.Minutes
            } elseif ($span.TotalHours -ge 1) {
                $durationStr = "{0}h {1}m {2}s" -f [int]$span.Hours, $span.Minutes, $span.Seconds
            } else {
                $durationStr = "{0}m {1}s" -f [int]$span.Minutes, [int]$span.Seconds
            }
        }
    }

    $remIp = $tc.RemoteAddress
    $isPrivate = Test-IsPrivateOrReservedIP $remIp
    $intel = if (!$isPrivate -and $ipCache.ContainsKey($remIp)) { $ipCache[$remIp] } else { $null }

    $country = if ($isPrivate) { "Local / Private" } elseif ($intel -and $intel.Country) { $intel.Country } else { "Unknown" }
    $asnOrg  = if ($isPrivate) {
        if ($remIp -in @('127.0.0.1', '::1', '0.0.0.0', '::')) { "Loopback / Unspecified" }
        elseif ($remIp -match '^100\.') { "Tailscale / CGNAT Mesh" }
        else { "LAN Private Network (RFC1918)" }
    } elseif ($intel -and $intel.Organization) { $intel.Organization } else { "Unresolved" }
    $ptrHost = if ($isPrivate) { "Internal" } elseif ($intel -and $intel.ReverseDNS) { $intel.ReverseDNS } else { "N/A" }

    # Risk / Exposure Assessment
    $exposureRisk = "Informational"
    if ($tc.State -eq "Listen" -and $tc.LocalAddress -in @("0.0.0.0", "::") -and $pInfo.Name -notmatch '^(System|svchost\.exe|lsass\.exe|wininit\.exe|spoolsv\.exe|services\.exe)$') {
        $exposureRisk = "Medium (Wildcard Listener on Non-OS Process)"
    }

    $tcpRecords += [PSCustomObject]@{
        Protocol            = "TCP"
        State               = [string]$tc.State
        LocalAddress        = $tc.LocalAddress
        LocalPort           = $tc.LocalPort
        RemoteAddress       = $remIp
        RemotePort          = $tc.RemotePort
        IsPublicRemoteIP    = (!$isPrivate)
        PID                 = $pidVal
        ProcessName         = $pInfo.Name
        BinaryPath          = if ($pInfo.Path) { $pInfo.Path } else { "System / Protected" }
        RelatedServices     = $svcs
        ConnectionStartTime = $connStartStr
        ConnectionDuration  = $durationStr
        Country             = $country
        ASN_Organization    = $asnOrg
        ReverseDNS          = $ptrHost
        ExposureRisk        = $exposureRisk
    }
}

# 4. Collect UDP Endpoints
$udpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
$udpRecords = @()
foreach ($ue in $udpEndpoints) {
    $pidVal = [int]$ue.OwningProcess
    $pInfo  = if ($procMap.ContainsKey($pidVal)) { $procMap[$pidVal] } else { @{ Name = if ($pidVal -eq 4) { "System" } else { "PID-$pidVal" }; Path = "" } }
    $svcs   = if ($svcByPid.ContainsKey($pidVal)) { ($svcByPid[$pidVal] -join ", ") } else { "None" }
    $udpRecords += [PSCustomObject]@{
        Protocol            = "UDP"
        State               = "Bound/Listening"
        LocalAddress        = $ue.LocalAddress
        LocalPort           = $ue.LocalPort
        PID                 = $pidVal
        ProcessName         = $pInfo.Name
        BinaryPath          = if ($pInfo.Path) { $pInfo.Path } else { "System / Protected" }
        RelatedServices     = $svcs
        CreationTime        = if ($ue.CreationTime -and ([DateTime]$ue.CreationTime).Year -gt 2000) { ([DateTime]$ue.CreationTime).ToString("yyyy-MM-ddTHH:mm:sszzz") } else { "Unknown" }
    }
}

# 5. Firewall Profiles & DNS Client Cache Sample
$fwProfiles = @()
try {
    Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object {
        $fwProfiles += [PSCustomObject]@{
            Name                  = $_.Name
            Enabled               = [bool]$_.Enabled
            DefaultInboundAction  = [string]$_.DefaultInboundAction
            DefaultOutboundAction = [string]$_.DefaultOutboundAction
        }
    }
} catch {}

$dnsCache = @()
try {
    Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First 60 | ForEach-Object {
        $dnsCache += [PSCustomObject]@{
            Entry      = $_.Entry
            RecordName = $_.Name
            RecordType = [string]$_.Type
            Data       = $_.Data
            TTL_Sec    = $_.TimeToLive
        }
    }
} catch {}

$output = [PSCustomObject]@{
    ScriptId             = "NET-01"
    ScriptName           = "Get-NetworkForensics.ps1"
    CollectedAtLocal     = $nowLocal
    CollectedAtUtc       = $nowUtc
    Summary              = [PSCustomObject]@{
        TotalTCPConnections   = $tcpRecords.Count
        EstablishedTCPCount   = @($tcpRecords | Where-Object { $_.State -eq 'Established' }).Count
        ListeningTCPCount     = @($tcpRecords | Where-Object { $_.State -eq 'Listen' }).Count
        PublicRemoteIPCount   = $publicIpsToResolve.Count
        TotalUDPEndpoints     = $udpRecords.Count
        TelemetryNote         = "Per-process cumulative network byte counters require active ETW session; adapter-level byte totals are collected in HW-01/PERF-01."
    }
    FirewallProfiles     = $fwProfiles
    TCPConnections       = $tcpRecords
    UDPEndpoints         = $udpRecords
    DNSCacheSample       = $dnsCache
}

$outDir = Split-Path -Path $OutputPath -Parent
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$output | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Output "Network forensics written to $OutputPath"
