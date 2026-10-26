<#
.SYNOPSIS
    Unified Entity Correlation Engine Script (CORR-01)
.DESCRIPTION
    Connects Processes (with PID + CreationTimestamp stable EntityId), Parent Processes (PPID),
    Binaries (SHA-256 + Authenticode Signature), Windows Services, Registry Persistence Keys,
    and Active TCP/UDP Network Endpoints (with IP Intelligence) into a normalized dataset.
    Calculates explainable, deterministic Threat Assessment and Risk Assessment classifications
    per Section 6 and Section 13. Read-only.
#>
param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $baseDir "Data\Inventory\correlated_entities_latest.json" }
$nowLocal = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
$nowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Ensure prerequisite inventories exist or run them if missing
$procPath = "$baseDir\Data\Inventory\process_inventory_latest.json"
$svcPath  = "$baseDir\Data\Inventory\service_inventory_latest.json"
$regPath  = "$baseDir\Data\Inventory\registry_persistence_latest.json"
$netPath  = "$baseDir\Data\Inventory\network_forensics_latest.json"

if (!(Test-Path $procPath)) { & "$baseDir\Scripts\Processes\Get-ProcessInventory.ps1" -OutputPath $procPath | Out-Null }
if (!(Test-Path $svcPath))  { & "$baseDir\Scripts\Services\Get-ServiceInventory.ps1" -OutputPath $svcPath | Out-Null }
if (!(Test-Path $regPath))  { & "$baseDir\Scripts\Registry\Get-RegistryPersistence.ps1" -OutputPath $regPath | Out-Null }
if (!(Test-Path $netPath))  { & "$baseDir\Scripts\Networking\Get-NetworkForensics.ps1" -OutputPath $netPath | Out-Null }

$procData = Get-Content $procPath -Raw | ConvertFrom-Json
$svcData  = Get-Content $svcPath -Raw | ConvertFrom-Json
$regData  = Get-Content $regPath -Raw | ConvertFrom-Json
$netData  = Get-Content $netPath -Raw | ConvertFrom-Json

# Map User/Owner via Get-Process -IncludeUserName where accessible, or WMI/Current User fallback
$currentUser = "$env:USERDOMAIN\$env:USERNAME"
$currentSid  = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value

# Build lookup dictionaries
# 1. Services by PID and by BinaryPath
$svcByPid = @{}
$svcByExe = @{}
foreach ($s in $svcData.Services) {
    $p = [int]$s.ProcessId
    if ($p -gt 0) {
        if (!$svcByPid.ContainsKey($p)) { $svcByPid[$p] = @() }
        $svcByPid[$p] += "$($s.Name) ($($s.State)/$($s.StartMode))"
    }
    if ($s.ExecutablePath) {
        $eLow = $s.ExecutablePath.ToLower()
        if (!$svcByExe.ContainsKey($eLow)) { $svcByExe[$eLow] = @() }
        $svcByExe[$eLow] += $s.Name
    }
}

# 2. Registry Entries by TargetBinary or ProcessName
$regEntries = @($regData.Entries)

# 3. Network Endpoints by PID
$netByPid = @{}
foreach ($tc in $netData.TCPConnections) {
    $p = [int]$tc.PID
    if (!$netByPid.ContainsKey($p)) { $netByPid[$p] = @() }
    $epStr = if ($tc.State -eq "Listen") {
        "LISTEN TCP $($tc.LocalAddress):$($tc.LocalPort)"
    } else {
        "$($tc.State) TCP -> $($tc.RemoteAddress):$($tc.RemotePort) [$($tc.Country) | $($tc.ASN_Organization) | Dur: $($tc.ConnectionDuration)]"
    }
    $netByPid[$p] += $epStr
}
foreach ($ue in $netData.UDPEndpoints) {
    $p = [int]$ue.PID
    if (!$netByPid.ContainsKey($p)) { $netByPid[$p] = @() }
    $netByPid[$p] += "UDP $($ue.LocalAddress):$($ue.LocalPort)"
}

# Correlate every Process
$correlatedEntities = @()
foreach ($proc in $procData.Processes) {
    $pidVal = [int]$proc.PID
    $path   = $proc.BinaryPath
    $pLow   = if ($path) { $path.ToLower() } else { "" }
    $pName  = $proc.ProcessName

    # Services association
    $relServices = @()
    if ($svcByPid.ContainsKey($pidVal)) {
        $relServices += $svcByPid[$pidVal]
    } elseif ($pLow -and $svcByExe.ContainsKey($pLow) -and $pLow -notmatch 'svchost\.exe$') {
        $relServices += ($svcByExe[$pLow] | ForEach-Object { "$_ (Configured)" })
    }
    $svcDisplay = if ($relServices.Count -gt 0) { ($relServices | Select-Object -Unique) -join "; " } else { "None" }

    # Registry association
    $relReg = @()
    foreach ($re in $regEntries) {
        if (($re.TargetBinary -and $pLow -and $re.TargetBinary.ToLower() -eq $pLow) -or
            ($re.ValueData -and $pName -and $re.ValueData -match [ regex ]::Escape($pName))) {
            $relReg += "$($re.Scope): $($re.EntryName) = $($re.ValueData)"
        }
    }
    $regDisplay = if ($relReg.Count -gt 0) { ($relReg | Select-Object -Unique) -join " | " } else { "None" }

    # Network association
    $netList = if ($netByPid.ContainsKey($pidVal)) { $netByPid[$pidVal] | Select-Object -Unique } else { @() }
    $netDisplay = if ($netList.Count -gt 0) { ($netList | Select-Object -First 6) -join " ; " } else { "None" }

    # User / SID heuristic when non-elevated
    $userSid = if ($pidVal -in @(0, 4) -or $pLow -match '^c:\\windows\\system32\\(services|lsass|wininit|smss|csrss)\.exe$') {
        "NT AUTHORITY\SYSTEM (S-1-5-18)"
    } elseif ($svcDisplay -ne "None" -and $pLow -match 'svchost\.exe$') {
        "Service Account / SYSTEM"
    } else {
        "$currentUser ($currentSid)"
    }

    # Deterministic Threat Assessment & Risk Assessment (Section 13)
    $threat = "Informational"
    $risk   = "Low"
    $reasons = @()

    if ($proc.AnomalyFlags -and $proc.AnomalyFlags.Count -gt 0) {
        foreach ($af in $proc.AnomalyFlags) { $reasons += $af }
    }

    if ($pLow -match '\\appdata\\local\\temp\\|\\windows\\temp\\|\\users\\public\\') {
        $threat = "Medium"
        $risk   = "Medium"
        $reasons += "Executing from Temp/Public folder"
    }

    if ($proc.SignatureStatus -eq "NotSigned") {
        if ($netList.Count -gt 0 -and $relReg.Count -gt 0) {
            $threat = "Medium"
            $risk   = "Medium"
            $reasons += "Unsigned executable with both network activity and registry persistence"
        } else {
            if ($threat -eq "Informational") { $threat = "Low" }
            $reasons += "Unsigned binary (not inherently malicious)"
        }
    } elseif ($proc.SignatureStatus -notin @("Valid", "KernelTrusted", "VerificationUnavailable")) {
        $threat = "High"
        $risk   = "High"
        $reasons += "Invalid Authenticode signature ($($proc.SignatureStatus))"
    }

    if ($pName -match 'rustdesk') {
        if ($threat -eq "Informational") { $threat = "Low" }
        $risk = "Medium"
        $reasons += "Remote desktop control software active"
    }

    if ($proc.WorkingSet_MB -gt 1000) {
        if ($risk -eq "Low") { $risk = "Medium" }
        $reasons += "High memory footprint ($($proc.WorkingSet_MB) MB)"
    }

    if ($reasons.Count -eq 0) {
        $reasons += "Verified signature and expected execution parameters"
    }

    $correlatedEntities += [PSCustomObject]@{
        EntityId          = $proc.EntityId
        ProcessName       = $pName
        PID               = $pidVal
        PPID              = $proc.PPID
        ParentProcess     = $proc.ParentDisplay
        IsOrphaned        = $proc.IsOrphanedProcess
        BinaryPath        = $path
        CommandLine       = $proc.CommandLine
        UserAndSID        = $userSid
        StartTime         = $proc.StartTime
        CPU_Seconds       = $proc.CPU_Seconds
        WorkingSet_MB     = $proc.WorkingSet_MB
        PrivateBytes_MB   = $proc.PrivateBytes_MB
        GPU_Dedicated_MB  = $proc.GPU_Dedicated_MB
        ResourceSummary   = "RAM: $($proc.WorkingSet_MB) MB | CPU: $($proc.CPU_Seconds)s | GPU: $($proc.GPU_Dedicated_MB) MB"
        SignatureStatus   = $proc.SignatureStatus
        Publisher         = $proc.CompanyName
        SHA256            = $proc.SHA256
        Services          = $svcDisplay
        ServiceCount      = $relServices.Count
        Registry          = $regDisplay
        RegistryCount     = $relReg.Count
        Network           = $netDisplay
        NetworkCount      = $netList.Count
        ThreatAssessment  = $threat
        RiskAssessment    = $risk
        AssessmentEvidence= ($reasons -join "; ")
    }
}

$output = [PSCustomObject]@{
    ScriptId          = "CORR-01"
    ScriptName        = "Invoke-EntityCorrelation.ps1"
    CollectedAtLocal  = $nowLocal
    CollectedAtUtc    = $nowUtc
    Summary           = [PSCustomObject]@{
        TotalCorrelatedProcesses = $correlatedEntities.Count
        WithActiveServices       = @($correlatedEntities | Where-Object { $_.ServiceCount -gt 0 }).Count
        WithRegistryPersistence  = @($correlatedEntities | Where-Object { $_.RegistryCount -gt 0 }).Count
        WithNetworkEndpoints     = @($correlatedEntities | Where-Object { $_.NetworkCount -gt 0 }).Count
        ElevatedThreatCount      = @($correlatedEntities | Where-Object { $_.ThreatAssessment -in @('Critical','High','Medium') }).Count
    }
    Entities          = $correlatedEntities
}

$outDir = Split-Path -Path $OutputPath -Parent
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$output | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Output "Entity correlation completed: $($correlatedEntities.Count) unified process entities written to $OutputPath"
