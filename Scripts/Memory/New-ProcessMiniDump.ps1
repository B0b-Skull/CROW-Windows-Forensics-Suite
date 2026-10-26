<#
.SYNOPSIS
    Authorized On-Demand Process MiniDump Acquisition Script (MEM-02)
.DESCRIPTION
    Creates a user-mode minidump of a specified running Process ID (PID) into
    Evidence\MemoryDumps\ using native Windows MiniDumpWriteDump, and records
    a chain-of-custody SHA-256 manifest entry.
    Requires explicit target PID parameter. Never runs automatically.
#>
param(
    [Parameter(Mandatory=$true)]
    [int]$TargetPID,
    [string]$Reason = "Manual Forensic Triage via Dashboard"
)

$ErrorActionPreference = 'Stop'
$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$proc = Get-Process -Id $TargetPID -ErrorAction SilentlyContinue
if (!$proc) {
    $err = [PSCustomObject]@{
        ScriptId = "MEM-02"
        Status   = "Error"
        Message  = "Process ID $TargetPID was not found or has already exited."
    }
    $err | ConvertTo-Json
    exit 1
}

$dumpDir = Join-Path $baseDir "Evidence\MemoryDumps"
if (!(Test-Path $dumpDir)) { New-Item -ItemType Directory -Path $dumpDir -Force | Out-Null }

$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$safeName = ($proc.ProcessName -replace '[^a-zA-Z0-9_\-]', '_')
$dumpFile = Join-Path $dumpDir "${safeName}_PID${TargetPID}_${ts}.dmp"

# Use .NET P/Invoke MiniDumpWriteDump (DbgHelp.dll) so standard user can dump own processes without requiring elevated rundll32 comsvcs
$pinvokeCode = @"
using System;
using System.Runtime.InteropServices;
using System.IO;

public static class NativeMiniDumper {
    [DllImport("dbghelp.dll", SetLastError = true)]
    public static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        uint ProcessId,
        SafeHandle hFile,
        uint DumpType,
        IntPtr ExceptionParam,
        IntPtr UserStreamParam,
        IntPtr CallbackParam
    );
}
"@
Add-Type -TypeDefinition $pinvokeCode -ErrorAction SilentlyContinue

$fs = $null
$success = $false
try {
    $fs = [System.IO.File]::Create($dumpFile)
    # MiniDumpWithFullMemoryInfo (0x00000800) | MiniDumpWithHandleData (0x00000004) | MiniDumpWithUnloadedModules (0x00000020) = 0x824
    $success = [NativeMiniDumper]::MiniDumpWriteDump($proc.Handle, [uint32]$TargetPID, $fs.SafeFileHandle, 0x00000824, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
} catch {
    $success = $false
} finally {
    if ($null -ne $fs) {
        try { $fs.Close(); $fs.Dispose() } catch {}
    }
}

if (!$success -or !(Test-Path $dumpFile) -or (Get-Item $dumpFile).Length -eq 0) {
    if (Test-Path $dumpFile) { Remove-Item $dumpFile -Force -ErrorAction SilentlyContinue }
    $err = [PSCustomObject]@{
        ScriptId       = "MEM-02"
        Status         = "Error"
        Message        = "MiniDumpWriteDump failed for PID $TargetPID ($($proc.ProcessName)). Target process may require Administrator elevation or Protected Process Light (PPL) access."
        Explanation    = "Windows blocked reading virtual memory of PID $TargetPID ($($proc.ProcessName)) because it runs in an elevated Administrator session, SYSTEM token, or Protected Process Light (PPL) boundary."
        RecommendedFix = "Run Start-Dashboard.cmd as Administrator (Right-click -> Run as administrator) to capture minidumps of elevated/SYSTEM processes."
    }
    $err | ConvertTo-Json
    exit 1
}

$item = Get-Item $dumpFile
$hash = (Get-FileHash -LiteralPath $dumpFile -Algorithm SHA256).Hash
$custodyRecord = [PSCustomObject]@{
    ScriptId          = "MEM-02"
    Status            = "Success"
    CapturedAtLocal   = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
    CapturedAtUtc     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    CollectedByUser   = "$env:USERDOMAIN\$env:USERNAME"
    HostName          = $env:COMPUTERNAME
    TargetPID         = $TargetPID
    ProcessName       = $proc.ProcessName
    DumpFilePath      = $dumpFile
    Size_KB           = [math]::Round($item.Length / 1KB, 2)
    SHA256            = $hash
    Reason            = $Reason
}

$manifestLog = Join-Path $dumpDir "chain_of_custody_manifest.jsonl"
($custodyRecord | ConvertTo-Json -Compress) | Add-Content -Path $manifestLog -Encoding UTF8
$custodyRecord | ConvertTo-Json -Depth 4
