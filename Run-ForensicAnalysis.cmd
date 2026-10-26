@echo off
setlocal
title CROW INNOVATIONS Windows System Analysis ^& Forensics Suite - Full Scan ^& Launch
cd /d "%~dp0"

echo ============================================================================
echo   CROW INNOVATIONS Windows System Analysis ^& Forensics Suite
echo   Automated Environment Initialization ^& Full Forensic System Scan
echo ============================================================================
echo.

REM Check for Administrator privileges; request UAC elevation if not already elevated
net session >nul 2>&1
if %errorlevel% neq 0 (
    if "%1" neq "ELEVATED_ATTEMPT" (
        echo [INFO] Requesting Administrator privileges for full kernel/event/security visibility...
        powershell -NoProfile -Command "try { Start-Process -FilePath '%~f0' -ArgumentList 'ELEVATED_ATTEMPT' -WorkingDirectory '%~dp0' -Verb RunAs -ErrorAction Stop } catch { exit 1 }"
        if %errorlevel% equ 0 exit /b
        echo [NOTICE] Continuing in Standard User mode ^(some Security Event Logs ^& Kernel Dumps may be restricted^)...
    )
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-And-Scan.ps1"
pause
