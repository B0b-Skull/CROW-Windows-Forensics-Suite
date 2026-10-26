@echo off
setlocal
title CROW INNOVATIONS Windows System Analysis ^& Forensics Suite (localhost:8765)
cd /d "%~dp0"

echo ============================================================================
echo   CROW INNOVATIONS Windows System Analysis ^& Forensics Suite
echo   Starting Controlled Localhost Script ^& Live Telemetry Backend (127.0.0.1:8765)
echo ============================================================================
echo.

set "PY_CMD="
where python >nul 2>&1
if %errorlevel% equ 0 (
    set "PY_CMD=python"
) else (
    where py >nul 2>&1
    if %errorlevel% equ 0 (
        set "PY_CMD=py -3"
    ) else (
        for /d %%D in ("C:\Program Files\Python3*" "%LOCALAPPDATA%\Programs\Python\Python3*") do (
            if exist "%%~fD\python.exe" set "PY_CMD=%%~fD\python.exe"
        )
    )
)

if defined PY_CMD (
    start "" "http://127.0.0.1:8765/index.html"
    "%PY_CMD%" "%~dp0Dashboard\Backend\server.py" --host 127.0.0.1 --port 8765
) else (
    echo [NOTICE] Python 3 was not found on PATH.
    echo [LIVE MODE] Launching Dashboard with 100%% Native PowerShell Live Telemetry Streamer ^(Zero External Dependencies^)...
    echo Keep this window open to stream real-time CPU, RAM, GPU ^& VRAM metrics every 3 seconds to the browser.
    start "" "%~dp0index.html"
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Scripts\Performance\Start-LiveTelemetryStream.ps1" -IntervalSeconds 3 -MaxSamples 999999
)
pause
