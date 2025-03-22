@echo off
setlocal enabledelayedexpansion

:: Ensure Administrator Privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Please run this script as Administrator!
    pause
    exit /b
)

:: Detect FileZilla Server Installation Path
set "filezillaPath=C:\Program Files\FileZilla Server\Logs"
if not exist "%filezillaPath%" set "filezillaPath=C:\Program Files (x86)\FileZilla Server\Logs"

:: Delete all FileZilla log files
if exist "%filezillaPath%" (
    echo [✔] Deleting FileZilla Server logs...
    del /q /s "%filezillaPath%\*"
    echo [✔] FileZilla log files deleted!
) else (
    echo [✖] FileZilla Server log folder not found!
)

:: Clear FileZilla logs from Windows Event Viewer
echo [✔] Clearing FileZilla logs from Event Viewer...
wevtutil cl Application /q:"*[System[Provider[@Name='FileZilla Server']]]"

echo [✔] FileZilla logs have been deleted successfully!
pause
