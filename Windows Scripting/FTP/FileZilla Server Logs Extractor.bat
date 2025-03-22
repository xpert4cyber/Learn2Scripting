@echo off
setlocal enabledelayedexpansion

:: Ensure Administrator Privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Please run this script as Administrator!
    pause
    exit /b
)

:: Set log storage location on Desktop
set logFolder=%USERPROFILE%\Desktop\FileZilla_Server_Logs
mkdir "%logFolder%"

:: Detect FileZilla Server Installation Path
set "filezillaPath=C:\Program Files\FileZilla Server\Logs"
if not exist "%filezillaPath%" set "filezillaPath=C:\Program Files (x86)\FileZilla Server\Logs"

:: Copy FileZilla log files
if exist "%filezillaPath%" (
    echo [✔] Copying FileZilla logs from %filezillaPath%...
    xcopy "%filezillaPath%\*" "%logFolder%" /s /y >nul
) else (
    echo [✖] FileZilla Server log folder not found!
)

:: Extract FileZilla logs from Windows Event Viewer
echo [✔] Extracting FileZilla logs from Event Viewer...
wevtutil qe Application /q:"*[System[Provider[@Name='FileZilla Server']]]" /f:text > "%logFolder%\FileZilla_Event_Logs.txt"

echo [✔] All FileZilla logs have been saved to: %logFolder%
pause
