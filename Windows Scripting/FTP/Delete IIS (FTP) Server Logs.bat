@echo off
setlocal enabledelayedexpansion

:: Check for Administrator Privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Please run this script as Administrator!
    pause
    exit /b
)

:: Confirm deletion
echo WARNING: This will delete all FTP logs from IIS Server permanently!
set /p confirm="Are you sure? (Y/N): "
if /I not "%confirm%"=="Y" (
    echo Operation canceled.
    exit /b
)

:: Check if IIS FTP Service is installed
sc query ftpsvc >nul 2>&1
if %errorlevel% neq 0 (
    echo [✖] IIS FTP Server NOT detected.
    pause
    exit /b
)

:: Define log path
set logPath=C:\inetpub\logs\LogFiles

:: Delete IIS FTP log files
if exist "%logPath%\FTPSVC*" (
    echo [✔] Deleting FTP logs from %logPath%...
    del /q /s "%logPath%\FTPSVC*"
    echo [✔] IIS FTP logs deleted successfully!
) else (
    echo [✖] No IIS FTP logs found in %logPath%.
)

:: Clear FTP-related Windows Event Logs
echo [✔] Clearing IIS FTP logs from Windows Event Viewer...
wevtutil cl "Microsoft-Windows-IIS-FTP-Service/Operational" >nul 2>&1
wevtutil cl Security >nul 2>&1

echo [✔] All FTP logs have been deleted successfully!
pause
