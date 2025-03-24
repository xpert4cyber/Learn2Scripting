@echo off
setlocal enabledelayedexpansion

:: Define the log storage location
set "LOG_DIR=%USERPROFILE%\Desktop\Telnet_Logs"

:: Check if Telnet Server is installed
dism /online /Get-Features | findstr /i "TelnetServer" >nul
if %errorlevel% neq 0 (
    echo [!] Telnet Server is not installed on this system.
    pause
    exit /b
)

echo [*] Extracting Telnet Server logs...

:: Create a folder to store logs
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

:: Copy logs from different locations
if exist "C:\Windows\System32\LogFiles\TelnetServer" (
    xcopy /E /I /Y "C:\Windows\System32\LogFiles\TelnetServer" "%LOG_DIR%\System32_TelnetLogs"
)

if exist "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Telnet%4Admin.evtx" (
    copy "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Telnet%4Admin.evtx" "%LOG_DIR%\Telnet_Admin.evtx"
)

if exist "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Telnet%4Operational.evtx" (
    copy "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Telnet%4Operational.evtx" "%LOG_DIR%\Telnet_Operational.evtx"
)

:: Export logs from Event Viewer
wevtutil qe Microsoft-Windows-Telnet/Admin /f:text > "%LOG_DIR%\Telnet_Admin.txt"
wevtutil qe Microsoft-Windows-Telnet/Operational /f:text > "%LOG_DIR%\Telnet_Operational.txt"

echo [✔] Logs extracted successfully and stored in: %LOG_DIR%
pause
exit
