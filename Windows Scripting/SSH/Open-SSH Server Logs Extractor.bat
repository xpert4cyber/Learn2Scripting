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
set logFolder=%USERPROFILE%\Desktop\SSH_Connection_Logs
mkdir "%logFolder%"

:: Extract SSH logs from Event Viewer
echo [✔] Extracting SSH login attempts...
wevtutil qe Security /q:"*[System[(EventID=4624 or EventID=4625)]] and EventData[Data[@Name='ProcessName'] and contains(Data, 'sshd.exe')]" /f:text > "%logFolder%\SSH_Login_Logs.txt"

:: Extract SSHD logs from filesystem
set sshLogPath=C:\ProgramData\ssh\logs\sshd.log
if exist "%sshLogPath%" (
    echo [✔] Copying SSHD log file...
    copy "%sshLogPath%" "%logFolder%\sshd.log" >nul
) else (
    echo [✖] No SSHD log file found.
)

:: Extract real-time SSH connections
echo [✔] Checking active SSH connections...
netstat -an | findstr ":22" > "%logFolder%\Active_SSH_Connections.txt"

echo [✔] All logs have been saved to: %logFolder%
pause
