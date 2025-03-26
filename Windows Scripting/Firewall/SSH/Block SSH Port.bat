@echo off
setlocal

:: Check for Administrator Privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Please run this script as Administrator.
    pause
    exit
)

echo Blocking OpenSSH Server port (22)...

:: Block inbound traffic on port 22 (SSH)
netsh advfirewall firewall add rule name="Block OpenSSH Port 22" dir=in action=block protocol=TCP localport=22 enable=yes

:: Block outbound traffic on port 22 (SSH)
netsh advfirewall firewall add rule name="Block OpenSSH Port 22 Outbound" dir=out action=block protocol=TCP localport=22 enable=yes

echo OpenSSH Server port (22) has been blocked successfully.
pause
