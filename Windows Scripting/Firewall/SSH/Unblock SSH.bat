@echo off
setlocal

:: Check for Administrator Privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Please run this script as Administrator.
    pause
    exit
)

echo Unblocking OpenSSH Server port (22)...

:: Delete inbound and outbound rules for SSH
netsh advfirewall firewall delete rule name="Block OpenSSH Port 22"
netsh advfirewall firewall delete rule name="Block OpenSSH Port 22 Outbound"

echo OpenSSH Server port (22) has been unblocked.
pause
