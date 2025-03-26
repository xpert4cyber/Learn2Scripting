@echo off
setlocal enabledelayedexpansion

:: Check for Administrator Privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Please run this script as Administrator.
    pause
    exit
)

echo Blocking all manually installed software from accessing the internet...

:: Loop through all installed programs
for /r "C:\Program Files" %%F in (*.exe) do (
    netsh advfirewall firewall add rule name="Block %%~nxF" dir=out action=block program="%%F" enable=yes
)

for /r "C:\Program Files (x86)" %%F in (*.exe) do (
    netsh advfirewall firewall add rule name="Block %%~nxF" dir=out action=block program="%%F" enable=yes
)

echo All installed software has been blocked from internet access!
pause
