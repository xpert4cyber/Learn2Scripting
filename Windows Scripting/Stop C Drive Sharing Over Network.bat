@echo off
:: Remove C: drive sharing and disable file sharing

:: Run as administrator check
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Run this script as Administrator!
    pause
    exit
)

:: Remove the shared C: drive (CShare)
echo Removing C: drive share...
net share CShare /delete

:: Disable file sharing in Windows Firewall
echo Disabling File Sharing...
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No

:: Confirm removal
echo.
echo Updated share status:
net share

echo.
echo ✅ C: drive sharing has been turned OFF.
echo.
pause
