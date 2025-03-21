@echo off
:: Grant Everyone full access to C: drive over the network (Use with caution)

:: Run as administrator check
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Run this script as Administrator!
    pause
    exit
)

:: Enable file sharing
echo Enabling File Sharing...
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes

:: Set up C: drive share (Warning: FULL ACCESS)
echo Sharing C: drive as "CShare"...
net share CShare=C:\ /GRANT:Everyone,FULL

:: Show shared folders
echo.
echo Current Shares:
net share

:: Show the network path
echo.
echo Your C: drive is now shared as "\\%COMPUTERNAME%\CShare"
echo.
echo To access it from another PC, use:
echo   \\%COMPUTERNAME%\CShare
echo   or
echo   \\%IPADDRESS%\CShare
echo.
pause
