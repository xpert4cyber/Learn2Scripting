@echo off
setlocal enabledelayedexpansion

:: Check if Nmap is installed
where nmap >nul 2>&1
if %errorlevel% neq 0 (
    echo Nmap is not installed or not in PATH!
    echo Download it from: https://nmap.org/download.html
    pause
    exit /b
)

:: Get current date and time for unique folder names
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set datetime=%%I
set timestamp=%datetime:~0,4%-%datetime:~6,2%-%datetime:~8,2%_%datetime:~10,2%

:: Set log folder on Desktop
set logFolder=%USERPROFILE%\Desktop\NmapScan_%timestamp%
mkdir "%logFolder%"

:: Define target (local machine)
set target=127.0.0.1

:: Perform full port scan using Nmap
echo Scanning all 65535 ports on %target%...
nmap -p- -T4 -A -v %target% -oN "%logFolder%\Nmap_Full_Scan.txt" -oX "%logFolder%\Nmap_Full_Scan.xml" -oG "%logFolder%\Nmap_Full_Scan.gnmap"

:: Extract open ports from Nmap results
findstr /I /C:"open" "%logFolder%\Nmap_Full_Scan.txt" > "%logFolder%\Open_Ports.txt"

:: Store system information
echo Saving system information...
systeminfo > "%logFolder%\SystemInfo.txt"
ipconfig /all > "%logFolder%\Network_Config.txt"
netstat -ano > "%logFolder%\Netstat_Output.txt"
wmic process get name,processid > "%logFolder%\Running_Processes.txt"
wmic product get name,version > "%logFolder%\Installed_Programs.txt"

echo Scan complete! All logs are stored in: %logFolder%
pause
