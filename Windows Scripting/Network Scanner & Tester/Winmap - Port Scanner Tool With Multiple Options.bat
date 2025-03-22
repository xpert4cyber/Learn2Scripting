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

:: Get user input for target
:TARGET
cls
echo =====================================
echo      Fast Nmap Interactive Scanner
echo =====================================
set /p target=Enter target IP or domain: 
if "%target%"=="" (
    echo Target cannot be empty! Try again.
    timeout /t 2 >nul
    goto TARGET
)

:: Show scan options
:MENU
cls
echo =====================================
echo      Select Nmap Scan Type
echo =====================================
echo [1] Quick Scan (Fast Ping + Open Ports)
echo [2] Service & Version Detection
echo [3] Full Port Scan (All 65535 Ports)
echo [4] Aggressive Scan (Deep Recon)
echo [5] UDP Scan (Common Ports)
echo [6] Firewall Evasion Scan
echo [7] All Scans (Parallel Execution)
echo [B] Back to Target Selection
echo [E] Exit
echo =====================================
set /p choice=Enter your choice: 

:: Process user choice
if "%choice%"=="1" goto QUICK_SCAN
if "%choice%"=="2" goto SERVICE_SCAN
if "%choice%"=="3" goto FULL_PORT_SCAN
if "%choice%"=="4" goto AGGRESSIVE_SCAN
if "%choice%"=="5" goto UDP_SCAN
if "%choice%"=="6" goto FIREWALL_SCAN
if "%choice%"=="7" goto ALL_SCANS
if /I "%choice%"=="B" goto TARGET
if /I "%choice%"=="E" exit

echo Invalid option! Try again.
timeout /t 2 >nul
goto MENU

:: Fast Scans
:QUICK_SCAN
echo Running Quick Scan...
nmap -T4 -F %target% -oN "%logFolder%\Quick_Scan.txt"
goto MENU

:SERVICE_SCAN
echo Running Service & Version Detection...
nmap -T4 -sV %target% -oN "%logFolder%\Service_Version_Scan.txt"
goto MENU

:FULL_PORT_SCAN
echo Running Full Port Scan...
nmap -T4 -p- %target% -oN "%logFolder%\Full_Port_Scan.txt"
goto MENU

:AGGRESSIVE_SCAN
echo Running Aggressive Scan...
nmap -T4 -A %target% -oN "%logFolder%\Aggressive_Scan.txt"
goto MENU

:UDP_SCAN
echo Running UDP Scan...
nmap -T4 -sU --top-ports 100 %target% -oN "%logFolder%\UDP_Scan.txt"
goto MENU

:FIREWALL_SCAN
echo Running Firewall Evasion Scan...
nmap -T4 -f %target% -oN "%logFolder%\Firewall_Evasion.txt"
goto MENU

:ALL_SCANS
echo Running all scans in parallel...
start nmap -T4 -F %target% -oN "%logFolder%\Quick_Scan.txt"
start nmap -T4 -sV %target% -oN "%logFolder%\Service_Version_Scan.txt"
start nmap -T4 -p- %target% -oN "%logFolder%\Full_Port_Scan.txt"
start nmap -T4 -A %target% -oN "%logFolder%\Aggressive_Scan.txt"
start nmap -T4 -sU --top-ports 100 %target% -oN "%logFolder%\UDP_Scan.txt"
start nmap -T4 -f %target% -oN "%logFolder%\Firewall_Evasion.txt"
goto MENU
