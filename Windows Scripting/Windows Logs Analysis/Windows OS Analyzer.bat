@echo off
TITLE Windows OS Full Analysis Tool
SETLOCAL ENABLEDELAYEDEXPANSION

:: Check for Administrator Privileges
NET SESSION >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO [!] Please run this script as Administrator.
    PAUSE
    EXIT
)

:: Define Output Directory Structure
SET OUTPUT_DIR=%CD%\Windows_OS_Analysis
SET SYSTEM_INFO_DIR=%OUTPUT_DIR%\System_Info
SET SOFTWARE_DIR=%OUTPUT_DIR%\Software
SET NETWORK_DIR=%OUTPUT_DIR%\Network
SET USERS_DIR=%OUTPUT_DIR%\Users
SET SECURITY_DIR=%OUTPUT_DIR%\Security
SET DISK_DIR=%OUTPUT_DIR%\Disk

:: Create Folders
FOR %%F IN ("%SYSTEM_INFO_DIR%" "%SOFTWARE_DIR%" "%NETWORK_DIR%" "%USERS_DIR%" "%SECURITY_DIR%" "%DISK_DIR%") DO (
    IF NOT EXIST "%%F" MKDIR "%%F"
)

:: Function to Log Data
ECHO Windows OS Analysis Report - %DATE% %TIME% > "%OUTPUT_DIR%\Overview.txt"
ECHO -------------------------------------------------------------- >> "%OUTPUT_DIR%\Overview.txt"

:: [🔍] System Information
ECHO [🔍] SYSTEM INFORMATION >> "%SYSTEM_INFO_DIR%\SystemInfo.txt"
SYSTEMINFO >> "%SYSTEM_INFO_DIR%\SystemInfo.txt"

:: [🛠] Installed Software
ECHO [🛠] INSTALLED SOFTWARE >> "%SOFTWARE_DIR%\InstalledSoftware.txt"
WMIC PRODUCT GET Name, Version >> "%SOFTWARE_DIR%\InstalledSoftware.txt"

:: [⚙️] Running Processes
ECHO [⚙️] RUNNING PROCESSES >> "%SOFTWARE_DIR%\RunningProcesses.txt"
TASKLIST >> "%SOFTWARE_DIR%\RunningProcesses.txt"

:: [🔧] Services Information
ECHO [🔧] SERVICES LIST >> "%SYSTEM_INFO_DIR%\Services.txt"
SC QUERY STATE= ALL >> "%SYSTEM_INFO_DIR%\Services.txt"

:: [📌] Installed Drivers
ECHO [📌] INSTALLED DRIVERS >> "%SYSTEM_INFO_DIR%\Drivers.txt"
DRIVERQUERY >> "%SYSTEM_INFO_DIR%\Drivers.txt"

:: [🌐] Network Configuration
ECHO [🌐] NETWORK CONFIGURATION >> "%NETWORK_DIR%\NetworkConfig.txt"
IPCONFIG /ALL >> "%NETWORK_DIR%\NetworkConfig.txt"

:: [🔗] Open Ports & Active Connections
ECHO [🔗] OPEN PORTS & CONNECTIONS >> "%NETWORK_DIR%\OpenPorts.txt"
NETSTAT -ANO >> "%NETWORK_DIR%\OpenPorts.txt"

:: [👥] User Accounts
ECHO [👥] USER ACCOUNTS >> "%USERS_DIR%\UserAccounts.txt"
NET USER >> "%USERS_DIR%\UserAccounts.txt"

:: [📂] Shared Folders
ECHO [📂] SHARED FOLDERS >> "%USERS_DIR%\SharedFolders.txt"
NET SHARE >> "%USERS_DIR%\SharedFolders.txt"

:: [⏳] Scheduled Tasks
ECHO [⏳] SCHEDULED TASKS >> "%SOFTWARE_DIR%\ScheduledTasks.txt"
SCHTASKS /QUERY /FO LIST >> "%SOFTWARE_DIR%\ScheduledTasks.txt"

:: [🚀] Startup Programs
ECHO [🚀] STARTUP PROGRAMS >> "%SOFTWARE_DIR%\StartupPrograms.txt"
WMIC STARTUP GET Caption, Command >> "%SOFTWARE_DIR%\StartupPrograms.txt"

:: [💾] Disk Information
ECHO [💾] DISK INFORMATION >> "%DISK_DIR%\DiskInfo.txt"
WMIC LOGICALDISK GET DeviceID, VolumeName, Size, FreeSpace >> "%DISK_DIR%\DiskInfo.txt"

:: [🖥] RAM Information
ECHO [🖥] RAM INFORMATION >> "%DISK_DIR%\RAM_Info.txt"
WMIC MEMORYCHIP GET Capacity, Speed, Manufacturer, PartNumber >> "%DISK_DIR%\RAM_Info.txt"

:: [📜] Recent System Event Logs
ECHO [📜] EVENT LOGS (LAST 50 SYSTEM EVENTS) >> "%SECURITY_DIR%\SystemEvents.txt"
WEVTUTIL QE SYSTEM /C:50 /F:TEXT >> "%SECURITY_DIR%\SystemEvents.txt"

:: [📜] Recent Application Event Logs
ECHO [📜] EVENT LOGS (LAST 50 APPLICATION EVENTS) >> "%SECURITY_DIR%\ApplicationEvents.txt"
WEVTUTIL QE APPLICATION /C:50 /F:TEXT >> "%SECURITY_DIR%\ApplicationEvents.txt"

:: [✔] Analysis Complete
ECHO [✔] Windows OS Analysis Complete! >> "%OUTPUT_DIR%\Overview.txt"
ECHO [📁] Reports saved in: %OUTPUT_DIR%
ECHO.
ECHO ✅ Windows OS Analysis Completed Successfully!
ECHO 🔹 Reports saved in: "%OUTPUT_DIR%"

:: Open the analysis folder
START "" "%OUTPUT_DIR%"

PAUSE
