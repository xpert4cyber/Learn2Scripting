@echo off
setlocal enabledelayedexpansion

:: Check for Administrator Privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Please run this script as Administrator!
    pause
    exit /b
)

:: Create timestamped folder on Desktop
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set datetime=%%I
set timestamp=%datetime:~0,4%-%datetime:~4,2%-%datetime:~6,2%_%datetime:~8,2%-%datetime:~10,2%-%datetime:~12,2%
set logFolder=%USERPROFILE%\Desktop\IIS_FTP_Logs_%timestamp%
mkdir "%logFolder%"

:: Log file for debugging
set logFile=%logFolder%\IIS_FTP_Extraction_Log.txt
echo [INFO] IIS FTP Log Extraction - %DATE% %TIME% > "%logFile%"
echo. >> "%logFile%"

:: Check if IIS FTP Service is installed & running
sc query ftpsvc >nul 2>&1
if %errorlevel% == 0 (
    echo [✔] IIS FTP Server detected! >> "%logFile%"
    echo Extracting FTP logs...
) else (
    echo [✖] IIS FTP Server NOT detected. >> "%logFile%"
    echo No IIS FTP Server found. > "%logFolder%\No_IIS_FTP_Detected.txt"
    echo Exiting...
    pause
    exit /b
)

:: Extract IIS FTP logs from default log location
set logPath=C:\inetpub\logs\LogFiles
if exist "%logPath%" (
    echo [✔] Copying FTP logs from %logPath% >> "%logFile%"
    mkdir "%logFolder%\IIS_FTP_Server_Logs"
    xcopy "%logPath%\FTPSVC*" "%logFolder%\IIS_FTP_Server_Logs" /s /y >nul
) else (
    echo [✖] IIS FTP log directory not found! >> "%logFile%"
    echo No IIS FTP logs found. > "%logFolder%\No_IIS_FTP_Logs_Found.txt"
)

:: Extract FTP-related logs from Windows Event Logs (Successful logins)
echo [✔] Extracting Windows Event Logs for FTP authentication... >> "%logFile%"
wevtutil qe Security /q:"*[System[(EventID=4624)]] and EventData[Data[@Name='LogonType'] and (Data='2' or Data='10')]" /f:text > "%logFolder%\IIS_FTP_EventLogs.txt"

:: Extract IIS FTP errors from Windows Event Viewer
echo [✔] Extracting IIS FTP Error Logs... >> "%logFile%"
wevtutil qe Application /q:"*[System[(Provider[@Name='Microsoft-Windows-IIS-FTP-Service'])]]" /f:text > "%logFolder%\IIS_FTP_Error_Logs.txt"

:: Save netstat output for active FTP connections
echo [✔] Checking active FTP connections... >> "%logFile%"
netstat -ano | find ":21 " > "%logFolder%\Active_FTP_Connections.txt"

echo [✔] All IIS FTP logs have been saved in: %logFolder% >> "%logFile%"
echo Extraction complete. Check the folder on your Desktop.
pause
