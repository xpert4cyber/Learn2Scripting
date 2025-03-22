@echo off
setlocal enabledelayedexpansion

:: Ensure Administrator Privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Please run this script as Administrator!
    pause
    exit /b
)

:: Create timestamped log storage folder on Desktop
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set dt=%%I
set logFolder=%USERPROFILE%\Desktop\Attacker_Logs_%dt:~0,8%-%dt:~8,6%
mkdir "%logFolder%"

:: Function to monitor logs in real-time
echo [✔] Monitoring system for potential attackers...
:monitor
cls
echo [✔] Extracting attacker logs...

:: 1. Extract failed login attempts (SSH, RDP, FTP, IIS, SMB)
set "eventIDs=4625 4776 529 530 531 532 533 534 535 536 537 539 540 552"
(for %%E in (%eventIDs%) do (
    wevtutil qe Security /q:"*[System[(EventID=%%E)]]" /f:text
)) > "%logFolder%\Failed_Login_Attempts.txt"

:: 2. Extract successful logins (Track intrusions)
wevtutil qe Security /q:"*[System[(EventID=4624)]]" /f:text > "%logFolder%\Successful_Logins.txt"

:: 3. Monitor real-time active connections (Detect attackers)
(for %%P in (21 22 23 25 53 80 110 135 139 143 443 445 3306 3389 5900 8080) do (
    netstat -an | findstr :%%P
)) > "%logFolder%\Active_Attacker_IPs.txt"

:: 4. Extract Windows Firewall logs
set fwLog=C:\Windows\System32\LogFiles\Firewall\pfirewall.log
if exist "%fwLog%" (
    copy "%fwLog%" "%logFolder%\Firewall_Attacker_IPs.log" >nul
) 

:: 5. Extract blocked IPs from Windows Firewall
netsh advfirewall monitor show firewallrule | findstr "Blocked" > "%logFolder%\Blocked_IPs.txt"

:: 6. Extract attack logs from common log locations (SSH, FTP, IIS, HTTP logs)
set logPaths=^
"C:\inetpub\logs\LogFiles\W3SVC*" ^
"C:\Windows\System32\winevt\Logs\Security.evtx" ^
"C:\Windows\System32\LogFiles\HTTPERR\httperr*.log" ^
"C:\ProgramData\ssh\logs\sshd.log" ^
"C:\Program Files\FileZilla Server\Logs\*"

(for %%L in (%logPaths%) do (
    if exist %%L (
        xcopy "%%L" "%logFolder%\" /s /y >nul
    )
))

:: 7. Extract attacker IPs
findstr /R "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" "%logFolder%\Active_Attacker_IPs.txt" > "%logFolder%\Extracted_IPs.txt"

:: 8. Live lookup of attacker IPs using IP-API (Free)
echo [✔] Looking up attacker IPs...
(for /f "tokens=*" %%I in (%logFolder%\Extracted_IPs.txt) do (
    curl -s "http://ip-api.com/line/%%I" >> "%logFolder%\IP_Lookup_Results.txt"
))

:: 9. Refresh every 30 seconds for live monitoring
timeout /t 30
goto monitor
