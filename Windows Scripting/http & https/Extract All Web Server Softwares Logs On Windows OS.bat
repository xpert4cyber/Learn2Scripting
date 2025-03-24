@echo off
setlocal enabledelayedexpansion

:: Define log storage path
set "LOG_DIR=%USERPROFILE%\Desktop\WebServer_Logs"
mkdir "%LOG_DIR%"

echo [*] Extracting Web Server Logs...

:: Check and Extract IIS Logs
if exist "C:\inetpub\logs\LogFiles" (
    echo [IIS] Logs Found!
    xcopy "C:\inetpub\logs\LogFiles" "%LOG_DIR%\IIS" /E /I /Y
)

:: Check and Extract Apache Logs (XAMPP/WAMP)
if exist "C:\xampp\apache\logs" (
    echo [Apache-XAMPP] Logs Found!
    xcopy "C:\xampp\apache\logs" "%LOG_DIR%\Apache-XAMPP" /E /I /Y
)
if exist "C:\wamp64\logs" (
    echo [Apache-WAMP] Logs Found!
    xcopy "C:\wamp64\logs" "%LOG_DIR%\Apache-WAMP" /E /I /Y
)

:: Check and Extract Nginx Logs
if exist "C:\nginx\logs" (
    echo [Nginx] Logs Found!
    xcopy "C:\nginx\logs" "%LOG_DIR%\Nginx" /E /I /Y
)

:: Check and Extract Tomcat Logs
if exist "C:\Program Files\Apache Software Foundation\Tomcat 9.0\logs" (
    echo [Tomcat] Logs Found!
    xcopy "C:\Program Files\Apache Software Foundation\Tomcat 9.0\logs" "%LOG_DIR%\Tomcat" /E /I /Y
)

:: Check for Other Web Servers
for %%S in (
    "C:\ProgramData\nginx\logs",
    "C:\ProgramData\Apache Group\Apache2\logs",
    "C:\Program Files\Nginx\logs",
    "C:\Program Files (x86)\Apache Group\Apache2\logs"
) do (
    if exist %%S (
        echo [Other Web Server] Logs Found at %%S
        xcopy "%%S" "%LOG_DIR%\OtherServers" /E /I /Y
    )
)

echo [✔] Logs extracted to: %LOG_DIR%
pause
exit
