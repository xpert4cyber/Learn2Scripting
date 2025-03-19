@echo off
setlocal enabledelayedexpansion

:: Define output file
set outputFile=%CD%\wifi_passwords.txt

:: Clear previous output file content
echo Listing saved Wi-Fi profiles... > "%outputFile%"
echo. >> "%outputFile%"

echo [*] Retrieving saved Wi-Fi profiles...
for /f "tokens=2 delims=:" %%a in ('netsh wlan show profiles ^| findstr "All User Profile"') do (
    set "profileName=%%a"
    set "profileName=!profileName:~1!"

    echo [*] Extracting password for: !profileName!

    :: Extract password and handle empty cases
    set "wifiPassword="
    for /f "tokens=*" %%b in ('netsh wlan show profile name^="!profileName!" key^=clear ^| findstr /C:"Key Content"') do (
        set "wifiPassword=%%b"
    )

    :: Process extracted password
    if defined wifiPassword (
        set "wifiPassword=!wifiPassword:*: =!"
    ) else (
        set "wifiPassword=No password (Open Network)"
    )

    :: Save to file
    echo SSID: !profileName! >> "%outputFile%"
    echo Password: !wifiPassword! >> "%outputFile%"
    echo ---------------------- >> "%outputFile%"
)

echo.
echo [*] Passwords saved to %outputFile%
pause
