@echo off
setlocal

:: Run as Administrator check
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Please run this script as Administrator.
    pause
    exit
)

:: Define the hosts file path
set "hostsFile=C:\Windows\System32\drivers\etc\hosts"
set "backupFile=%hostsFile%.bak"

:: Check if a backup exists
if exist "%backupFile%" (
    copy /Y "%backupFile%" "%hostsFile%"
    echo Social media sites unblocked successfully!
) else (
    echo No backup found. Removing block entries manually...
    
    :: Create a temporary file
    findstr /V "facebook.com twitter.com instagram.com youtube.com tiktok.com snapchat.com linkedin.com reddit.com whatsapp.com" "%hostsFile%" > "%hostsFile%.tmp"
    move /Y "%hostsFile%.tmp" "%hostsFile%"
)

:: Flush DNS cache to apply changes
ipconfig /flushdns

echo Done! Social media sites are now accessible.
pause
