@echo off
setlocal enabledelayedexpansion

:: Run as Administrator check
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Please run this script as Administrator.
    pause
    exit
)

:: Define the hosts file path
set "hostsFile=C:\Windows\System32\drivers\etc\hosts"

:: Backup the original hosts file
if not exist "%hostsFile%.bak" copy "%hostsFile%" "%hostsFile%.bak"

:: List of social media sites to block
set "sites=facebook.com twitter.com instagram.com youtube.com tiktok.com snapchat.com linkedin.com reddit.com whatsapp.com"

echo Blocking social media sites...

:: Loop through sites and add them to hosts file
for %%S in (%sites%) do (
    echo 127.0.0.1  %%S>>"%hostsFile%"
    echo 127.0.0.1  www.%%S>>"%hostsFile%"
)

echo Social media sites blocked successfully!
ipconfig /flushdns

pause
