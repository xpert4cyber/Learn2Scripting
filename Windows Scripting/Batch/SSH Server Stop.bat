@echo off
echo Stopping SSH Server...
net stop sshd
if %errorlevel%==0 (
    echo SSH Server stopped successfully.
) else (
    echo Failed to stop SSH Server or it is not running.
)
pause
