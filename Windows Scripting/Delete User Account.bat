@echo off
title Delete Admin User
echo Deleting user admin0001...

:: Check if user exists
net user admin0001 >nul 2>&1
if %errorlevel% neq 0 (
    echo User 'admin0001' does not exist.
    pause
    exit /b
)

:: Remove user from Administrators group
net localgroup Administrators admin0001 /delete

:: Delete the user account
net user admin0001 /delete

:: Remove user profile folder (optional)
rd /s /q "C:\Users\admin0001"

echo User 'admin0001' has been deleted successfully.
pause
