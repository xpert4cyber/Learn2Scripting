@echo off
title Create Admin User
echo Creating user admin0001...

:: Create a new user with the specified password
net user admin0001 admin@1234 /add

:: Add the user to the Administrators group
net localgroup Administrators admin0001 /add

:: Display success message
echo User 'admin0001' has been created with administrator privileges.
echo Username: admin0001
echo Password: admin@1234

pause
