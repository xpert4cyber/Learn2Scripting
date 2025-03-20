@echo off
title SSH Server Setup on Windows
echo Installing OpenSSH Server...

:: Install OpenSSH Server if not installed
powershell -Command "Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*' | Select-Object -ExpandProperty State" | findstr "NotPresent" > nul
if %errorlevel%==0 (
    powershell -Command "Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'"
)

:: Start SSH service
sc config sshd start=auto
net start sshd

:: Allow SSH through Windows Firewall (port 22)
netsh advfirewall firewall add rule name="OpenSSH" dir=in action=allow protocol=TCP localport=22

:: Get server IP address
for /f "tokens=2 delims=:" %%A in ('ipconfig ^| findstr /R "IPv4.*"') do set "IP=%%A"
set IP=%IP:~1%

:: Get current username
set USERNAME=%USERNAME%

:: Check password status
powershell -Command "$pass = Get-LocalUser -Name $env:USERNAME | Select-Object -ExpandProperty PasswordLastSet; If ($pass -eq $null) {Write-Output 'No Password Set'} Else {Write-Output 'Password Set'}" > password_status.txt
set /p PASSWORD=<password_status.txt
del password_status.txt

:: Save details to file
echo SSH Server Details: > ssh_details.txt
echo -------------------- >> ssh_details.txt
echo IP Address: %IP% >> ssh_details.txt
echo Username: %USERNAME% >> ssh_details.txt
echo Password: %PASSWORD% >> ssh_details.txt

echo Installation complete! Check "ssh_details.txt" for login details.
pause
