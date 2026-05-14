<#
==================================================================================
 WINDOWS SERVER MAXIMUM COVERAGE LOGGING STACK (REALISTIC A–Z)
 SOC / DFIR / ACTIVE DIRECTORY / THREAT HUNTING READY
==================================================================================
#>

# ============================
# ADMIN CHECK
# ============================
If (-NOT ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "[!] Run as Administrator" -ForegroundColor Red
    Exit
}

Set-ExecutionPolicy Bypass -Scope Process -Force

Write-Host "[+] Deploying MAXIMUM Windows Server Logging..." -ForegroundColor Cyan

# ============================
# BASE
# ============================
New-Item -ItemType Directory -Path "C:\SOC_STACK\Sysmon" -Force | Out-Null
New-Item -ItemType Directory -Path "C:\Logs" -Force | Out-Null
New-Item -ItemType Directory -Path "C:\PowerShellLogs" -Force | Out-Null

# ============================
# 1. FULL ADVANCED AUDIT POLICY (ALL IMPORTANT SUBCATEGORIES)
# ============================
$audit = @(
"Logon","Logoff","Account Lockout","Special Logon",
"Process Creation","Process Termination",
"File System","Registry","Handle Manipulation",
"User Account Management","Security Group Management",
"Credential Validation",
"Kerberos Authentication Service","Kerberos Service Ticket Operations",
"Directory Service Access","Directory Service Changes","Directory Service Replication",
"File Share","Detailed File Share",
"Removable Storage",
"Filtering Platform Connection","Filtering Platform Packet Drop",
"Other Object Access Events",
"Security System Extension",
"DPAPI Activity",
"Audit Policy Change",
"Authorization Policy Change"
)

foreach ($a in $audit) {
    auditpol /set /subcategory:"$a" /success:enable /failure:enable | Out-Null
}

# ============================
# 2. PROCESS + COMMAND LINE TRACKING
# ============================
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
/v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# ============================
# 3. POWERSHELL FULL TELEMETRY
# ============================
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty ... -Name EnableScriptBlockLogging -Value 1

New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
Set-ItemProperty ... -Name EnableModuleLogging -Value 1

New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force | Out-Null
Set-ItemProperty ... -Name EnableTranscripting -Value 1

# ============================
# 4. DEFENDER + SECURITY STACK
# ============================
wevtutil sl "Microsoft-Windows-Windows Defender/Operational" /e:true
wevtutil sl "Microsoft-Windows-Windows Defender/WHC" /e:true

# ============================
# 5. FIREWALL FULL LOGGING
# ============================
Set-NetFirewallProfile -Profile Domain,Public,Private `
-LogAllowed True -LogBlocked True -LogIgnored True `
-LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log" `
-LogMaxSizeKilobytes 32767

# ============================
# 6. CORE WINDOWS SERVER EVENT CHANNELS
# ============================
$logs = @(
"Security","System","Application",
"Microsoft-Windows-SMBServer/Operational",
"Microsoft-Windows-SMBClient/Operational",
"Microsoft-Windows-WMI-Activity/Operational",
"Microsoft-Windows-TaskScheduler/Operational",
"Microsoft-Windows-WinRM/Operational",
"Microsoft-Windows-PowerShell/Operational",
"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
"Microsoft-Windows-DNS-Client/Operational",
"Microsoft-Windows-DNS-Server/Analytical",
"Microsoft-Windows-Kerberos/Operational",
"Microsoft-Windows-NTLM/Operational",
"Microsoft-Windows-DeviceGuard/Operational",
"Microsoft-Windows-PrintService/Operational"
)

foreach ($l in $logs) {
    wevtutil sl "$l" /e:true
}

# ============================
# 7. LOG SIZE + RETENTION MAX
# ============================
wevtutil sl Security /ms:4294967295
wevtutil sl System /ms:1073741824
wevtutil sl Application /ms:1073741824

wevtutil sl Security /rt:true
wevtutil sl System /rt:true
wevtutil sl Application /rt:true

# ============================
# 8. OBJECT ACCESS + USB + FILE FORENSICS
# ============================
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable

# ============================
# 9. LSASS PROTECTION (CREDENTIAL THEFT BLOCK VISIBILITY)
# ============================
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
/v RunAsPPL /t REG_DWORD /d 1 /f

# ============================
# 10. SYSMON (FULL BEHAVIORAL TELEMETRY)
# ============================
$sysmon = "C:\SOC_STACK\Sysmon"
Invoke-WebRequest "https://live.sysinternals.com/Sysmon64.exe" -OutFile "$sysmon\Sysmon64.exe"

Invoke-WebRequest `
"https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
-OutFile "$sysmon\sysmonconfig.xml"

Start-Process "$sysmon\Sysmon64.exe" -ArgumentList "-accepteula -i $sysmon\sysmonconfig.xml" -Wait

# ============================
# FINAL APPLY
# ============================
gpupdate /force | Out-Null

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "[+] MAXIMUM WINDOWS SERVER LOGGING ENABLED" -ForegroundColor Green
Write-Host "[+] SOC + DFIR + AD + NETWORK VISIBILITY ACTIVE" -ForegroundColor Green
Write-Host "[+] SYS MON + DEFENDER + AUDIT + FIREWALL READY" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Cyan
