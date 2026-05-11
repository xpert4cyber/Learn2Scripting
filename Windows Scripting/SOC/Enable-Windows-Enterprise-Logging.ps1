<#
==================================================================================
 FINAL ENTERPRISE WINDOWS LOGGING ENABLEMENT SCRIPT
 SOC / DFIR / THREAT HUNTING READY (CLEAN VERSION)
==================================================================================
#>

# ============================
# ADMIN CHECK (FIXED)
# ============================

If (-NOT ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "[!] Run PowerShell as Administrator!" -ForegroundColor Red
    Exit
}

Write-Host "`n[+] Starting Windows Logging Hardening..." -ForegroundColor Cyan

# ============================
# CREATE LOG FOLDER
# ============================

New-Item -ItemType Directory -Path "C:\PowerShellLogs" -Force | Out-Null

# ============================
# ENABLE AUDIT POLICIES
# ============================

Write-Host "[+] Enabling Audit Policies..." -ForegroundColor Yellow

$audit = @(
"Logon","Logoff","Account Lockout","Special Logon",
"Process Creation","Process Termination",
"File System","Registry",
"User Account Management","Security Group Management",
"Credential Validation",
"File Share","Detailed File Share",
"Removable Storage",
"Filtering Platform Connection",
"Security System Extension"
)

foreach ($a in $audit) {
    auditpol /set /subcategory:"$a" /success:enable /failure:enable
}

# ============================
# PROCESS COMMAND LINE LOGGING
# ============================

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
/v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# ============================
# POWERSHELL LOGGING
# ============================

Write-Host "[+] Enabling PowerShell Logging..." -ForegroundColor Green

New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
-Name EnableScriptBlockLogging -Value 1

New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
-Name EnableModuleLogging -Value 1

# Transcription
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force | Out-Null
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
-Name EnableTranscripting -Value 1

Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
-Name OutputDirectory -Value "C:\PowerShellLogs"

# ============================
# DEFENDER LOGS
# ============================

wevtutil sl "Microsoft-Windows-Windows Defender/Operational" /e:true

# ============================
# FIREWALL LOGGING
# ============================

Set-NetFirewallProfile `
-Profile Domain,Public,Private `
-LogAllowed True `
-LogBlocked True `
-LogIgnored True `
-LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log" `
-LogMaxSizeKilobytes 32767

# ============================
# ENABLE IMPORTANT LOG CHANNELS
# ============================

$logs = @(
"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
"Microsoft-Windows-TaskScheduler/Operational",
"Microsoft-Windows-WMI-Activity/Operational",
"Microsoft-Windows-SMBServer/Operational",
"Microsoft-Windows-DNS-Client/Operational",
"Microsoft-Windows-DeviceGuard/Operational",
"Microsoft-Windows-Kerberos/Operational",
"Microsoft-Windows-NTLM/Operational",
"Microsoft-Windows-WinRM/Operational",
"Microsoft-Windows-PrintService/Operational"
)

foreach ($log in $logs) {
    wevtutil sl "$log" /e:true
}

# ============================
# INCREASE LOG SIZE + RETENTION
# ============================

wevtutil sl Security /ms:209715200
wevtutil sl System /ms:104857600
wevtutil sl Application /ms:104857600

wevtutil sl Security /rt:true
wevtutil sl System /rt:true
wevtutil sl Application /rt:true

# ============================
# OBJECT ACCESS + USB
# ============================

auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable

# ============================
# FINAL MESSAGE
# ============================

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "[+] WINDOWS LOGGING ENABLED SUCCESSFULLY" -ForegroundColor Green
Write-Host "[+] SOC READY BASELINE CONFIG APPLIED" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Cyan