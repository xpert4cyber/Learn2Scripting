<#
==================================================================================
 ULTRA ENTERPRISE WINDOWS LOGGING + SYSMON DEPLOYMENT SCRIPT
 SOC / DFIR / THREAT HUNTING / MALWARE ANALYSIS READY
==================================================================================
#>

# ============================
# ADMIN CHECK
# ============================
If (-NOT ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "[!] Run PowerShell as Administrator!" -ForegroundColor Red
    Exit
}

Write-Host "`n[+] Initializing Enterprise Security Telemetry Stack..." -ForegroundColor Cyan

# ============================
# VARIABLES
# ============================
$baseDir = "C:\SecurityStack"
$sysmonDir = "$baseDir\Sysmon"
$configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$configFile = "$sysmonDir\sysmonconfig.xml"

New-Item -ItemType Directory -Path $sysmonDir -Force | Out-Null
New-Item -ItemType Directory -Path "C:\PowerShellLogs" -Force | Out-Null

# ============================
# ENABLE AUDIT POLICIES (EXPANDED)
# ============================
Write-Host "[+] Enabling Advanced Audit Policies..." -ForegroundColor Yellow

$audit = @(
"Logon","Logoff","Account Lockout","Special Logon",
"Process Creation","Process Termination",
"File System","Registry","Handle Manipulation",
"User Account Management","Security Group Management",
"Credential Validation","Kerberos Authentication Service",
"Kerberos Service Ticket Operations",
"File Share","Detailed File Share",
"Removable Storage",
"Filtering Platform Connection",
"Filtering Platform Packet Drop",
"Other Object Access Events",
"Security System Extension",
"Process Creation",
"Process Termination"
)

foreach ($a in $audit) {
    auditpol /set /subcategory:"$a" /success:enable /failure:enable | Out-Null
}

# ============================
# PROCESS COMMAND LINE LOGGING
# ============================
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
/v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# ============================
# POWERSHELL DEEP LOGGING
# ============================
Write-Host "[+] Enabling PowerShell Deep Logging..." -ForegroundColor Green

New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
-Name EnableScriptBlockLogging -Value 1

New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
-Name EnableModuleLogging -Value 1

New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force | Out-Null
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
-Name EnableTranscripting -Value 1

Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
-Name OutputDirectory -Value "C:\PowerShellLogs"

# ============================
# DEFENDER LOGGING
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
# ENABLE CRITICAL EVENT LOG CHANNELS
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
"Microsoft-Windows-PrintService/Operational",
"Microsoft-Windows-PowerShell/Operational"
)

foreach ($log in $logs) {
    wevtutil sl "$log" /e:true
}

# ============================
# INCREASE LOG SIZE + RETENTION
# ============================
wevtutil sl Security /ms:2147483648
wevtutil sl System /ms:1073741824
wevtutil sl Application /ms:1073741824

wevtutil sl Security /rt:true
wevtutil sl System /rt:true
wevtutil sl Application /rt:true

# ============================
# OBJECT ACCESS + USB FORENSICS
# ============================
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable

# ============================
# ============================
# SYSMON AUTO INSTALL (ARCH DETECTION)
# ============================
Write-Host "[+] Installing Sysmon..." -ForegroundColor Cyan

$arch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture

if ($arch -like "*64*") {
    $sysmonExe = "$sysmonDir\Sysmon64.exe"
    $downloadUrl = "https://live.sysinternals.com/Sysmon64.exe"
} else {
    $sysmonExe = "$sysmonDir\Sysmon.exe"
    $downloadUrl = "https://live.sysinternals.com/Sysmon.exe"
}

Invoke-WebRequest -Uri $downloadUrl -OutFile $sysmonExe

# ============================
# DOWNLOAD SYSMON CONFIG (ADVANCED)
# ============================
Write-Host "[+] Downloading Sysmon Configuration..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $configUrl -OutFile $configFile

# ============================
# INSTALL SYSMON WITH CONFIG
# ============================
Write-Host "[+] Deploying Sysmon with enterprise config..." -ForegroundColor Green
Start-Process -FilePath $sysmonExe -ArgumentList "-accepteula -i $configFile" -Wait -NoNewWindow

# ============================
# ENABLE ADDITIONAL SECURITY TELEMETRY
# ============================
Write-Host "[+] Enabling Advanced Threat Telemetry..." -ForegroundColor Yellow

# Process auditing enhancements
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable

# DNS logging via ETW
wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true

# LSA & Authentication tracking
wevtutil sl "Microsoft-Windows-LSA/Operational" /e:true

# ============================
# FINAL HARDENING TOUCH
# ============================
Write-Host "[+] Applying final SOC baseline hardening..." -ForegroundColor Cyan

gpupdate /force | Out-Null

# ============================
# FINAL STATUS
# ============================
Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "[+] ENTERPRISE TELEMETRY STACK DEPLOYED SUCCESSFULLY" -ForegroundColor Green
Write-Host "[+] SYSMON + WINDOWS LOGGING + AUDIT ENABLED" -ForegroundColor Green
Write-Host "[+] READY FOR SOC / DFIR / THREAT HUNTING / MALWARE ANALYSIS" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Cyan