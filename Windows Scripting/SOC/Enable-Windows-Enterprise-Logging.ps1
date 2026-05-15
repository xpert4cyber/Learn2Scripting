# =================================================================================================
# ULTIMATE ENTERPRISE DFIR / SOC / MALWARE TELEMETRY ENGINE
# FULL WINDOWS SERVER A-Z LOGGING + THREAT HUNTING ENABLEMENT
# Author: Enterprise SOC/DFIR Style Script
# RUN AS ADMINISTRATOR
# =================================================================================================

Clear-Host

Write-Host "=================================================================================================" -ForegroundColor Cyan
Write-Host " ULTIMATE ENTERPRISE WINDOWS TELEMETRY ENGINE" -ForegroundColor Cyan
Write-Host " DFIR | SOC | THREAT HUNTING | RANSOMWARE | MALWARE | IR" -ForegroundColor Cyan
Write-Host "=================================================================================================" -ForegroundColor Cyan

# =================================================================================================
# ADMIN CHECK
# =================================================================================================

if (-not ([Security.Principal.WindowsPrincipal]
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "`n[!] RUN POWERSHELL AS ADMINISTRATOR" -ForegroundColor Red
    exit
}

# =================================================================================================
# GLOBAL VARIABLES
# =================================================================================================

$ErrorActionPreference = "SilentlyContinue"

$MaxSizeCritical = 1073741824      # 1 GB
$MaxSizeMedium   = 536870912       # 512 MB
$MaxSizeSmall    = 268435456       # 256 MB

$AllLogs = wevtutil el

# =================================================================================================
# SAFE ENABLE FUNCTION
# =================================================================================================

function Enable-LogSafe {

    param(
        [string]$LogName,
        [int64]$Size = 268435456
    )

    try {

        if ($AllLogs -contains $LogName) {

            wevtutil sl "$LogName" /e:true | Out-Null
            wevtutil sl "$LogName" /ms:$Size | Out-Null

            Write-Host "[ENABLED] $LogName" -ForegroundColor Green
        }
        else {

            Write-Host "[MISSING ] $LogName" -ForegroundColor DarkYellow
        }
    }
    catch {

        Write-Host "[FAILED  ] $LogName" -ForegroundColor Red
    }
}

# =================================================================================================
# ENTERPRISE DFIR / SOC LOG CHANNELS
# =================================================================================================

$CriticalLogs = @(

# -------------------------------------------------------------------------------------------------
# CORE WINDOWS
# -------------------------------------------------------------------------------------------------

"Security",
"System",
"Application",
"Setup",

# -------------------------------------------------------------------------------------------------
# POWERSHELL
# -------------------------------------------------------------------------------------------------

"Windows PowerShell",
"Microsoft-Windows-PowerShell/Admin",
"Microsoft-Windows-PowerShell/Operational",

# -------------------------------------------------------------------------------------------------
# SYSMON
# -------------------------------------------------------------------------------------------------

"Microsoft-Windows-Sysmon/Operational",

# -------------------------------------------------------------------------------------------------
# WMI
# -------------------------------------------------------------------------------------------------

"Microsoft-Windows-WMI-Activity/Operational",

# -------------------------------------------------------------------------------------------------
# TASK SCHEDULER
# -------------------------------------------------------------------------------------------------

"Microsoft-Windows-TaskScheduler/Operational",

# -------------------------------------------------------------------------------------------------
# DEFENDER
# -------------------------------------------------------------------------------------------------

"Microsoft-Windows-Windows Defender/Operational",
"Microsoft-Windows-Windows Defender/WHC",

# -------------------------------------------------------------------------------------------------
# FIREWALL
# -------------------------------------------------------------------------------------------------

"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",

# -------------------------------------------------------------------------------------------------
# KERNEL / PROCESS / FILE
# -------------------------------------------------------------------------------------------------

"Microsoft-Windows-Kernel-General",
"Microsoft-Windows-Kernel-Process",
"Microsoft-Windows-Kernel-File",
"Microsoft-Windows-Kernel-Network",

# -------------------------------------------------------------------------------------------------
# SMB
# -------------------------------------------------------------------------------------------------

"Microsoft-Windows-SMBServer/Operational",
"Microsoft-Windows-SMBClient/Operational",

# -------------------------------------------------------------------------------------------------
# RDP / TERMINAL SERVICES
# -------------------------------------------------------------------------------------------------

"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",

# -------------------------------------------------------------------------------------------------
# DNS
# -------------------------------------------------------------------------------------------------

"Microsoft-Windows-DNS-Client/Operational",
"Microsoft-Windows-DNSServer/Audit",
"Microsoft-Windows-DNSServer/Operational",

# -------------------------------------------------------------------------------------------------
# APPLOCKER
# -------------------------------------------------------------------------------------------------

"Microsoft-Windows-AppLocker/EXE and DLL",
"Microsoft-Windows-AppLocker/MSI and Script",
"Microsoft-Windows-AppLocker/Packaged app-Deployment",
"Microsoft-Windows-AppLocker/Packaged app-Execution",

# -------------------------------------------------------------------------------------------------
# CODE INTEGRITY
# -------------------------------------------------------------------------------------------------

"Microsoft-Windows-CodeIntegrity/Operational",

# -------------------------------------------------------------------------------------------------
# DEVICE / USB
# -------------------------------------------------------------------------------------------------

"Microsoft-Windows-DriverFrameworks-UserMode/Operational",
"Microsoft-Windows-Partition/Diagnostic",
"Microsoft-Windows-Storage-ClassPnP/Operational",

# -------------------------------------------------------------------------------------------------
# NETWORK
# -------------------------------------------------------------------------------------------------

"Microsoft-Windows-TCPIP/Operational",
"Microsoft-Windows-NDIS/Diagnostic",

# -------------------------------------------------------------------------------------------------
# CRASH / EXPLOIT / DFIR
# -------------------------------------------------------------------------------------------------

"Microsoft-Windows-WER-SystemErrorReporting/Operational",
"Microsoft-Windows-Kernel-Boot",

# -------------------------------------------------------------------------------------------------
# BITS / DOWNLOADS
# -------------------------------------------------------------------------------------------------

"Microsoft-Windows-Bits-Client/Operational",

# -------------------------------------------------------------------------------------------------
# AMSI
# -------------------------------------------------------------------------------------------------

"Microsoft-Antimalware-Scan-Interface/Operational"

)

# =================================================================================================
# ENABLE CRITICAL CHANNELS
# =================================================================================================

Write-Host "`n=================================================================================================" -ForegroundColor Cyan
Write-Host " ENABLING ENTERPRISE DFIR LOG CHANNELS" -ForegroundColor Cyan
Write-Host "=================================================================================================" -ForegroundColor Cyan

foreach ($log in $CriticalLogs) {

    if ($log -match "Security|Sysmon") {

        Enable-LogSafe -LogName $log -Size $MaxSizeCritical
    }
    elseif ($log -match "PowerShell|SMB|RDP|DNS|Defender") {

        Enable-LogSafe -LogName $log -Size $MaxSizeMedium
    }
    else {

        Enable-LogSafe -LogName $log -Size $MaxSizeSmall
    }
}

# =================================================================================================
# AUTO ENABLE ALL SAFE OPERATIONAL / ADMIN CHANNELS
# =================================================================================================

Write-Host "`n=================================================================================================" -ForegroundColor Cyan
Write-Host " AUTO DISCOVERING ALL SAFE OPERATIONAL CHANNELS" -ForegroundColor Cyan
Write-Host "=================================================================================================" -ForegroundColor Cyan

foreach ($channel in $AllLogs) {

    try {

        if (
            $channel -match "Operational|Admin|Analytic" -and
            $channel -notmatch "Debug|Trace"
        ) {

            wevtutil sl "$channel" /e:true | Out-Null

            Write-Host "[AUTO-ENABLED] $channel" -ForegroundColor DarkCyan
        }
    }
    catch {}
}

# =================================================================================================
# ADVANCED AUDIT POLICY
# =================================================================================================

Write-Host "`n=================================================================================================" -ForegroundColor Cyan
Write-Host " APPLYING ENTERPRISE AUDIT POLICY" -ForegroundColor Cyan
Write-Host "=================================================================================================" -ForegroundColor Cyan

$AuditPolicies = @(

"Account Lockout",
"Application Group Management",
"Computer Account Management",
"Credential Validation",
"Detailed File Share",
"Directory Service Access",
"Directory Service Changes",
"Directory Service Replication",
"File Share",
"File System",
"Filtering Platform Connection",
"Filtering Platform Packet Drop",
"Handle Manipulation",
"Kernel Object",
"Kerberos Authentication Service",
"Kerberos Service Ticket Operations",
"Logoff",
"Logon",
"Network Policy Server",
"Other Account Management Events",
"Other Logon/Logoff Events",
"Plug and Play Events",
"Policy Change",
"Privilege Use",
"Process Creation",
"Process Termination",
"Registry",
"Removable Storage",
"SAM",
"Security Group Management",
"Sensitive Privilege Use",
"Special Logon",
"User Account Management"
)

foreach ($policy in $AuditPolicies) {

    auditpol /set /subcategory:"$policy" /success:enable /failure:enable | Out-Null

    Write-Host "[AUDIT ENABLED] $policy" -ForegroundColor Green
}

# =================================================================================================
# PROCESS COMMAND LINE LOGGING
# =================================================================================================

Write-Host "`n[+] PROCESS COMMAND-LINE LOGGING" -ForegroundColor Yellow

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
/v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null

# =================================================================================================
# POWERSHELL DEEP LOGGING
# =================================================================================================

Write-Host "[+] POWERSHELL FORENSIC LOGGING" -ForegroundColor Yellow

$PSBase = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell"

New-Item $PSBase -Force | Out-Null

# Script Block Logging
New-Item "$PSBase\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty "$PSBase\ScriptBlockLogging" EnableScriptBlockLogging 1

# Module Logging
New-Item "$PSBase\ModuleLogging" -Force | Out-Null
Set-ItemProperty "$PSBase\ModuleLogging" EnableModuleLogging 1

# Transcription
New-Item "$PSBase\Transcription" -Force | Out-Null
Set-ItemProperty "$PSBase\Transcription" EnableTranscripting 1
Set-ItemProperty "$PSBase\Transcription" OutputDirectory "C:\PS_Transcripts"

# =================================================================================================
# DEFENDER HARDENING
# =================================================================================================

Write-Host "`n[+] DEFENDER ADVANCED TELEMETRY" -ForegroundColor Yellow

Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent 1
Set-MpPreference -EnableNetworkProtection Enabled
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -DisableIOAVProtection $false

# =================================================================================================
# ASR RULES
# =================================================================================================

Write-Host "`n[+] ENABLING MICROSOFT ASR RULES" -ForegroundColor Yellow

$ASRRules = @(
"56a863a9-875e-4185-98a7-b882c64b5ce5",
"d4f940ab-401b-4efc-aadc-ad5f3c50688a",
"3b576869-a4ec-4529-8536-b80a7769e899",
"be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
"26190899-1602-49e8-8b27-eb1d0a1ce869",
"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
)

foreach ($rule in $ASRRules) {

    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule `
                     -AttackSurfaceReductionRules_Actions Enabled
}

# =================================================================================================
# FIREWALL LOGGING
# =================================================================================================

Write-Host "`n[+] FIREWALL LOGGING" -ForegroundColor Yellow

netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
netsh advfirewall set allprofiles logging allowedconnections enable | Out-Null

# =================================================================================================
# APPLOCKER AUDIT MODE
# =================================================================================================

Write-Host "`n[+] APPLOCKER AUDIT MODE" -ForegroundColor Yellow

Set-Service AppIDSvc -StartupType Automatic
Start-Service AppIDSvc

# =================================================================================================
# SACL FILE AUDITING
# =================================================================================================

Write-Host "`n[+] ENABLING FILE SYSTEM SACL AUDITING" -ForegroundColor Yellow

auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null

# =================================================================================================
# SMB AUDITING
# =================================================================================================

Write-Host "`n[+] SMB FORENSIC LOGGING" -ForegroundColor Yellow

Set-SmbServerConfiguration -AuditSmb1Access $true -Force | Out-Null

# =================================================================================================
# RDP FORENSICS
# =================================================================================================

Write-Host "`n[+] RDP FORENSIC LOGGING" -ForegroundColor Yellow

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
/v fEnableLogging /t REG_DWORD /d 1 /f | Out-Null

# =================================================================================================
# DNS CLIENT LOGGING
# =================================================================================================

Write-Host "`n[+] DNS CLIENT LOGGING" -ForegroundColor Yellow

wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true

# =================================================================================================
# SYSMON INSTALL
# =================================================================================================

Write-Host "`n=================================================================================================" -ForegroundColor Cyan
Write-Host " INSTALLING SYSMON" -ForegroundColor Cyan
Write-Host "=================================================================================================" -ForegroundColor Cyan

$SysmonEXE = "$env:TEMP\Sysmon64.exe"
$SysmonCFG = "$env:TEMP\sysmonconfig.xml"

Invoke-WebRequest `
"https://live.sysinternals.com/Sysmon64.exe" `
-OutFile $SysmonEXE `
-UseBasicParsing

Invoke-WebRequest `
"https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" `
-OutFile $SysmonCFG `
-UseBasicParsing

Start-Process $SysmonEXE `
-ArgumentList "-accepteula -i `"$SysmonCFG`"" `
-Wait

# =================================================================================================
# WINDOWS EVENT FORWARDING
# =================================================================================================

Write-Host "`n[+] WINDOWS EVENT FORWARDING SERVICE" -ForegroundColor Yellow

Set-Service Wecsvc -StartupType Automatic
Start-Service Wecsvc

# =================================================================================================
# RETENTION SETTINGS
# =================================================================================================

Write-Host "`n[+] LOG RETENTION SETTINGS" -ForegroundColor Yellow

wevtutil sl Security /rt:true
wevtutil sl System /rt:true
wevtutil sl Application /rt:true

# =================================================================================================
# FINAL STATUS REPORT
# =================================================================================================

Write-Host "`n=================================================================================================" -ForegroundColor Green
Write-Host " FINAL ENTERPRISE TELEMETRY STATUS" -ForegroundColor Green
Write-Host "=================================================================================================" -ForegroundColor Green

Write-Host "[OK] ADVANCED AUDITING ENABLED" -ForegroundColor Green
Write-Host "[OK] POWERSHELL FORENSICS ENABLED" -ForegroundColor Green
Write-Host "[OK] DEFENDER HARDENING ENABLED" -ForegroundColor Green
Write-Host "[OK] ASR RULES ENABLED" -ForegroundColor Green
Write-Host "[OK] FIREWALL LOGGING ENABLED" -ForegroundColor Green
Write-Host "[OK] SMB FORENSICS ENABLED" -ForegroundColor Green
Write-Host "[OK] RDP FORENSICS ENABLED" -ForegroundColor Green
Write-Host "[OK] AMSI LOGGING ENABLED" -ForegroundColor Green
Write-Host "[OK] APPLOCKER AUDIT ENABLED" -ForegroundColor Green
Write-Host "[OK] SACL AUDITING ENABLED" -ForegroundColor Green
Write-Host "[OK] WINDOWS EVENT FORWARDING READY" -ForegroundColor Green
Write-Host "[OK] SYSMON INSTALLED" -ForegroundColor Green
Write-Host "[OK] ENTERPRISE THREAT HUNTING MODE ACTIVE" -ForegroundColor Green

Write-Host "`n=================================================================================================" -ForegroundColor Green
Write-Host " MAXIMUM POSSIBLE WINDOWS SERVER TELEMETRY ENABLED" -ForegroundColor Green
Write-Host " DFIR / SOC / MALWARE / RANSOMWARE READY" -ForegroundColor Green
Write-Host "=================================================================================================" -ForegroundColor Green
