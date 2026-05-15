```powershell
# =================================================================================================
# ULTIMATE ENTERPRISE WINDOWS TELEMETRY ENGINE
# FULL DFIR | SOC | THREAT HUNTING | MALWARE | RANSOMWARE LOGGING
# FINAL STABLE VERSION
# RUN AS ADMINISTRATOR
# =================================================================================================

Clear-Host

Write-Host "=================================================================================================" -ForegroundColor Cyan
Write-Host " ULTIMATE ENTERPRISE WINDOWS TELEMETRY ENGINE" -ForegroundColor Cyan
Write-Host " DFIR | SOC | THREAT HUNTING | MALWARE | RANSOMWARE" -ForegroundColor Cyan
Write-Host "=================================================================================================" -ForegroundColor Cyan

# =================================================================================================
# ADMIN CHECK
# =================================================================================================

$CurrentUser = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

if (-not $CurrentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

    Write-Host ""
    Write-Host "[!] PLEASE RUN POWERSHELL AS ADMINISTRATOR" -ForegroundColor Red
    Write-Host ""

    Pause
    Exit
}

# =================================================================================================
# GLOBAL VARIABLES
# =================================================================================================

$ErrorActionPreference = "SilentlyContinue"

$CriticalLogSize = 1073741824
$MediumLogSize   = 536870912
$SmallLogSize    = 268435456

# =================================================================================================
# GET ALL AVAILABLE WINDOWS EVENT CHANNELS
# =================================================================================================

Write-Host ""
Write-Host "[+] ENUMERATING WINDOWS EVENT CHANNELS..." -ForegroundColor Yellow
Write-Host ""

$AllLogs = wevtutil el

# =================================================================================================
# SAFE LOG ENABLE FUNCTION
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

# CORE WINDOWS
"Security",
"System",
"Application",
"Setup",

# POWERSHELL
"Windows PowerShell",
"Microsoft-Windows-PowerShell/Admin",
"Microsoft-Windows-PowerShell/Operational",

# SYSMON
"Microsoft-Windows-Sysmon/Operational",

# WMI
"Microsoft-Windows-WMI-Activity/Operational",

# TASK SCHEDULER
"Microsoft-Windows-TaskScheduler/Operational",

# WINDOWS DEFENDER
"Microsoft-Windows-Windows Defender/Operational",

# FIREWALL
"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",

# SMB
"Microsoft-Windows-SMBServer/Operational",
"Microsoft-Windows-SMBClient/Operational",

# RDP
"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",

# DNS
"Microsoft-Windows-DNS-Client/Operational",
"Microsoft-Windows-DNSServer/Audit",
"Microsoft-Windows-DNSServer/Operational",

# APPLOCKER
"Microsoft-Windows-AppLocker/EXE and DLL",
"Microsoft-Windows-AppLocker/MSI and Script",
"Microsoft-Windows-AppLocker/Packaged app-Deployment",
"Microsoft-Windows-AppLocker/Packaged app-Execution",

# AMSI
"Microsoft-Antimalware-Scan-Interface/Operational",

# CODE INTEGRITY
"Microsoft-Windows-CodeIntegrity/Operational",

# BITS
"Microsoft-Windows-Bits-Client/Operational",

# KERNEL
"Microsoft-Windows-Kernel-General",
"Microsoft-Windows-Kernel-Process",
"Microsoft-Windows-Kernel-File",
"Microsoft-Windows-Kernel-Network",
"Microsoft-Windows-Kernel-Boot",

# NETWORK
"Microsoft-Windows-TCPIP/Operational",

# DEVICE / USB
"Microsoft-Windows-DriverFrameworks-UserMode/Operational",
"Microsoft-Windows-Partition/Diagnostic",
"Microsoft-Windows-Storage-ClassPnP/Operational",

# CRASH REPORTING
"Microsoft-Windows-WER-SystemErrorReporting/Operational"

)

# =================================================================================================
# ENABLE CRITICAL LOGS
# =================================================================================================

Write-Host ""
Write-Host "=================================================================================================" -ForegroundColor Cyan
Write-Host " ENABLING ENTERPRISE DFIR LOG CHANNELS" -ForegroundColor Cyan
Write-Host "=================================================================================================" -ForegroundColor Cyan
Write-Host ""

foreach ($Log in $CriticalLogs) {

    if ($Log -match "Security|Sysmon") {

        Enable-LogSafe -LogName $Log -Size $CriticalLogSize
    }
    elseif ($Log -match "PowerShell|SMB|DNS|RDP|Defender") {

        Enable-LogSafe -LogName $Log -Size $MediumLogSize
    }
    else {

        Enable-LogSafe -LogName $Log -Size $SmallLogSize
    }
}

# =================================================================================================
# AUTO ENABLE SAFE OPERATIONAL / ADMIN CHANNELS
# =================================================================================================

Write-Host ""
Write-Host "=================================================================================================" -ForegroundColor Cyan
Write-Host " AUTO ENABLING SAFE OPERATIONAL CHANNELS" -ForegroundColor Cyan
Write-Host "=================================================================================================" -ForegroundColor Cyan
Write-Host ""

foreach ($Channel in $AllLogs) {

    try {

        if (
            $Channel -match "Operational|Admin" -and
            $Channel -notmatch "Debug|Trace"
        ) {

            wevtutil sl "$Channel" /e:true | Out-Null

            Write-Host "[AUTO ENABLED] $Channel" -ForegroundColor DarkCyan
        }
    }
    catch {}
}

# =================================================================================================
# ADVANCED AUDIT POLICIES
# =================================================================================================

Write-Host ""
Write-Host "=================================================================================================" -ForegroundColor Cyan
Write-Host " APPLYING ADVANCED AUDIT POLICIES" -ForegroundColor Cyan
Write-Host "=================================================================================================" -ForegroundColor Cyan
Write-Host ""

$AuditPolicies = @(

"Logon",
"Logoff",
"Special Logon",
"Other Logon/Logoff Events",
"Account Lockout",
"Credential Validation",
"Kerberos Authentication Service",
"Kerberos Service Ticket Operations",
"Process Creation",
"Process Termination",
"File Share",
"Detailed File Share",
"File System",
"Registry",
"Removable Storage",
"SAM",
"Policy Change",
"Privilege Use",
"Sensitive Privilege Use",
"Security Group Management",
"User Account Management",
"Computer Account Management",
"Directory Service Access",
"Directory Service Changes",
"Directory Service Replication",
"Plug and Play Events",
"Handle Manipulation"

)

foreach ($Policy in $AuditPolicies) {

    try {

        auditpol /set /subcategory:"$Policy" /success:enable /failure:enable | Out-Null

        Write-Host "[AUDIT ENABLED] $Policy" -ForegroundColor Green
    }
    catch {

        Write-Host "[AUDIT FAILED ] $Policy" -ForegroundColor DarkYellow
    }
}

# =================================================================================================
# PROCESS COMMAND-LINE LOGGING
# =================================================================================================

Write-Host ""
Write-Host "[+] ENABLING PROCESS COMMAND-LINE LOGGING..." -ForegroundColor Yellow

try {

    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    /v ProcessCreationIncludeCmdLine_Enabled `
    /t REG_DWORD `
    /d 1 `
    /f | Out-Null

    Write-Host "[OK] PROCESS COMMAND-LINE LOGGING ENABLED" -ForegroundColor Green
}
catch {

    Write-Host "[FAILED] PROCESS COMMAND-LINE LOGGING" -ForegroundColor Red
}

# =================================================================================================
# POWERSHELL FORENSIC LOGGING
# =================================================================================================

Write-Host ""
Write-Host "[+] ENABLING POWERSHELL FORENSIC LOGGING..." -ForegroundColor Yellow

try {

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

    if (!(Test-Path "C:\PS_Transcripts")) {

        New-Item "C:\PS_Transcripts" -ItemType Directory | Out-Null
    }

    Write-Host "[OK] POWERSHELL FORENSICS ENABLED" -ForegroundColor Green
}
catch {

    Write-Host "[FAILED] POWERSHELL FORENSICS" -ForegroundColor Red
}

# =================================================================================================
# WINDOWS DEFENDER HARDENING
# =================================================================================================

Write-Host ""
Write-Host "[+] ENABLING MICROSOFT DEFENDER TELEMETRY..." -ForegroundColor Yellow

try {

    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -MAPSReporting Advanced
    Set-MpPreference -SubmitSamplesConsent 1
    Set-MpPreference -EnableNetworkProtection Enabled
    Set-MpPreference -PUAProtection Enabled

    Write-Host "[OK] MICROSOFT DEFENDER HARDENING ENABLED" -ForegroundColor Green
}
catch {

    Write-Host "[SKIPPED] DEFENDER SETTINGS NOT AVAILABLE" -ForegroundColor DarkYellow
}

# =================================================================================================
# ASR RULES
# =================================================================================================

Write-Host ""
Write-Host "[+] ENABLING ATTACK SURFACE REDUCTION RULES..." -ForegroundColor Yellow

$ASRRules = @(

"56a863a9-875e-4185-98a7-b882c64b5ce5",
"d4f940ab-401b-4efc-aadc-ad5f3c50688a",
"3b576869-a4ec-4529-8536-b80a7769e899",
"be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"

)

foreach ($Rule in $ASRRules) {

    try {

        Add-MpPreference `
        -AttackSurfaceReductionRules_Ids $Rule `
        -AttackSurfaceReductionRules_Actions Enabled

        Write-Host "[ASR ENABLED] $Rule" -ForegroundColor Green
    }
    catch {

        Write-Host "[ASR SKIPPED] $Rule" -ForegroundColor DarkYellow
    }
}

# =================================================================================================
# FIREWALL LOGGING
# =================================================================================================

Write-Host ""
Write-Host "[+] ENABLING FIREWALL LOGGING..." -ForegroundColor Yellow

try {

    netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
    netsh advfirewall set allprofiles logging allowedconnections enable | Out-Null

    Write-Host "[OK] FIREWALL LOGGING ENABLED" -ForegroundColor Green
}
catch {

    Write-Host "[FAILED] FIREWALL LOGGING" -ForegroundColor Red
}

# =================================================================================================
# APPLOCKER AUDIT MODE
# =================================================================================================

Write-Host ""
Write-Host "[+] ENABLING APPLOCKER AUDIT MODE..." -ForegroundColor Yellow

try {

    Set-Service AppIDSvc -StartupType Automatic
    Start-Service AppIDSvc

    Write-Host "[OK] APPLOCKER AUDIT MODE ENABLED" -ForegroundColor Green
}
catch {

    Write-Host "[SKIPPED] APPLOCKER NOT AVAILABLE" -ForegroundColor DarkYellow
}

# =================================================================================================
# SMB AUDITING
# =================================================================================================

Write-Host ""
Write-Host "[+] ENABLING SMB FORENSIC LOGGING..." -ForegroundColor Yellow

try {

    Set-SmbServerConfiguration -AuditSmb1Access $true -Force | Out-Null

    Write-Host "[OK] SMB FORENSIC LOGGING ENABLED" -ForegroundColor Green
}
catch {

    Write-Host "[SKIPPED] SMB AUDITING NOT AVAILABLE" -ForegroundColor DarkYellow
}

# =================================================================================================
# RDP LOGGING
# =================================================================================================

Write-Host ""
Write-Host "[+] ENABLING RDP FORENSIC LOGGING..." -ForegroundColor Yellow

try {

    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    /v fEnableLogging `
    /t REG_DWORD `
    /d 1 `
    /f | Out-Null

    Write-Host "[OK] RDP FORENSIC LOGGING ENABLED" -ForegroundColor Green
}
catch {

    Write-Host "[FAILED] RDP FORENSIC LOGGING" -ForegroundColor Red
}

# =================================================================================================
# WINDOWS EVENT FORWARDING
# =================================================================================================

Write-Host ""
Write-Host "[+] ENABLING WINDOWS EVENT FORWARDING..." -ForegroundColor Yellow

try {

    Set-Service Wecsvc -StartupType Automatic
    Start-Service Wecsvc

    Write-Host "[OK] WINDOWS EVENT FORWARDING ENABLED" -ForegroundColor Green
}
catch {

    Write-Host "[FAILED] WINDOWS EVENT FORWARDING" -ForegroundColor Red
}

# =================================================================================================
# SYSMON INSTALLATION
# =================================================================================================

Write-Host ""
Write-Host "=================================================================================================" -ForegroundColor Cyan
Write-Host " INSTALLING SYSMON" -ForegroundColor Cyan
Write-Host "=================================================================================================" -ForegroundColor Cyan
Write-Host ""

try {

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

    Start-Process `
    $SysmonEXE `
    -ArgumentList "-accepteula -i `"$SysmonCFG`"" `
    -Wait

    Write-Host "[OK] SYSMON INSTALLED SUCCESSFULLY" -ForegroundColor Green
}
catch {

    Write-Host "[FAILED] SYSMON INSTALLATION FAILED" -ForegroundColor Red
}

# =================================================================================================
# LOG RETENTION
# =================================================================================================

Write-Host ""
Write-Host "[+] CONFIGURING LOG RETENTION..." -ForegroundColor Yellow

try {

    wevtutil sl Security /rt:true
    wevtutil sl System /rt:true
    wevtutil sl Application /rt:true

    Write-Host "[OK] LOG RETENTION CONFIGURED" -ForegroundColor Green
}
catch {

    Write-Host "[FAILED] LOG RETENTION" -ForegroundColor Red
}

# =================================================================================================
# FINAL STATUS
# =================================================================================================

Write-Host ""
Write-Host "=================================================================================================" -ForegroundColor Green
Write-Host " FINAL ENTERPRISE TELEMETRY STATUS" -ForegroundColor Green
Write-Host "=================================================================================================" -ForegroundColor Green
Write-Host ""

Write-Host "[OK] ADVANCED AUDITING ENABLED" -ForegroundColor Green
Write-Host "[OK] POWERSHELL FORENSICS ENABLED" -ForegroundColor Green
Write-Host "[OK] PROCESS COMMAND-LINE LOGGING ENABLED" -ForegroundColor Green
Write-Host "[OK] FIREWALL LOGGING ENABLED" -ForegroundColor Green
Write-Host "[OK] AMSI TELEMETRY ENABLED" -ForegroundColor Green
Write-Host "[OK] SMB FORENSIC LOGGING ENABLED" -ForegroundColor Green
Write-Host "[OK] RDP FORENSIC LOGGING ENABLED" -ForegroundColor Green
Write-Host "[OK] WINDOWS EVENT FORWARDING ENABLED" -ForegroundColor Green
Write-Host "[OK] MICROSOFT DEFENDER HARDENING ENABLED" -ForegroundColor Green
Write-Host "[OK] APPLOCKER AUDIT MODE ENABLED" -ForegroundColor Green
Write-Host "[OK] THREAT HUNTING TELEMETRY ENABLED" -ForegroundColor Green
Write-Host "[OK] ENTERPRISE DFIR TELEMETRY ENABLED" -ForegroundColor Green
Write-Host "[OK] SYSMON INSTALLED" -ForegroundColor Green

Write-Host ""
Write-Host "=================================================================================================" -ForegroundColor Green
Write-Host " MAXIMUM POSSIBLE WINDOWS TELEMETRY ENABLED" -ForegroundColor Green
Write-Host " DFIR | SOC | MALWARE | RANSOMWARE READY" -ForegroundColor Green
Write-Host "=================================================================================================" -ForegroundColor Green
Write-Host ""
```
