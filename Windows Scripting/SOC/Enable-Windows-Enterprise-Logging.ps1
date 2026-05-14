# ==========================================================
# SOC AUTO LOG DISCOVERY + AUTO ENABLE ENGINE (FINAL)
# ==========================================================

Clear-Host
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " SOC AUTO LOG DISCOVERY + FIX ENGINE START" -ForegroundColor Cyan
Write-Host "=============================================`n" -ForegroundColor Cyan

# ---------------- ADMIN CHECK ----------------
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "RUN AS ADMIN REQUIRED" -ForegroundColor Red
    exit
}

# ==========================================================
# 1. DEFINE CRITICAL LOG SET (A-Z SOC COVERAGE)
# ==========================================================

$criticalLogs = @(
"Security",
"System",
"Application",
"Setup",
"Windows PowerShell",
"Microsoft-Windows-PowerShell/Operational",
"Microsoft-Windows-Sysmon/Operational",
"Microsoft-Windows-WMI-Activity/Operational",
"Microsoft-Windows-TaskScheduler/Operational",
"Microsoft-Windows-DNS-Client/Operational",
"Microsoft-Windows-Windows Defender/Operational",
"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
"Microsoft-Windows-Kernel-General",
"Microsoft-Windows-Kernel-Process",
"Microsoft-Windows-Kernel-File",
"Microsoft-Windows-Kernel-Network"
)

# ==========================================================
# 2. SCAN EXISTING LOG CHANNELS
# ==========================================================

Write-Host "[+] Scanning Event Log Channels..." -ForegroundColor Yellow

$available = wevtutil el

$report = @()
foreach ($log in $criticalLogs) {

    $exists = $available -contains $log

    if ($exists) {
        $status = "AVAILABLE"
    } else {
        $status = "MISSING"
    }

    $report += [PSCustomObject]@{
        LogName = $log
        Status  = $status
    }
}

$report | Format-Table -AutoSize

# ==========================================================
# 3. AUTO ENABLE AVAILABLE LOGS
# ==========================================================

Write-Host "`n[+] Enabling Available Logs..." -ForegroundColor Yellow

foreach ($r in $report) {

    if ($r.Status -eq "AVAILABLE") {
        try {
            wevtutil sl $r.LogName /e:true 2>$null
            wevtutil sl $r.LogName /ms:1073741824 2>$null
            Write-Host "ENABLED: $($r.LogName)" -ForegroundColor Green
        } catch {
            Write-Host "FAILED: $($r.LogName)" -ForegroundColor DarkRed
        }
    }
}

# ==========================================================
# 4. ADVANCED AUDIT POLICY AUTO FIX
# ==========================================================

Write-Host "`n[+] Applying Audit Policy..." -ForegroundColor Yellow

$auditFix = @(
"Logon",
"Logoff",
"Account Lockout",
"Special Logon",
"Process Creation",
"Process Termination",
"User Account Management",
"Security Group Management",
"Credential Validation",
"File System",
"Registry",
"Removable Storage",
"Policy Change"
)

foreach ($a in $auditFix) {
    try {
        auditpol /set /subcategory:$a /success:enable /failure:enable | Out-Null
        Write-Host "AUDIT ENABLED: $a" -ForegroundColor Green
    } catch {
        Write-Host "AUDIT SKIP: $a" -ForegroundColor DarkYellow
    }
}

# ==========================================================
# 5. POWERSHELL FORENSIC LOGGING
# ==========================================================

Write-Host "`n[+] Enabling PowerShell Logging..." -ForegroundColor Yellow

$ps = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell"

New-Item $ps -Force | Out-Null

New-Item "$ps\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty "$ps\ScriptBlockLogging" EnableScriptBlockLogging 1

New-Item "$ps\ModuleLogging" -Force | Out-Null
Set-ItemProperty "$ps\ModuleLogging" EnableModuleLogging 1

New-Item "$ps\Transcription" -Force | Out-Null
Set-ItemProperty "$ps\Transcription" EnableTranscripting 1

# ==========================================================
# 6. PROCESS COMMAND LINE LOGGING (DFIR CRITICAL)
# ==========================================================

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
/v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null

# ==========================================================
# 7. FIREWALL LOGGING
# ==========================================================

Write-Host "`n[+] Firewall Logging..." -ForegroundColor Yellow

netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
netsh advfirewall set allprofiles logging allowedconnections enable | Out-Null

# ==========================================================
# 8. SYSMON AUTO INSTALL
# ==========================================================

Write-Host "`n[+] Sysmon Setup..." -ForegroundColor Yellow

$sysmonPath = "$env:ProgramData\sysmon.exe"
$configPath  = "$env:ProgramData\sysmon.xml"

Invoke-WebRequest "https://live.sysinternals.com/Sysmon64.exe" -OutFile $sysmonPath -UseBasicParsing

Invoke-WebRequest `
"https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
-OutFile $configPath -UseBasicParsing

Start-Process $sysmonPath -ArgumentList "-accepteula -i `"$configPath`"" -Wait

# ==========================================================
# 9. FINAL GAP REPORT
# ==========================================================

Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host " FINAL LOG COVERAGE REPORT" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

$missing = $report | Where-Object { $_.Status -eq "MISSING" }

if ($missing.Count -eq 0) {
    Write-Host "ALL CRITICAL LOGS AVAILABLE & ENABLED" -ForegroundColor Green
} else {
    Write-Host "MISSING LOGS (OS LIMITATIONS):" -ForegroundColor Yellow
    $missing | Format-Table -AutoSize
}

Write-Host "`n=============================================" -ForegroundColor Green
Write-Host " SOC AUTO DISCOVERY COMPLETED" -ForegroundColor Green
Write-Host " SYSTEM NOW MAXIMUM POSSIBLE TELEMETRY MODE" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
