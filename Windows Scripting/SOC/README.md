# 🛡️ Enterprise Windows Logging Hardening Script (SOC / DFIR Ready)

A powerful PowerShell-based Windows security logging automation script designed to convert a default Windows system into a **SOC-ready monitoring environment**.

It enables advanced auditing, process tracking, PowerShell telemetry, network visibility, and persistence detection for real-world cybersecurity operations.

---

## 🚨 Why This Script Exists

Modern cyber attacks are stealthy and often bypass default Windows logging:

- Fileless malware
- PowerShell attacks
- RDP brute force
- Lateral movement
- Registry persistence
- USB data exfiltration

👉 Default Windows logs are NOT sufficient for proper detection.

This script enhances visibility using built-in Windows security features.

---

## ⚙️ Features Enabled

### 🔐 Authentication Monitoring
- Successful & failed logons (4624 / 4625)
- Account lockout events
- Kerberos authentication logs
- NTLM authentication logs
- RDP session tracking
- WinRM remote access logs

---

### ⚙️ Process Execution Tracking
- Process creation (4688)
- Process termination
- Command-line logging enabled
- PowerShell Script Block Logging (4104)
- PowerShell Module Logging
- PowerShell Transcription logs

---

### 🌐 Network Visibility
- Windows Firewall logs (allowed/blocked traffic)
- SMB server logs
- DNS client logs
- Filtering Platform connection logs
- Remote session activity logs

---

### 🧠 Persistence & System Monitoring
- Task Scheduler logs
- Service installation tracking (7045)
- WMI activity logs
- Group Policy change logs
- DeviceGuard / system integrity logs

---

### 💾 Data Access & Device Control
- USB / removable storage logging
- File system auditing
- Registry modification tracking
- File share access monitoring

---

### 🛡️ Security Hardening
- Windows Defender operational logs enabled
- Audit policy hardening applied
- Security log size increased
- Log retention enabled

---

## 📊 SOC / DFIR Benefits

✔ Detect malware execution  
✔ Identify suspicious PowerShell activity  
✔ Track privilege escalation  
✔ Monitor lateral movement  
✔ Investigate forensic artifacts  
✔ Detect persistence techniques  

---

## 🧠 Real-World Use Cases

- SOC Analyst Lab Setup  
- Cybersecurity Projects  
- DFIR Investigations  
- Threat Hunting Labs  
- Blue Team Training  
- Red Team Detection Testing  

---

## ⚠️ Important Note

This script uses Windows native logging only.

For advanced threat visibility and deep attack detection, it is recommended to install Sysmon.

Sysmon provides detailed telemetry for process execution, network connections, registry modifications, and advanced attack techniques such as process injection, which are not captured by default Windows event logs.

---

## 🚀 How to Run

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Enable-Windows-Enterprise-Logging.ps1
