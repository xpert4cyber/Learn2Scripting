# 🛡️ Enterprise Windows Logging Hardening Script (SOC / DFIR Ready)

🚨 Transform any Windows system into a **security monitoring-ready machine** with enterprise-grade logging configuration for SOC, DFIR, and Threat Hunting.

---

## 🔥 What This Project Does

Modern attacks are stealthy:
- Fileless malware
- PowerShell abuse
- RDP brute force
- Lateral movement
- Persistence via registry/tasks
- USB data theft

👉 Default Windows logging is NOT enough for detection.

This script enables **advanced Windows security telemetry** to improve visibility and investigation capability.

---

## ⚙️ Features Enabled

### 🔐 Authentication Monitoring
- Logon / Logoff tracking (4624 / 4625)
- Account lockout events
- Kerberos authentication logs
- NTLM authentication logs
- RDP session tracking
- Remote access (WinRM)

---

### ⚙️ Process Execution Tracking
- Process creation (4688)
- Process termination
- Command-line auditing enabled
- PowerShell Script Block Logging (4104)
- PowerShell Module Logging
- PowerShell Transcription logs

---

### 🌐 Network Activity Visibility
- Windows Firewall logs (allowed / blocked traffic)
- SMB server logs
- DNS client logs
- Filtering Platform connection logs
- Remote session activity tracking

---

### 🧠 Persistence & System Monitoring
- Task Scheduler logs
- Service installation tracking (7045)
- WMI activity logs
- Group Policy changes
- DeviceGuard / system integrity logs

---

### 💾 Data Access & Device Control
- USB / removable storage tracking
- File system auditing
- Registry modification logging
- File share access monitoring

---

### 🛡️ Security Hardening
- Windows Defender logs enabled
- Audit policy hardening applied
- Log size increased
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
- DFIR Investigation Environments  
- Threat Hunting Labs  
- Blue Team Training  
- Red Team Detection Testing  

---

## ⚠️ Important Note

This script uses **Windows native logging only**.

For advanced attack visibility, install:

👉 :contentReference[oaicite:0]{index=0}

(Sysmon adds deep process, network, and injection-level telemetry.)

---

## 🚀 How to Run

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Enable-Windows-Enterprise-Logging.ps1
