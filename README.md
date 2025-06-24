# YARA-Rules-Repo
# 🔍 Complex YARA Rules for Detecting Common Malware Threats

This repository contains a curated set of advanced YARA rules designed to detect **10 of the most common and dangerous malware threats** seen in the wild. These rules are written for malware analysts, SOC teams, blue teamers, and incident responders who need fast, reliable detections during triage, hunting, and sandboxing.

---

## 🚀 Threats Covered

1. **Ransomware** – Detects files encrypted with known extensions (`.crypt`, `.locked`, etc.)
2. **Cobalt Strike** – Identifies beaconing and configuration artifacts
3. **Emotet** – Flags suspicious PowerShell and Outlook-based payloads
4. **Infostealers (RedLine, Vidar, Raccoon)** – Detects credential and wallet dump behavior
5. **Meterpreter Shellcode** – Matches known byte patterns of Metasploit payloads
6. **PowerShell Downloader** – Identifies obfuscated download-and-execute scripts
7. **Packed Malware (UPX)** – Flags binaries packed with UPX
8. **Keyloggers** – Detects artifacts of user activity logging
9. **Reverse Shells** – Flags suspicious socket and command execution behavior
10. **Malicious Excel Macros** – Detects auto-executing VBA with obfuscation

---

## 🧠 How to Use

### 🔧 Prerequisites
- Install [YARA](https://github.com/VirusTotal/yara)
- Linux or Windows system (or sandbox VM)
- Optional: [VirusTotal CLI](https://github.com/VirusTotal/vt-cli) for bulk scanning

### 📦 Clone the Repo
```bash
git clone https://github.com/username/complex-yara-threat-rules.git
cd complex-yara-threat-rules

yara -r complex_threats.yar /path/to/suspicious/files


 Disclaimer
This project is for educational and research purposes only.
Do not execute any malware samples without proper containment and safeguards.
Use in isolated VMs and sandbox environments.


