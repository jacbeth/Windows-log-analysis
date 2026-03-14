# Lab 01 – Suspicious PowerShell Execution

![jacbeth Labs](https://img.shields.io/badge/jacbeth%20Labs-Cybersecurity-%230A0A0A)
![Status: In Progress](https://img.shields.io/badge/Status-In%20Progress-%23FFC300)
![Category: SOC Lab](https://img.shields.io/badge/Category-SOC%20Lab-%230078D6)
![Platform: Windows](https://img.shields.io/badge/Platform-Windows-%230078D6)
![Tool: TBD](https://img.shields.io/badge/Tool-TBD-%238A2BE2)
![Detection: TBD](https://img.shields.io/badge/Detection-TBD-%23FF8800)
![MITRE: TBD](https://img.shields.io/badge/MITRE-TBD-%23C0392B)

## 📝 Objective

Detect and analyse suspicious PowerShell activity using Sysmon on a Windows 11 endpoint.

## 🧪 Environment

- Windows 11 (VirtualBox)
- Sysmon (Event ID 1 – Process Creation)
- PowerShell 5.1

*Sysmon Log Path:*

Application and Services Logs > Microsoft > Windows > Sysmon > Operational

## 🔍 Initial Observation

- Sysmon Event ID 1 triggered on `powershell.exe`
- Encoded command present
- Execution policy bypass observed

## 🧬 Decoding Results
- Base64 decoded to: `Get-Date`
- No additional payloads observed

## 🧠 Analyst Summary

- **Technique:** Suspicious  
- **Payload:** Benign  
- **Action:** Would escalate for further review in a production SOC due to:
- Encoded command usage  
- Execution policy bypass  
- Potential for LOLBins abuse  

## 🧩 MITRE ATT\&CK Mapping

- **T1059.001 – PowerShell**
- **T1027 – Obfuscated/Encoded Files**

## 📁 Repository Structure

Lab01-Suspicious-PowerShell

│

├── README.md

├── Notes.md

└── /screenshots/

