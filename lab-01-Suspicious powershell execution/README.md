# Lab 01 – Suspicious PowerShell Execution

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

