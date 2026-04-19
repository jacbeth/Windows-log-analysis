### Suspicious PowerShell Execution
#### Objective
Detect and analyse suspicious PowerShell activity using Sysmon on a Windows 11 endpoint.

#### Environment
- Windows 11 (VirtualBox)
- Sysmon (Event ID 1 – Process Creation)
- PowerShell 5.1

#### Initial Observation
- Sysmon Event ID 1 triggered on `powershell.exe`, encoded command present, execution policy bypass observed

#### Decoding Results
- Base64 decoded to: `Get-Date`, no additional payloads observed

#### Summary
- **Technique:** Suspicious  
- **Payload:** Benign  
- **Action:** Would escalate for further review in a production SOC due to: Encoded command usage, execution policy bypass and potential for LOLBins abuse  
NB: A LOLBIN (short for Living Off the Land Binary) is a legitimate, built in system tool that attackers often use for malicious activity, such as such as PowerShell, certutil, and rundll32

#### MITRE ATT&CK Mapping
- **T1059.001 – PowerShell** and **T1027 – Obfuscated/Encoded Files**


