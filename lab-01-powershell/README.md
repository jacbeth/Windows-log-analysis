# Lab 01 – Suspicious PowerShell Execution



## Objective

Detect and analyse suspicious PowerShell activity using Sysmon on a Windows 11 endpoint.



## Environment

* Windows 11 (VirtualBox)
* Sysmon (Event ID 1)
* PowerShell 5.1

## 

## Path to Sysmon logs:

Application and Services Logs > Microsoft > Windows > Sysmon > Operational



## Initial Observation

Sysmon Event ID 1 triggered on powershell.exe
Encoded command present
Execution policy bypass observed



## Decoding Results

Base64 decoded Get-Date
No additional payloads observed



## Summary

Technique is suspicious
Payload is benign
Would escalate for further review in production

