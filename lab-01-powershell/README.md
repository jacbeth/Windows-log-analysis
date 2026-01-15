# Lab 01 – Suspicious PowerShell Execution  📄 [Notes](notes.md)

# Objective
Detect and analyse suspicious PowerShell activity using Sysmon on a Windows 11 endpoint. The  -EncodedCommand flag, is a technique associated with obfuscation and malicious script execution. The objective was to validate Sysmon logging and practice SOC triage skills in a controlled lab environment. (Sysmon provides much more focused telemetry than Windows Event Viewer.)

# Environment
- Windows 11 (VirtualBox)
- Sysmon (Event IDs 1, 3)
- PowerShell 5.1

# Path to Sysmon logs:
Application and Services Logs > Microsoft > Windows > Sysmon > Operational

# Detection
A PowerShell process was observed executing an encoded command with execution
policy bypass.
•	Detection Source: Sysmon (Event ID 1 – Process Creation)
•	Endpoint: Windows 11 VM
•	User Account: Local user
•	Process: powershell.exe
•	Command Line: Included the -EncodedCommand parameter

# Events
Sysmon logged the following fields:
•	Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
•	CommandLine: powershell.exe -NoProfile -EncodedCommand <Base64String>
•	ParentImage: cmd.exe
•	User: Local user account
•	Hashes: SHA256 hash of PowerShell executable
•	ProcessGuid: Unique identifier for correlation
The Base64 string decoded to the benign command: Get-Date

# Analysis
Encoded PowerShell commands are commonly used by attackers to evade detection.
Although the decoded command was benign (`Get-Date`), the execution technique
matches real-world malware behavior.

# Indicators of Compromise
•	Suspicious command line
•	Base64 payload
•	Process information
•	User account 

# MITRE ATT&CK
- T1059.001 – PowerShell
- T1027 – Obfuscated/Encoded Files

# Recommendations
•	Create a SIEM detection rule to alert on any use of -EncodedCommand.
•	Add enrichment to decode Base64 automatically during triage.
•	Monitor for repeated encoded PowerShell executions, especially from unusual parent processes.
•	Correlate with network and registry events to identify follow up malicious behaviour.

# Conclusion
This activity would be classified as suspicious and warrant further investigation
in a production SOC environment.
