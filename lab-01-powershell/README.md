# Lab 01 – Suspicious PowerShell Execution 

## Objective
Detect and analyse suspicious PowerShell activity using Sysmon on a Windows 11 endpoint. The  -EncodedCommand flag, is a technique associated with obfuscation and malicious script execution. The objective was to validate Sysmon logging and practice SOC triage skills in a controlled lab environment. (Sysmon provides much more focused telemetry than Windows Event Viewer.)

## Environment
- Windows 11 (VirtualBox)
- Sysmon (Event ID 1)
- PowerShell 5.1

## Path to Sysmon logs:
Application and Services Logs > Microsoft > Windows > Sysmon > Operational

## Detection
A PowerShell process was observed executing an encoded command with execution
policy bypass.
-	Detection Source: Sysmon (Event ID 1 – Process Creation)
-	Endpoint: Windows 11 VM
-	User Account: windows11 local account
-	Process: powershell.exe
-	Command Line: Included the -EncodedCommand parameter

## Events
Sysmon logged the following fields:
-	Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
-	CommandLine: “C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe” -NoProfile -EncodedCommand RwBlAHQALQBEAGEAdABlAA==
-	ParentImage: powershell.exe
-	User: Local user account
-	Hashes: SHA256=6A7SF3DDA06163BB6253E4F82A283E184D70755C067633C4190FBFF64F0BAECDIMPH9F91C97560360686D37B0E311BB88D64

The Base64 string decoded to the benign command: Get-Date

## Analysis
Encoded PowerShell commands are commonly used by attackers to evade detection.
Although the decoded command was benign (`Get-Date`), the execution technique
matches real-world malware behavior.

## MITRE ATT&CK
- T1059.001 – PowerShell
- T1027 – Obfuscated/Encoded Files

## Recommendations
-	Create a SIEM detection rule to alert on any use of -EncodedCommand.
-	Add enrichment to decode Base64 automatically during triage.
-	Monitor for repeated encoded PowerShell executions, especially from unusual parent processes.
-	Correlate with network and registry events to identify follow up malicious behaviour.

## Conclusion
This activity would be classified as suspicious and warrant further investigation
in a production SOC environment.
