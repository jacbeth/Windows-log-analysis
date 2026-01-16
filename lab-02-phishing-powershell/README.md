# Phishing Detection Lab

├── README.md  
├── notes.md   
└── screenshots/
    ├── sysmon-event1-powershell.png
    ├── sysmon-event3-network.png
    └── sysmon-event11-file.png

## Objective
Simulate phishing-style payload delivery and analyse endpoint behaviour using
Sysmon telemetry.

## Scenario
A user received an invoice themed phishing email and interacted with the
attachment, resulting in suspicious activity on the endpoint.

## Tools Used
- Windows 11
- PowerShell
- Sysmon
- Event Viewer

## Detection Summary
PowerShell execution was observed initiating an outbound HTTPS connection and
creating a file in a user accessible directory.

## Evidence
- Sysmon Event ID 1: PowerShell process creation
- Sysmon Event ID 3: HTTPS connection to example.com
- Sysmon Event ID 11: File creation (invoice.html)
  
## MITRE ATT&CK
- T1566 – Phishing
- T1059.001 – PowerShell
- T1071.001 – Web Protocols
- T1036 – Masquerading


