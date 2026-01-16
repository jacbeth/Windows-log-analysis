## Scenario
A user in the accounts department received an email with an
attachment titled "Invoice.html". The email stated a payment was overdue
and instructed the user to open the attachment to review invoice details. 
Upon opening the attachment, suspicious activity was observed on the
endpoint.

## Detection 
- PowerShell was used instead of a browser to retrieve external content
- The file was written to a user accessible directory
- Invoice themed filenames are commonly used in phishing campaigns
- Outbound network traffic originated from a scripting engine

## Evidence
## Event ID 1 — Process Creation
Parent process
Image: 
CMD: 

## Event ID 3 — Network Connection
•	Image: powershell.exe
•	DestinationHostname: example.com
•	DestinationPort: 443
•	Protocol: tcp

## Event ID 11 — File Creation
•	Image: powershell.exe
•	TargetFilename:
•	File location user folders – phishing indicator

## MITRE ATT&CK Analysis

### T1566 – Phishing (Initial Access)
Intial access  was simulated as a phishing email containing an
invoice themed attachment. User interaction with the attachment represents
a common phishing scenario where execution occurs only after the user opens
the file or clicks a link.

### T1059.001 – Command and Scripting Interpreter: PowerShell (Execution)
Sysmon Event ID 1 shows the execution of `powershell.exe` with a scripted
command used to retrieve external content. The command line indicates intentional execution rather than background
system activity.

### T1071.001 – Application Layer Protocol: Web Protocols (Command and Control)
Sysmon Event ID 3 confirms outbound HTTPS communication to an external domain.
Attackers commonly use standard web protocols such as HTTPS to blend in with
legitimate traffic and evade basic network filtering.

### T1036 – Masquerading (Defense Evasion)
The downloaded file was named `invoice.html` and written to a user accessible directory. Invoice related filenames are a
common masquerading technique used in phishing and increase the likelihood of user interaction.

## Analysis
This lab simulates phishing-style payload delivery using PowerShell. Following
user interaction with an invoice themed attachment, a PowerShell process was
executed, resulting in outbound network communication and file creation. The
observed behavior aligns with common phishing and initial payload delivery
techniques.

## Response Actions
- Isolated the affected endpoint
- Reviewed Sysmon logs for related activity
- Confirmed no additional payloads were downloaded
- Recommended user awareness training and password reset

## Lessons Learned
This incident highlights the importance of monitoring scripting engines
such as PowerShell and correlating process execution with network activity
and file creation to effectivly detect phishing based payload delivery.


