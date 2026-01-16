## Scenario
A user in the accounts department received an email with an
attachment titled "Invoice.html". The email stated a payment was overdue
and instructed the user to open the attachment to review invoice details. 
Upon opening the attachment, suspicious activity was observed on the
endpoint.

## Incident Timeline

- User received a phishing email containing an invoice-themed attachment
- User executed the attachment, triggering a PowerShell process
- PowerShell initiated an outbound HTTPS connection to an external domain
- A file named `invoice.html` was written to the user's Documents directory

## Detection 
- PowerShell was used instead of a browser to retrieve external content
- The file was written to a user-accessible directory
- Invoice-themed filenames are commonly used in phishing campaigns
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

## Analysis
This lab simulates phishing-style payload delivery using PowerShell. A PowerShell process was executed following user interaction with an invoice themed  phishing attachment which are commonly used in phishing campaigns. This resulted in outbound network communication and file creation.

## Response Actions
- Isolated the affected endpoint
- Reviewed Sysmon logs for related activity
- Confirmed no additional payloads were downloaded
- Recommended user awareness training and password reset

## Lessons Learned
This incident highlights the importance of monitoring scripting engines
such as PowerShell and correlating process execution with network activity
and file creation to detect phishing-based payload delivery.


