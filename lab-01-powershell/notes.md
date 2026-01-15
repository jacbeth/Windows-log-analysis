#  Notes – Lab 01

## Powershell script to encode Get-Time 
- $cmd = 'Get-Process'       Defines the command to encode
- $bytes = [System.Text.Encoding]::UTF8.GetBytes($cmd)       Converts text into Unicode bytes
- $encoded = [Convert]::ToBase64String($bytes)        Conversion into a 64 bit string, used to hide commands
- $encoded        Prints to screen
- “C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe” -NoProfile -EncodedCommand RwBlAHQALQBEAGEAdABlAA==         Starts process, passes the argument and resultes in Sysmon Event ID 1

## Initial Observation
- Sysmon Event ID 1 triggered on powershell.exe
- Encoded command present
- Execution policy bypass observed

## Questions Asked
- Was this user-initiated or automated?
- What process spawned PowerShell?
- Is this normal admin behavior?

## Indicators of Compromise
-	Suspicious command line
-	Base64 payload
-	Process information
-	User account 

## Decoding Results
- Base64 decoded using UTF-16LE
- Decoded command: Get-Date
- No additional payloads observed

## Assessment
- Technique is suspicious
- Payload is benign
- Would escalate for deeper review in production

## Lessons Learned
- Get-Date – Powershell misinterpreted the bytes and decoded as Get-Datu
- PowerShell encoding issues can cause malformed commands. 
- Always verify PowerShell version and encoding



