# Lab 2: Phishing Email Payload Delivery



## Objective

Simulate a phishing email scenario that results in PowerShell based payload

delivery and investigate the activity using Sysmon logs.



## Scenario

A user in the Accounts department received an email containing an attachment

titled "Invoice.html". After the attachment was opened, suspicious

activity was observed on the endpoint.



## Tools Used

\- Windows 11

\- PowerShell

\- Sysmon

\- Event Viewer



\# Detection Summary

Investigation identified PowerShell execution initiating outbound HTTPS

communication and writing a file to a user accessible directory, consistent

with phishing based payload delivery.

