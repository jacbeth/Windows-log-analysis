# Lab 2 – Suspicious Email Payload Delivery

---

## 📝 Objective
Simulate a phishing email scenario that results in PowerShell‑based payload delivery and investigate the activity using Sysmon telemetry.

---

## 🧪 Scenario Summary
A user received an email containing an attachment titled **Invoice.html**.  
After opening the attachment, suspicious behaviour was observed:

- PowerShell execution  
- Outbound HTTPS communication  
- File creation in a user directory  

This behaviour is consistent with phishing based initial access.

---

## 🔍 Detection Summary
Sysmon logs revealed:

- PowerShell retrieving external content  
- Network connections initiated by a scripting engine  
- File creation linked to the executed script  

These indicators align with phishing payload delivery techniques.

---

## 🧩 MITRE ATT&CK Mapping
- **T1566 – Phishing**  
- **T1059.001 – PowerShell**  
- **T1071.001 – Web Protocols**  
- **T1036 – Masquerading**

---

## 📁 Repository Structure
```text
/Lab02-Phishing-Email/
│
├── README.md
├── Notes.md
└── /screenshots/
      ├── 01_phishing-execution.png
      ├── 02_phishing_invoice.jpg
      ├── 03_sysmon_event1_process_creation.png
      └── 04_sysmon_event3_network_connection.png
