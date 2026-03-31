# Threat Hunt Report: Azuki Series: Pt 1: Port of Entry

**Date of Report:** 2026-03-30

**Analyst:** Madelynn Charron

---

## Executive Summary
Azuki Import/Export experienced a targeted compromise resulting in the theft of sensitive supplier contracts and pricing data. The attacker gained initial access through a successful Remote Desktop Protocol (RDP) login using compromised credentials associated with the *kenji.sato* account.

Following initial access, the attacker established persistence, disabled security controls, and staged malware within a hidden directory. Credential dumping tools were used to escalate access, enabling lateral movement to additional systems. Sensitive data was collected, compressed, and exfiltrated via a Discord webhook. The attacker maintained command-and-control communication and attempted to evade detection by clearing event logs and creating a backdoor administrative account.

---

## Background

### **Situation**

Azuki Import/Export Trading Co. recently lost a six-year shipping contract after a competitor underbid them by exactly 3%. Shortly after, sensitive supplier contracts and pricing data were discovered on underground forums.

The precision of the underbid, combined with the data leak, strongly suggests a targeted compromise resulting in **intellectual property theft and data exfiltration**.

### **Company Overview**

- **Name:** Azuki Import/Export Trading Co.
- **Size:** 23 employees
- **Industry:** Shipping & logistics
- **Region:** Japan / Southeast Asia

### **Compromised System**

- **Hostname:** `AZUKI-SL`
- **Role:** IT Administrator Workstation
- **Significance:** High-value target with elevated privileges and access to sensitive business data

---

## Investigation Overview

### **Available Evidence**

- Microsoft Defender for Endpoint (MDE) telemetry, including:
    - Process events
    - Network activity
    - File activity
    - Registry modifications

### Tools & Environment

- Microsoft Defender for Endpoint (MDE)
- Kusto Query Language (KQL)
- Windows OS telemetry

### **Investigation Objectives**

The threat hunt aims to answer the following key questions:

- What was the **initial access vector**?
- Which **user account(s)** were compromised?
- What **data was accessed or stolen**?
- How was data **exfiltrated**?
- Did the attacker establish **persistence** within the environment?
- Is there evidence of **lateral movement** to other systems?

### **Hunt Scope & Initial Query**

The investigation focuses on activity originating from the compromised administrative workstation within the identified timeframe.
This query establishes a baseline of process activity to identify suspicious behavior, attacker tooling, and execution patterns throughout the intrusion lifecycle.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
```

---

## Attack Path Summary

- Initial access gained via exposed RDP using compromised credentials (*kenji.sato*)
- PowerShell used to download malicious script (`wupdate.ps1`)
- Defender protections disabled via registry modifications
- Malware staged in hidden directory (`C:\ProgramData\WindowsCache`)
- Payload downloaded using `certutil.exe`
- Persistence established via scheduled task and backdoor account
- Credentials dumped using renamed Mimikatz (`mm.exe`)
- Data collected and archived (`export-data.zip`)
- Data exfiltrated via Discord webhook
- Logs cleared to evade detection

---

## Investigation Timeline

| Time (UTC) | Event | Details |
| --- | --- | --- |
| 2025-11-19 00:57:18 | Initial Access (RDP) | Successful Remote Desktop login from external IP **88.97.178.12** using compromised account *kenji.sato* |
| 2025-11-19 18:49:27 | Defense Evasion | Windows Defender exclusions added for file extensions (.ps1, .exe, .bat) and Temp directory |
| 2025-11-19 18:49:48 | Execution | PowerShell used with `ExecutionPolicy Bypass` to download `wupdate.ps1` from attacker server |
| 2025-11-19 19:04:01 | Discovery | `arp.exe -a` executed to enumerate internal network devices |
| 2025-11-19 19:05:33 | Defense Evasion | Hidden staging directory `C:\ProgramData\WindowsCache` created using `attrib` |
| 2025-11-19 19:06:58 | Payload Delivery | `certutil.exe` used to download malicious `svchost.exe` from **78.141.196.6** |
| 2025-11-19 19:07:47 | Persistence | Scheduled task **"Windows Update Check"** created to execute malware daily as SYSTEM |
| 2025-11-19 19:08:26 | Credential Access | Renamed Mimikatz (`mm.exe`) executed with `sekurlsa::logonpasswords` |
| 2025-11-19 19:08:58 | Collection | Sensitive data compressed into `export-data.zip` in staging directory |
| 2025-11-19 19:09:21 | Exfiltration | Data exfiltrated via `curl.exe` to Discord webhook |
| 2025-11-19 19:09:48 | Persistence (Alt Access) | New admin account **support** created and added to Administrators group |
| 2025-11-19 19:10:42 | Lateral Movement | RDP connection initiated to internal host **10.1.0.188** using `mstsc.exe` |
| 2025-11-19 19:11:04 | Command & Control | Compromised host communicates with C2 server **78.141.196.6** over port 443 |
| 2025-11-19 19:11:39 | Anti-Forensics | Windows event logs cleared using `wevtutil`, starting with Security log |

---

## Flags (1-20)

## 🚩 Flag 1: INITIAL ACCESS - Remote Access Source

**Objective:** Remote Desktop Protocol connections leave network traces that identify the source of unauthorized access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

**Question:** Identify the source IP address of the Remote Desktop Protocol connection?

**Flag Value:** 88.97.178.12

**Date / Time Detected:** 2025-11-19T00:57:18.3409813Z (12:57:18 AM)

**Query Used:**

```kql
DeviceLogonEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName contains "azuki"
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| where RemoteIP != ""
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteIPType, LogonType
| sort by Timestamp asc
```

**Evidence:**

<img width="1154" height="189" alt="image" src="https://github.com/user-attachments/assets/53cd2725-61cd-4ff5-8ab3-1e578f9427f2" />

**Key Observations:**

- Successful **RemoteInteractive (RDP)** logon observed
- Source IP: **88.97.178.12** (public IP)
- Authentication succeeded on multiple Azuki devices using kenji.sato account
- Activity occurred outside normal business context (early hours)
- External IP indicates access originated from outside corporate network

**Analysis:**

The Remote Desktop logon from a public IP address indicates that the attacker gained initial access via exposed or accessible RDP services. The use of valid credentials suggests either credential theft or brute force authentication. Since the connection originated externally and successfully authenticated, this confirms a compromised account was leveraged for initial access.

**MITRE ATT&CK Mapping:**
| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0001 | Initial Access |
| Technique | T1078 | Valid Accounts |


## 🚩 Flag 2: INITIAL ACCESS - Compromised User Account

**Objective:** Identifying which credentials were compromised determines the scope of unauthorized access and guides remediation efforts including password resets and privilege reviews.

**Question:** Identify the user account that was compromised for initial access?

**Flag Value:** kenji.sato

**Date / Time Detected:** 2025-11-19T00:57:18.3409813Z (12:57:18 AM)

**Key Observations:**

- Account kenji.sato used during the suspicious RDP session
- Same timestamp as initial access event
- Account successfully authenticated from external IP
- Indicates legitimate credentials were used

**Analysis:**

The attacker leveraged the kenji.sato account to gain access via RDP. This account becomes the initial foothold for all subsequent attacker activity.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0001 | Initial Access |
| Technique | T1078 | Valid Accounts |
