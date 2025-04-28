# Threat Hunt Event - Successful Brute Force Attack

![image](https://github.com/user-attachments/assets/10958483-cca1-4103-a29a-f41e736d111c)


**Threat Hunt Scenario:** Management has reported a large increase in failed login attempts across the enterprise environment. Logs have shown many virtual endpoints demonstrating this unusual behavior. The goal of this threat hunt is to investigate the existence of potential brute force attacks and to determine if there were any successful login attempts from malicious actors that need to be remediated.

## Threat Hunt Hypothesis
**Hypothesis:** Adversaries are conducting brute force attacks against internet-facing Azure virtual assets in order to gain unauthorized access without triggering account lockouts.

**Basis:**
- Management reports an increase in failed log on attemtps in cloud identities.
- MITRE ATT&CK Technique: T1110 (Brute Force)
  - MITRE ATT&CK sub-Technique: T1110.001 - Password Guessing
  - MITRE ATT&CK sub-Technique: T1110.002 - Password Cracking
  - MITRE ATT&CK sub-Technique: T1110.003 - Password Spraying
  - MITRE ATT&CK sub-Technique: T1110.004 - Credential Stuffing

**Expected Evidence:** 
- A high volume of failed log on attempts (greater than 10) from a single or multiple IPs across multiple user accounts.
- Login attempts clustered during late-night or weekend hours
- Login attempts from IP addresses geolocated outside expected business regions.

**Scope:** I will perform the threat hunt across all internet-facing cloud assets within the Azure enterprise environment utilizing Microsoft Sentinel and Microsoft Defender for Endpoint logs. I am specifically looking for activity related to multiple failed logon attempts, logins from abnormal geolocations, password guessing, password cracking, password spraying and credential stuffing.

**Priority:** High — potential unauthorized access to cloud assets.


## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Microsoft Sentinel
- Kusto Query Language (KQL)

##  High-Level Overview of Steps Taken During Hunt
Add links to each section/step of hunt!!
- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

```kql
DeviceFileEvents
| top 20 by Timestamp desc
```
```kql
DeviceNetworkEvents
| top 20 by Timestamp desc
```
```kql
DeviceProcessEvents
| top 20 by Timestamp desc
```
---



## Steps Taken During Hunt

### 1. Searched the `DeviceFileEvents` Table

I began my query by searching for any files that contained the string "tor" using the below query. The results showed that the user downloaded a TOR installer, ended up creating a TOR-related folder on their Desktop, and created a file called `TOR shopping lists.lnk` on `2025-04-25T17:44:06.1936918Z`. These TOR-related file events began on `2025-04-25T16:35:21.546641Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "ceh-tor1"
| where FileName contains "tor"
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/8daa6ff0-0828-4f9d-a429-a5a4ae47fb04)

---

### 2. Searched the `DeviceProcessEvents` Table

Since there where some kind of file that was created, I used the following query to determine what type of file had been created, the specific file path it was stored in, and which user account was responsible for its creation:

```kql
DeviceProcessEvents
| where DeviceName == "ceh-tor1"
| where ProcessCommandLine contains "TOR shopping lists"
| order by Timestamp desc' 
```
The results showed that a `TOR shopping lists.txt` file was created via notepad and stored on the VM's desktop by user `ceh2025` on `2025-04-25T17:51:09.028509Z`:

![image](https://github.com/user-attachments/assets/ec95ecc3-da9f-46c3-95d1-6b5335a99ecf)
![image](https://github.com/user-attachments/assets/763a1711-61b8-4a06-888f-c162bb8c57c6)

Additionally, I also searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on `DeviceFileEvent` logs, the user on the "ceh-tor1" device ran the file `tor-browser-windows-x86_64-portable-14.5.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "ceh-tor1"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, ActionType
```
The results showed that on `2025-04-25T17:43:37.8933806Z` the user ceh2025 downloaded and silently installed the TOR browser onto their virtual machine:

![image](https://github.com/user-attachments/assets/24b35bad-dd59-475a-88b3-91f2cb2cebed)


---

### 3. Searched the `DeviceProcessEvents` Table for Evidence of TOR Browser Launch

Searched for any evidence that the user "ceh2025" actually opened the TOR browser within their virtual machine. There was evidence that they did open it at `2025-01-08T16:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "ceh-tor1"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
The results showed that user ceh2025 did in fact launch the TOR browser from a folder on their desktop on `2025-04-25T17:44:26.1527056Z`. There were also several other instances of firefox being launched  from the same Desktop TOR folder.

![image](https://github.com/user-attachments/assets/5078cc14-0450-429c-a010-65916eaf0a33)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Next, I searched for any indication the TOR browser was used to establish a connection using any of the commonly known TOR ports using the following query:

```kql
DeviceNetworkEvents  
| where DeviceName == "ceh-tor1"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```

The results showed an initial successful connection taking place on `2025-04-25T17:44:37.9992858Z` by the user on the "ceh-tor1". The VM established a connection to the remote IP address `195.90.217.102` on port `443`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\ceh2025\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were also several other connections initiated by `tor.exe` to sites over port `9150` and `9001`.

![image](https://github.com/user-attachments/assets/441fad12-0669-4c6c-a889-1afb71e31914)


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-04-25T17:43:37.8933806Z`
- **Event:** The user "ceh2025" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\ceh2025\Downloads\tor-browser-windows-x86_64-portable-14.5.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-04-25T17:43:37.8933806Z`
- **Event:** The user "ceh2025" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-04-25T17:44:26.1527056Z`
- **Event:** User "ceh2025" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\ceh2025\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-04-25T17:44:37.9992858Z`
- **Event:** A network connection to IP `195.90.217.102` on port `443` by user "ceh2025" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\ceh2025\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-04-25T17:44:43.3142202Z` - Connected to `51.83.237.59` on port `9001`.
  - `2025-04-25T17:44:44.3257178Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "ceh2025" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-04-25T17:51:09.028509Z`
- **Event:** The user "ceh2025" created a file named `TOR shopping lists.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\ceh2025\Desktop\TOR shopping lists.txt`

---

## Summary

The user "ceh2025" on the "ceh-tor1" device initiated and completed the installation of the TOR browser. They then proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `TOR shopping lists.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `ceh-tor1` by the user `ceh2025`. The device was isolated, and the user's direct manager was notified.
