# Threat Hunt Event - Successful Brute Force Attack

![image](https://github.com/user-attachments/assets/10958483-cca1-4103-a29a-f41e736d111c)


## 🕵🏽 Threat Hunt Scenario:
Management has reported a large increase in failed login attempts across the enterprise environment. Logs have shown many virtual endpoints demonstrating this unusual behavior. The goal of this threat hunt is to investigate the existence of potential brute force attacks and to determine if there were any successful login attempts from malicious actors that need to be remediated.

## 🤔 Threat Hunt Hypothesis
**Hypothesis:** Adversaries are conducting brute force attacks against internet-facing Azure virtual assets in order to gain unauthorized access without triggering account lockouts.

**Scope:** I will perform the threat hunt across all internet-facing cloud assets within the Azure enterprise environment utilizing Microsoft Sentinel and Microsoft Defender for Endpoint logs. I am specifically looking for activity related to multiple failed logon attempts, logins from abnormal geolocations, password guessing, password cracking, password spraying and credential stuffing.

**Priority:** High — potential unauthorized access to cloud assets.

**Basis:**
- Management reports an increase in failed log on attemtps in cloud identities.
- MITRE ATT&CK Technique: T1110 (Brute Force)
  - MITRE ATT&CK sub-Technique: T1110.001 - Password Guessing
  - MITRE ATT&CK sub-Technique: T1110.003 - Password Spraying
  - MITRE ATT&CK sub-Technique: T1110.004 - Credential Stuffing

**Expected Evidence:** 
- A high volume of failed log on attempts (greater than 10) from a single or multiple IPs across multiple user accounts.
- Login attempts clustered during late-night or weekend hours
- Login attempts from IP addresses geolocated outside expected business regions.


## ⚙️ Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Microsoft Sentinel
- Kusto Query Language (KQL)
- VirusTotal

## ⛰️ High-Level Overview of Steps Taken During Hunt
- **Check `SecurityEvents`** for Greater than 10 failed Logon Attempts
- **Check `SecurityEvents`** for Successful Login Attempts from Malicious IPs
- **Designed Remediation Steps for Review**

---

## 🧩 Steps Taken During Hunt

### 1. Searched the `SecurityEvents` Table for Greater than 10 failed Logon Attempts

I began my query by using the `SecurityEvent` to look for any failed logon attempts (greater than 10) in the last 7 days by searching for Event ID 4625 (Account failed to log on). In addition, I included for the results to list the account names, IP addresses/ports, failure reason, how many times the event occured and logon types for any returned results:

**Query used to locate events:**
```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(7d)
| summarize FailedAttempts = count(), 
            StartTime = min(TimeGenerated), 
            EndTime = max(TimeGenerated)
    by AccountName, IpAddress, Computer
| where FailedAttempts > 10
| project StartTime, EndTime, AccountName, IpAddress, Computer, FailedAttempts
| order by FailedAttempts desc
```

The results yielded 309 failed logon events on the `windows-target-1` endpoint in the past 7 days, with many of them having thousands of failed logon attempts:

![image](https://github.com/user-attachments/assets/e9cf38fa-ab07-4539-9ade-fd3f1eba0472)

Additionally I ran the top 3 IP addresses with the highest logon attempts through VirusTotal, and they all came back flagged as malicious. It is also important to note that these IP addresses are registered in foreign countries such as Russia, United Arab Emirates, and Peru (company is based in USA):

![image](https://github.com/user-attachments/assets/4b7f78f2-a6ea-4792-9fb1-ab9b890db661)

![image](https://github.com/user-attachments/assets/5788ec5f-00de-4833-ab8a-d57d4cfd5ac4)

![image](https://github.com/user-attachments/assets/52c1c6c2-24e7-45ae-99a4-cc9fa9523220)


---

### 2. Searched the `SecurityEvents` Table for Successful Login Attempts from Malicious IPs

Due to the sheer number of failed logon attempts in just a 7 day period, it is safe to assume that some kind of brute force attack has been in play. Next, we are going to determine whether any of the malicious IP addresses actually successfully logged into the `windows-target-1` during their brute force attacks. To do this, I first want to get a list of all suspicious IP's that meet this criteria using the following KQL query in Sentinel:

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(7d)
| where Computer == "windows-target-1"
| summarize FailedAttempts = count()
    by IpAddress
| where FailedAttempts > 10
| order by FailedAttempts desc
```
The results show there were 311 unique IP addresses that accumulated more than 10 failed logon attempts in the last 7 days:

![image](https://github.com/user-attachments/assets/91834a79-5dc7-480d-bda7-f3f701b3f364)

Now that I have identified these IP addresses, I decided to search the Sentinel logs to see if any one of these IPs successfully logged into our endpoint using the following KQL query:

**Query used to locate event:**

```kql
SecurityEvent
| where EventID == 4624  // Successful logon
| where TimeGenerated > ago(7d)
| where Computer == "windows-target-1"
| project TimeGenerated, IpAddress, AccountName, Computer, LogonType
| order by TimeGenerated asc
```

The results show that there have been 1000 successful login attempts. Out of the 1000, none of the suspicious IP addresses showed to have successfully logged onto `windows-target-1`

![image](https://github.com/user-attachments/assets/29a02d33-f2e9-4e20-b6ec-09a216c1206b)


---

### 3. Incident Response and Remediation

We have verified that there have been multiple brute force attacks from multiple malicious IPs and geographical locations. There were no successful logons from these attacks, therefore, our next goal is to develop remediation steps and forward these recommendations to the appropriate management/stakeholders so that they can be approved for implementation.

There are three main remediation steps that can implement right away:

1. Block all verified malicious IP addresses that were logged in Sentinel.

2. Disable any unnecessary remote services that can increase the attack surface. These services can include:
- SSH (22/TCP)
- Telnet (23/TCP)
- FTP (21/TCP)
- NetBIOS / SMB / Samba (139/TCP & 445/TCP)
- LDAP (389/TCP)
- Kerberos (88/TCP)
- RDP / Terminal Services (3389/TCP)
- HTTP/HTTP Management Services (80/TCP & 443/TCP)
- MSSQL (1433/TCP)
- Oracle (1521/TCP)
- MySQL (3306/TCP)
- VNC (5900/TCP)
- SNMP (161/UDP and 162/TCP/UDP)

3. Enable an account lockout policy for this device after 5 failed logon attempts within the Microsoft Defender for Endpoint (EDR)

---

## Summary

Within the last 7 days, the device `windows-target-1` had incurred over 27,000 failed logon attempts. While investigation, many of these source IPs were from foreign countries and were flagged as malicious by VirustTotal. However, despite the high amounts of attempts, there is no record of a successful log in attempt. Remediation steps have been created and submitted to management for review.

---


