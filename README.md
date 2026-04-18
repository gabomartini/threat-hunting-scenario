<p align="center">
  <img src="https://github.com/user-attachments/assets/638a1363-432a-441e-90fb-f20a597ca7ae" width="150" height="auto">
    <h1 align="center">Threat Hunt Report: Unauthorized TOR Usage</h1>
</p>

---

# Table of Contents

- [Platforms and Languages Leveraged](#platforms-and-languages-leveraged)
- [Scenario](#scenario)
- [Controlled Lab Steps to Generate Logs and IoCs](#controlled-lab-steps-to-generate-logs-and-iocs-indicators-of-compromise)
- [Tables Used to Detect IoCs](#tables-used-to-detect-iocs)
- [Steps Taken](#steps-taken)
- [Chronological Event Timeline](#chronological-event-timeline)
- [Summary](#summary)
- [Response Taken](#response-taken)

---

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

---

## Controlled Lab Steps to Generate Logs and IoCs (Indicators of Compromise):
1. Download the TOR browser installer.
2. Install it silently.
3. Open the TOR browser from the folder on the desktop.
4. Connect to TOR and browse a few sites.
6. Create a text file on desktop.
7. Delete the file.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "Arcaico" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-03-23T11:49:22Z`. These events began at `2026-03-23T11:38:32Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-03-23T00:00:00) .. datetime(2026-03-24T00:00:00))
| where FileName startswith "tor" and DeviceName == "fuente-1"
| project Timestamp, ActionType, FileName, FolderPath
| sort by Timestamp asc
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/bf5b7064-74a8-4650-84f3-aa39de5eea79" width="auto" height="auto">
</p>

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64". Based on the logs returned, at `2026-03-23T11:41:14Z`, an employee on the "fuente-1" device ran the file `tor-browser-windows-x86_64-portable-15.0.7.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-03-23T00:00:00) .. datetime(2026-03-24T00:00:00))
| where ProcessCommandLine contains "tor-browser-windows-x86_64" and DeviceName == "fuente-1"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| sort by Timestamp asc
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/ef55e22e-851c-4047-83cf-d8c3c25dc2c2" width="auto" height="auto">
</p>

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "Arcaico" actually opened the TOR browser. There was evidence that they did open it at `2026-03-23T11:41:52Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-03-23T00:00:00) .. datetime(2026-03-24T00:00:00))
| where ProcessCommandLine has_any("tor.exe","firefox.exe") and DeviceName == "fuente-1"
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine
| sort by Timestamp asc
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/bd61e67d-617c-42b6-917f-b5ff1ad09d9e" width="auto" height="auto">
</p>

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-03-23T11:42:31Z`, an employee on the "fuente-1" device successfully established a connection to the remote IP address `217.123.118.44` on port `9001`. The connection was initiated by the process `tor.exe`. There was another connection over port `9150`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-03-23T00:00:00) .. datetime(2026-03-24T00:00:00))
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe") and DeviceName == "fuente-1"
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150) //specific network ports typically associated with Tor traffic
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp asc
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/152b70e6-ffcb-43d4-9b45-546c63e77ea5" width="auto" height="auto">
</p>

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer
- **Timestamp:** 2026-03-23T11:38:32Z
- **Event:** The user "Arcaico" downloaded the TOR Browser portable installer to the Downloads folder.
- **Action:** File creation detected (FileCreated).
- **File Path:** C:\Users\Arcaico\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe

### 2. Process Execution - Silent Installation
- **Timestamp:** 2026-03-23T11:41:14Z
- **Event:** The installer was executed using the /S flag, indicating a silent background installation without user prompts.
- **Action:** Process creation detected (ProcessCreated).
- **Command:** tor-browser-windows-x86_64-portable-15.0.7.exe /S

### 3. File Creation - TOR Executable
- **Timestamp:** 2026-03-23T11:41:25Z
- **Event:** As a result of the silent installation, the core TOR engine executable (tor.exe) was created on the disk.
- **Action:** File creation detected via the installer process.
- **Initiating Command:** "tor-browser-windows-x86_64-portable-15.0.7.exe" /S

### 4. Process Execution - TOR Browser Launch
- **Timestamp:** 2026-03-23T11:41:52Z
- **Event:** The TOR Browser (running as firefox.exe) was launched by the user "Arcaico." This initiated the specialized browser interface.
- **Action:** Process creation detected.
- **Command:** firefox.exe

### 5. Network Connection - TOR Relay Activity
- **Timestamp:** 2026-03-23T11:42:31Z
- **Event:** The tor.exe process established an outbound connection to a remote IP on port 9001, confirming the browser successfully connected to the TOR network.
- **Action:** Network connection detected.
- **Details:** Remote IP 217.123.118.44 on Port 9001 (Tor Relay).

### 6. File Modification - Suspicious Shopping List
- **Timestamp:** 2026-03-23T11:49:22Z
- **Event:** After approximately 7 minutes of browsing activity, a text file named "tor-shopping-list" was modified on the desktop, likely containing notes from the session.
- **Action:** File modification detected (FileModified).
- **File Path:** C:\Users\Arcaico\Desktop\tor-shopping-list.txt.txt

---

## Summary

The user "Arcaico" on the "fuente-1" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `fuente-1` by the user `Arcaico`. The device was isolated, and the user's direct manager was notified.

---
