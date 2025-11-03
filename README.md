# 🔍 Port Scan Investigation with Microsoft Defender for Endpoint (MDE)

## 🎯 Objective

Demonstrate how to investigate and confirm suspicious network activity — specifically **port scanning** — inside an enterprise environment using **Microsoft Defender for Endpoint (MDE)** advanced hunting capabilities.

---

## 🧱 Environment Overview

In this demo, I use a **Windows 11 24H2** virtual machine named **awl4114awl-mde**, assigned:

* **Public IP:** `20.57.46.8`
* **Private IP:** `10.0.0.109`
* **Region:** East US 2
* **Instance:** Standard DS1 v2
* **Network:** `Cyber-Range-Subnet`
* **Subscription:** `LOG(N) Pacific – Cyber Range 1`

The **Cyber Range** is a shared, cloud-based training environment designed to simulate enterprise networks and attack scenarios. Each participant operates within a common virtual network where simulated threats can safely occur and be detected without risk to production systems.

This VM represents an internal workstation onboarded to **Microsoft Defender for Endpoint (MDE)**.
I used a controlled PowerShell script to simulate internal reconnaissance (port scanning), then used **KQL (Kusto Query Language)** within MDE Advanced Hunting to detect, analyze, and attribute the behavior.

---

## ⚙️ Step 1 | Generate the Activity

I began by running a PowerShell port-scanning script to intentionally create suspicious network traffic.

```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1' -OutFile 'C:\programdata\portscan.ps1'; 
cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1
```

This script attempts multiple TCP connections across common ports (21–8443) targeting other internal IPs — simulating **lateral movement** or **reconnaissance** activity.

If this were a real network, this pattern would be a red flag for internal threat actor behavior.

<p align="left">
  <img src="images/Screenshot 2025-11-03 131308.png" width="750">
</p>

---

## 📈 Step 2 | Identify the Anomaly (Data Analysis)

Using **DeviceNetworkEvents**, I queried failed connections to detect anomalous outbound traffic:

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where RemoteIP != "127.0.0.1" and RemoteIP != "::1"
| summarize FailedConnections = count() by DeviceName, RemoteIP
| order by FailedConnections desc
```

<p align="left">
  <img src="images/Screenshot 2025-11-03 110650.png" width="450">
</p>

The query revealed that **awl4114awl-mde** had multiple failed connection attempts to `10.0.0.5`, which strongly indicates scanning behavior.

Next, I summarized total failed attempts by **LocalIP** to confirm which host originated the activity:

```kql
let IPInQuestion = "10.0.0.109";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP
| order by FailedConnectionsAttempts desc
```

<p align="left">
  <img src="images/Screenshot 2025-11-03 110705.png" width="750">
</p>

Result: The VM `10.0.0.109` was confirmed as the source of the repeated failed connections.

Finally, I listed every individual failed outbound connection in order to view the full scan pattern:

```kql
let IPInQuestion = "10.0.0.109";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```


<p align="left">
  <img src="images/Screenshot 2025-11-03 110719.png" width="750">
</p>

<p align="left">
  <img src="images/Screenshot 2025-11-03 072538.png" width="750">
</p>

This pattern clearly shows multiple sequential port attempts across the same destination (`10.0.0.5`), confirming active port scanning.

---

## 🧠 Step 3 | Correlate Behavior (Investigation Phase)

With the network anomaly confirmed, I pivoted to **DeviceProcessEvents** to identify which process triggered it:

```kql
let VMName = "awl4114awl-mde";
let specificTime = datetime(2025-11-03);
DeviceProcessEvents
| where DeviceName == VMName
| project DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

<p align="left">
  <img src="images/Screenshot 2025-11-03 134511.png" width="750">
</p>

At first, the results contained mostly normal system processes (e.g., `svchost.exe`, `TiWorker.exe`), but after filtering for PowerShell executions with policy bypass or web requests, I found the key event.

Searching specifically for `-ExecutionPolicy Bypass` isolated the malicious command chain.

<p align="left">
  <img src="images/Screenshot 2025-11-03 114756.png" width="750">
</p>

---

## 🧩 Step 4 | Confirm Execution Source

After expanding the time window, I refined the query to isolate all **PowerShell commands** that bypassed execution policy — a common indicator of scripted or potentially malicious automation.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-ExecutionPolicy", "Invoke-WebRequest", "Bypass", ".ps1")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

<p align="left">
  <img src="images/Screenshot 2025-11-03 125013.png" width="750">
</p>

The **Defender timeline** displayed clear spikes for **awl4114awl-mde** correlating with PowerShell execution events, confirming a link between the process and the network anomaly.


<p align="left">
  <img src="images/Screenshot 2025-11-03 125026.png" width="750">
</p>

### 🧩 Key Evidence

This query surfaced the **exact command** responsible for executing the scan:

```
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1
```

**Process chain confirmed:**

```
cmd.exe → powershell.exe → portscan.ps1
```

Cross-referencing timestamps with `DeviceNetworkEvents` verified that this activity directly preceded the burst of failed TCP connections — confirming the port-scanning event originated from this command.

### ✅ Attribution

The suspicious network behavior originated from:

* **Host:** awl4114awl-mde (10.0.0.109 / 20.57.46.8)
* **Process:** powershell.exe
* **Parent:** cmd.exe
* **Script:** C:\programdata\portscan.ps1

By correlating **network telemetry** and **process telemetry**, I established a clear cause-and-effect relationship — completing the **Investigation Phase**.

---

## 🧾 Step 5 | Findings Summary

| Category               | Observation / Evidence                                                               |
| ---------------------- | ------------------------------------------------------------------------------------ |
| **Network Scanning**   | Multiple failed TCP connections from `10.0.0.109` to `10.0.0.5` across ports 21–8443 |
| **Source Host**        | `awl4114awl-mde`                                                                     |
| **Initiating Process** | `powershell.exe` with `-ExecutionPolicy Bypass`                                      |
| **Parent Process**     | `cmd.exe`                                                                            |
| **Script Executed**    | `C:\programdata\portscan.ps1`                                                        |
| **Detection Method**   | MDE Advanced Hunting (`DeviceNetworkEvents` + `DeviceProcessEvents`)                 |

---

## 🧩 Conclusion

By combining **network logs** (`DeviceNetworkEvents`) with **process logs** (`DeviceProcessEvents`), I was able to trace a complete simulated attack from detection to root-cause attribution.

This demonstrates a realistic **SOC investigation workflow**:

1. Detect anomalous behavior.
2. Pivot to process telemetry for root cause.
3. Confirm execution chain and actor process.
4. Document findings and recommend containment.

In a real enterprise environment, this activity would warrant:

* Host isolation
* Script analysis
* PowerShell execution policy hardening
* Implementation of AppLocker or WDAC controls
