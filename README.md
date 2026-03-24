# SOC-lab-azure-sentinel
SOC Lab using Azure Sentinel with honeypot-based attack detection and visualization
# SOC Lab with Azure Sentinel | Honeypot + Attack Map

## 📌 Project Overview

This project demonstrates the implementation of a cloud-based Security Operations Center (SOC) lab using Microsoft Azure and Azure Sentinel (SIEM).

A deliberately vulnerable Windows virtual machine (honeypot) was deployed to attract malicious traffic. Security logs were collected, analyzed using Kusto Query Language (KQL), enriched with geographic intelligence, and visualized through a global attack map.

---

## 🎯 Objectives

* Build a cloud-native SIEM environment using Azure Sentinel
* Deploy a honeypot to capture real-world attack attempts
* Collect and analyze Windows security logs
* Detect brute-force login attempts using KQL
* Enrich logs with geographic data (GeoIP)
* Visualize attacker activity on a global map

---

## 🏗️ Architecture

The architecture consists of:

* Azure Virtual Machine (Honeypot)
* Network Security Group (Open inbound traffic)
* Log Analytics Workspace (Central log storage)
* Azure Sentinel (SIEM layer)
* GeoIP Watchlist (Threat enrichment)
* Sentinel Workbook (Attack visualization)

---

## ⚙️ Technologies Used

* Microsoft Azure
* Azure Sentinel (SIEM)
* Log Analytics Workspace (LAW)
* Windows 10 Virtual Machine
* KQL (Kusto Query Language)
* Sentinel Watchlists

---

## 🧪 Lab Implementation

### 1. Azure Environment Setup

* Created Azure subscription and resource group
* Configured required cloud resources

### 2. Honeypot Deployment

* Deployed Windows 10 Virtual Machine
* Configured Network Security Group to allow all inbound traffic
* Disabled Windows Firewall to increase exposure
* Purpose: Capture unauthorized access attempts

### 3. Log Generation

* Simulated failed login attempts
* Observed Windows Event ID **4625** (failed login events)

---

## 🔍 Log Collection & SIEM Integration

### Log Analytics Workspace

* Created central logging workspace
* Configured as data ingestion point

### Azure Sentinel Setup

* Enabled Sentinel on Log Analytics Workspace
* Established SIEM monitoring layer

### Data Connector

* Configured: **Windows Security Events via AMA**
* Created Data Collection Rule (DCR)
* Enabled log forwarding from VM

---

## 🔎 Detection using KQL

### Failed Login Detection

```kql
SecurityEvent
| where EventID == 4625
```

### Brute Force Detection

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
```

---

## 🌍 Log Enrichment (GeoIP)

To identify attacker locations, logs were enriched using a GeoIP dataset:

* Imported GeoIP CSV as a Sentinel Watchlist
* Mapped attacker IP addresses to geographic data

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
SecurityEvent
| where EventID == 4625
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
```

---

## 🗺️ Attack Map Visualization

A custom Sentinel Workbook was created to visualize attacker activity globally.

* Displays attack origin by country and city
* Uses heatmap visualization based on failed login count
* Provides real-time insights into attack patterns

---

## 🚨 SOC Workflow Simulation

1. Attacker attempts login (brute-force activity)
2. Logs generated on honeypot VM
3. Logs forwarded to Log Analytics Workspace
4. Azure Sentinel analyzes incoming data
5. KQL queries detect suspicious patterns
6. GeoIP enrichment adds location intelligence
7. Attack map visualizes global threat activity

---

## 📊 Observations & Analysis

* Multiple failed login attempts were detected from external IP addresses
* Attack patterns indicated automated brute-force behavior
* Repeated attempts were observed within short time intervals
* Global distribution of attacks highlighted exposure of public-facing systems

---

## 🧠 Key Learnings

* Hands-on experience with SIEM tools (Azure Sentinel)
* Practical understanding of SOC workflows
* Log analysis using KQL
* Threat detection and investigation
* Cloud-based security monitoring
* Threat intelligence enrichment

---


## 🚀 Future Improvements

* Implement Analytics Rules for automated alerting
* Integrate Microsoft Defender for Endpoint
* Add Logic Apps for automated incident response
* Use live threat intelligence feeds
* Expand to multi-VM environment for advanced simulations

---

## 📸 Project Preview

![Attack Map](screenshots/12-attack-map.jpg)

---

## 👤 Author

Rakesh B

---
