# Unauthorized (Rogue) Device Detection System

An enterprise-grade, proactive Layer 2 network intrusion detection system (NIDS) designed to discover active hardware assets, enforce strict Zero-Trust whitelisting baselines, and trigger real-time alerts upon detecting unauthorized devices on your local broadcast domain.

---

## Table of Contents
- [Architecture & Overview](#architecture--overview)
- [Cybersecurity Principles & Threat Model](#cybersecurity-principles--threat-model)
- [Prerequisites & System Requirements](#prerequisites--system-requirements)
  - [Windows Setup (Npcap Requirement)](#windows-setup-npcap-requirement)
  - [Linux & macOS Setup](#linux--macos-setup)
- [Installation](#installation)
- [Operational Workflow](#operational-workflow)
  - [1. Establishing the Trusted Baseline Whitelist](#1-establishing-the-trusted-baseline-whitelist)
  - [2. Managing the Whitelist](#2-managing-the-whitelist)
  - [3. Testing the Alert Pipeline](#3-testing-the-alert-pipeline)
  - [4. Launching the Continuous Detection Monitor](#4-launching-the-continuous-detection-monitor)
- [Configuration Reference](#configuration-reference)
- [Limitations & Defense-in-Depth Mitigations](#limitations--defense-in-depth-mitigations)
- [Compliance & SIEM Integration](#compliance--siem-integration)

---

## Architecture & Overview

The system is engineered as a modular, decoupled cybersecurity framework:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Local Broadcast Domain                          │
│                                                                        │
│   [Router / Gateway]    [Workstations]    [🚨 Rogue Raspberry Pi / Drop]│
└───────────▲───────────────────▲───────────────────────▲────────────────┘
            │                   │                       │
      (ARP Requests)      (ARP Replies)           (ARP Reply)
            │                   │                       │
┌───────────┴───────────────────┴───────────────────────┴────────────────┐
│                             scanner.py                                 │
│  - Raw Layer 2 Ethernet Broadcast (FF:FF:FF:FF:FF:FF)                  │
│  - Unstealthable ARP Discovery (RFC 826)                              │
│  - OUI Hardware Vendor Fingerprinting & Reverse DNS Resolution        │
│  - Optional Nmap Service & Port Interrogation                          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Active Discovered Hosts
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                             baseline.py                                │
│  - Zero Trust Whitelist Engine                                         │
│  - Authorized Asset Store: trusted_devices.json                        │
│  - Interactive Tagging & Whitelist Administration                      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Cross-Reference
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                             monitor.py                                 │
│  - Continuous 2-minute Detection Daemon                                │
│  - Discrepancy Analysis: Active MAC ∉ Whitelist ➔ UNAUTHORIZED        │
│  - Stateful Cooldown & Anti-Alert Fatigue Engine                       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Flagged Incident
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                             alerter.py                                 │
│  - Real-Time Webhook Dispatcher (Discord Rich Embeds / JSON / Slack)   │
│  - RFC 5424 Structured Audit Trail Logger (alerts.log)                 │
└────────────────────────────────────────────────────────────────────────┘
```

### Module Breakdown
* [`config.py`](file:///c:/Users/hunte/Desktop/unauthorized_device/config.py): Centralized configuration management with environmental overrides.
* [`scanner.py`](file:///c:/Users/hunte/Desktop/unauthorized_device/scanner.py): Scapy-powered Layer 2 ARP scanner, IEEE OUI hardware fingerprinting, and optional Nmap port interrogator.
* [`baseline.py`](file:///c:/Users/hunte/Desktop/unauthorized_device/baseline.py): Trusted device profiling tool that establishes, audits, and edits `trusted_devices.json`.
* [`monitor.py`](file:///c:/Users/hunte/Desktop/unauthorized_device/monitor.py): Continuous monitoring daemon running scheduled sweeps (default: every 2 minutes) with alert throttling.
* [`alerter.py`](file:///c:/Users/hunte/Desktop/unauthorized_device/alerter.py): Incident notification engine with Discord rich embed formatting, generic webhook POST dispatching, and append-only SIEM auditing in `alerts.log`.

---

## Cybersecurity Principles & Threat Model

### 1. Unstealthable Layer 2 ARP vs. Layer 3 Sweeps
Host firewalls (such as Windows Defender Firewall, macOS `pf`, or Linux `iptables`) often block ICMP Echo Requests (`ping`) and drop unsolicited TCP SYN probes to prevent network mapping. However, **no host can block Layer 2 ARP requests** (RFC 826) if it intends to communicate via IPv4 on a shared Ethernet/Wi-Fi segment. By broadcasting `who-has` frames, the scanner forces every active NIC to reply with its MAC address, bypassing host-based endpoint firewalls.

### 2. Zero Trust & Default-Deny Posture (NIST SP 800-207)
Traditional perimeter security assumes that anything physically plugged into an office RJ45 port or authenticated to a Wi-Fi SSID is trusted. In modern security engineering, this assumption is catastrophic. This project enforces a **Default-Deny** model: any device whose MAC address is not explicitly registered in the authorized baseline is immediately flagged as a rogue entity.

### 3. Targeted Threat Vectors
* **Physical Hardware Implants:** Raspberry Pi dropboxes, Hak5 LAN Turtles, or rogue microcontrollers (e.g., ESP8266/ESP32) plugged into conference room jacks or unmonitored wall drops.
* **Rogue Wireless Access Points & Evil Twins:** Unauthorized Wi-Fi extenders or access points plugged into the wired LAN.
* **Shadow IT & Policy Violations:** Personal laptops, unauthorized gaming consoles, or vulnerable consumer IoT devices connected without IT/Security authorization.

---

## Prerequisites & System Requirements

* **Python:** Version 3.8 or higher.
* **Privileges:** Administrator (Windows) or Root/`sudo` (Linux) privileges are required to create raw Layer 2 network sockets.

### Windows Setup (Npcap Requirement)
Scapy requires a packet capture driver to craft raw Ethernet frames on Windows:
1. Download **Npcap** from [https://npcap.com/#download](https://npcap.com/#download).
2. Run the installer.
3. **CRITICAL STEP:** During installation, ensure the checkbox **"Install Npcap in WinPcap API-compatible Mode"** is **CHECKED**. If unchecked, Scapy will not be able to bind to the network adapter.

### Linux & macOS Setup
* **Debian / Ubuntu:**
  ```bash
  sudo apt-get update
  sudo apt-get install -y libpcap-dev python3-pip nmap
  ```
* **RHEL / Rocky / Fedora:**
  ```bash
  sudo dnf install -y libpcap-devel nmap
  ```
* **macOS:**
  ```bash
  brew install libpcap nmap
  ```

---

## Installation

1. **Clone or navigate into the project workspace:**
   ```bash
   cd c:\Users\hunte\Desktop\unauthorized_device
   ```

2. **(Recommended) Create and activate a Python virtual environment:**
   ```bash
   # Windows (PowerShell)
   python -m venv venv
   .\venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## Operational Workflow

### 1. Establishing the Trusted Baseline Whitelist
Before running continuous detection, you must profile your legitimate hardware environment.

> [!IMPORTANT]
> Ensure only authorized, verified devices are connected to your network when creating the initial baseline scan!

Run the baseline generator:
```bash
# Automated profiling using auto-detected subnet:
python baseline.py --scan

# Or interactively label each device (e.g., 'Primary Workstation', 'Office Printer'):
python baseline.py --scan --interactive

# Or target a specific subnet:
python baseline.py --scan --subnet 192.168.1.0/24
```
This generates [`trusted_devices.json`](file:///c:/Users/hunte/Desktop/unauthorized_device/trusted_devices.json).

### 2. Managing the Whitelist
You can view, manually add, or revoke authorizations at any time:

* **View currently whitelisted devices:**
  ```bash
  python baseline.py --list
  ```
* **Manually authorize a new device:**
  ```bash
  python baseline.py --add "00:11:22:33:44:55" --label "Director iPad" --ip "192.168.1.85"
  ```
* **Revoke trust / remove a device:**
  ```bash
  python baseline.py --remove "00:11:22:33:44:55"
  ```

### 3. Testing the Alert Pipeline
Verify that webhook dispatching and file auditing operate correctly without needing an actual rogue device on your network:

```bash
python alerter.py --test
```
* **Console:** Displays formatted security incident alert.
* **Audit File:** Writes an entry to [`alerts.log`](file:///c:/Users/hunte/Desktop/unauthorized_device/alerts.log).
* **Webhook:** Submits an HTTP POST to the configured destination (default: `https://httpbin.org/post`).

#### Configuring Discord Webhook Alerts
1. Open your Discord server -> **Channel Settings** -> **Integrations** -> **Webhooks** -> **New Webhook**.
2. Copy the Webhook URL.
3. Set the environment variable:
   ```powershell
   # Windows PowerShell
   $env:ROGUE_WEBHOOK_URL="https://discord.com/api/webhooks/YOUR/WEBHOOK/URL"

   # Linux / macOS
   export ROGUE_WEBHOOK_URL="https://discord.com/api/webhooks/YOUR/WEBHOOK/URL"
   ```
4. Run `python alerter.py --test` to preview a rich red Discord security alert embed.

#### Configuring Telegram Bot Alerts
1. Open Telegram and search for `@BotFather`. Send `/newbot`, choose a name and username, and copy the **HTTP API Token** (e.g. `123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ`).
2. Press **Start** on your new bot in Telegram.
3. Search for `@userinfobot` on Telegram and send `/start` to copy your personal **Chat ID** (e.g. `987654321`).
4. Set the environment variables:
   ```powershell
   # Windows PowerShell
   $env:TELEGRAM_BOT_TOKEN="123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ"
   $env:TELEGRAM_CHAT_ID="987654321"

   # Linux / macOS
   export TELEGRAM_BOT_TOKEN="123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ"
   export TELEGRAM_CHAT_ID="987654321"
   ```
5. Test your Telegram setup immediately:
   ```bash
   python alerter.py --test-telegram
   ```

### 4. Launching the Continuous Detection Monitor
Launch the continuous detection daemon with administrative / root privileges:

```bash
# Windows (Run PowerShell as Administrator)
python monitor.py

# Linux / macOS
sudo python3 monitor.py
```

#### Custom Daemon Options:
```bash
# Scan every 60 seconds and enable active Nmap port interrogation on rogue assets:
python monitor.py --interval 60 --port-scan

# Monitor a specific DMZ or guest subnet:
python monitor.py --subnet 10.0.0.0/24
```

---

## Configuration Reference

You can configure the system either by editing [`config.py`](file:///c:/Users/hunte/Desktop/unauthorized_device/config.py) or by passing environment variables:

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `ROGUE_SUBNET` | Auto-detected | The IPv4 CIDR subnet to monitor (e.g. `192.168.1.0/24`) |
| `SCAN_INTERVAL_SECONDS` | `120` | Interval between network sweeps (default: 2 minutes) |
| `ROGUE_WEBHOOK_URL` | `https://httpbin.org/post` | Webhook URL for alerts (Discord, Slack, or generic JSON) |
| `TELEGRAM_BOT_TOKEN` | `""` | Telegram Bot API token from @BotFather |
| `TELEGRAM_CHAT_ID` | `""` | Telegram destination chat ID from @userinfobot |
| `ROGUE_BASELINE_FILE` | `trusted_devices.json` | Path to the authorized asset JSON store |
| `ROGUE_LOG_FILE` | `alerts.log` | Persistent append-only security log file |
| `ALERT_COOLDOWN_SECONDS` | `1800` | Suppresses duplicate webhook alerts for the same MAC (30 min cooldown) |
| `ENABLE_PORT_SCAN` | `False` | Toggles automatic Nmap service interrogation on detected rogues |
| `NMAP_DEFAULT_PORTS` | `21,22,23,25,80,443,445,3389,8080` | Targeted ports probed if port scanning is enabled |

---

## Limitations & Defense-in-Depth Mitigations

> [!WARNING]
> While ARP discovery provides powerful visibility, security engineers must understand its boundaries and implement defense-in-depth controls.

1. **MAC Address Spoofing:**
   - *Threat:* MAC addresses are transmitted in plaintext at Layer 2 and can be altered by any host using standard tools (`macchanger`, `ip link set`). An attacker sniffing the local link could identify a whitelisted MAC and clone it.
   - *Mitigation:* Complement MAC whitelisting with **IEEE 802.1X Port-Based Network Access Control (EAP-TLS)**, which requires cryptographic certificate authentication before switch ports or Wi-Fi APs transition to an authorized state.
2. **Broadcast Boundaries (VLANs):**
   - *Threat:* Layer 2 ARP frames do not traverse routers or separate VLANs.
   - *Mitigation:* Deploy this monitoring agent across each critical VLAN, use an ARP sensor daemon on your core switch/router, or enable **DHCP Snooping** and **Dynamic ARP Inspection (DAI)** on managed network switches.
3. **Switch Port Security:**
   - *Mitigation:* On managed Cisco/Aruba/Juniper hardware, configure `port-security` with sticky MAC limits and violation modes set to `shutdown` or `restrict`.

---

## Compliance & SIEM Integration

The append-only log file [`alerts.log`](file:///c:/Users/hunte/Desktop/unauthorized_device/alerts.log) satisfies key regulatory requirements:
* **PCI-DSS Requirement 11.1:** Mandates testing for the presence of unauthorized wireless and wired access points on a quarterly basis.
* **CIS Critical Security Control 1.1 & 1.2:** Establish and actively maintain an inventory of authorized enterprise assets and address unauthorized assets.
* **Log Ingestion:** `alerts.log` uses standard RFC 5424 timestamp and key-value formats, making it straightforward to forward to Splunk Universal Forwarder, Filebeat (Elasticsearch), or Wazuh agents:
  ```log
  [2026-11-01 13:51:18] [WARNING] [SECURITY-AUDIT] ROGUE_DEVICE_DETECTED: MAC=B8:27:EB:12:34:56 | IP=192.168.1.199 | Vendor='Raspberry Pi Foundation' | Hostname='kali-dropbox.lan' | OpenPorts=[22/ssh, 4444/metasploit]
  ```
