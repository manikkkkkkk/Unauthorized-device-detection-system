"""
demo.py - Interactive Cybersecurity Demonstration Simulator
============================================================
Purpose:
Provides a live, end-to-end demonstration of the Unauthorized (Rogue)
Device Detection System. Designed for presentations, interviews, or
testing without requiring physical hardware changes.

Demonstration Stages:
1. Baseline Verification (Zero-Trust asset inventory display).
2. Clean Network Sweep (Normal operational state).
3. Threat Actor Infiltration (Simulated physical dropbox / rogue device).
4. Automated Detection & Fingerprinting (OUI lookup + Port interrogation).
5. Real-Time Alert Dispatch (Telegram notification + SIEM audit log).
6. Triage & Incident Remediation.
"""

import os
import sys
import time
import json
from typing import Dict, Any

from baseline import load_baseline, list_trusted_devices
from alerter import send_alert, audit_logger
from config import BASELINE_FILE, LOG_FILE


def banner():
    print("""
\033[1;36m================================================================================
   ROUGE DEVICE DETECTION SYSTEM - INTERACTIVE CYBERSECURITY DEMONSTRATION
================================================================================\033[0m
  Demonstrating:
  • Zero-Trust Whitelisting (NIST SP 800-207)
  • Layer 2 Anomaly Detection (RFC 826)
  • Automated OUI Hardware Fingerprinting
  • Multi-Channel Real-Time Alerting (Telegram / Webhook / SIEM Log)
\033[1;36m================================================================================\033[0m
""")


def pause(message="\n[>] Press [ENTER] to advance to the next demonstration step..."):
    try:
        input(message)
    except (KeyboardInterrupt, EOFError):
        print("\nDemo aborted by operator.")
        sys.exit(0)


def stage_1_baseline():
    print("\n\033[1;34m[STAGE 1] ZERO-TRUST ASSET BASELINE INVENTORY\033[0m")
    print("--------------------------------------------------------------------------------")
    print("Concept: Under a Zero-Trust architecture, no device on the local network is")
    print("trusted implicitly. Only devices explicitly pre-authorized in the baseline store")
    print(f"('{BASELINE_FILE}') are permitted to operate.\n")

    list_trusted_devices(BASELINE_FILE)


def stage_2_normal_cycle():
    print("\033[1;32m[STAGE 2] ROUTINE MONITORING CYCLE (BENIGN NETWORK STATE)\033[0m")
    print("--------------------------------------------------------------------------------")
    print("[*] Initiating Layer 2 ARP discovery sweep across local broadcast domain...")
    time.sleep(1)

    baseline = load_baseline(BASELINE_FILE)
    authorized_devices = baseline.get("devices", {})

    print(f"[*] Broadcast ARP frame (FF:FF:FF:FF:FF:FF) transmitted.")
    print(f"[*] Processing {len(authorized_devices)} incoming ARP response(s)...")
    time.sleep(1)

    for mac, data in authorized_devices.items():
        print(f"    ✔ Host {data.get('ip'):<15} [{mac}] | Vendor: {data.get('vendor'):<22} [AUTHORIZED]")

    print(f"\n\033[1;32m[+] Cycle Complete: All {len(authorized_devices)} detected host(s) verified against whitelist.\033[0m")
    print("[+] Zero anomalies detected. No alerts triggered.")


def stage_3_rogue_infiltration():
    print("\n\033[1;31m[STAGE 3] THREAT ACTOR INTRUSION SIMULATION\033[0m")
    print("--------------------------------------------------------------------------------")
    print("Scenario: An unauthorized actor connects a physical network dropbox")
    print("(e.g., Raspberry Pi 4 running Kali Linux with automated recon tools)")
    print("into an unmonitored conference room Ethernet wall jack.")
    print("\n[*] Physical link established: Port FastEthernet 0/14 active (1000Mbps)...")
    print("[*] Attacker host acquires DHCP lease from local router...")
    time.sleep(1.5)

    rogue_device: Dict[str, Any] = {
        "ip": "192.168.1.189",
        "mac": "B8:27:EB:4A:8C:21",
        "vendor": "Raspberry Pi Foundation",
        "hostname": "kali-rogue-box.lan",
        "discovered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "open_ports": [
            {"port": 22, "protocol": "tcp", "name": "ssh", "product": "OpenSSH 9.2"},
            {"port": 80, "protocol": "tcp", "name": "http", "product": "Lighttpd/1.4.69"},
            {"port": 4444, "protocol": "tcp", "name": "metasploit", "product": "Reverse Shell Listener"},
        ],
    }

    return rogue_device


def stage_4_detection_and_alert(rogue_device: Dict[str, Any]):
    print("\n\033[1;33m[STAGE 4] AUTOMATED DETECTION & FINGERPRINTING\033[0m")
    print("--------------------------------------------------------------------------------")
    print("[*] Continuous monitor executes scheduled sweep (Cycle #42)...")
    time.sleep(1)
    print(f"[*] Evaluating active host: MAC={rogue_device['mac']} | IP={rogue_device['ip']}")
    print(f"[*] Querying IEEE OUI database for prefix '{rogue_device['mac'][:8]}'...")
    print(f"    Manufacturer Resolved: {rogue_device['vendor']}")
    time.sleep(1)

    print("\n\033[1;41m 🚨 CRITICAL ALERT: UNAUTHORIZED ROGUE DEVICE DETECTED! \033[0m")
    print(f"     Target IP:        {rogue_device['ip']}")
    print(f"     Physical MAC:     {rogue_device['mac']}")
    print(f"     Hardware Vendor:  {rogue_device['vendor']}")
    print(f"     DNS Hostname:     {rogue_device['hostname']}")
    print(f"     Timestamp:        {rogue_device['discovered_at']}")

    print("\n[*] Interrogating device for exposed network services (Nmap profiling)...")
    time.sleep(1.2)
    print(f"    Discovered {len(rogue_device['open_ports'])} exposed listening service(s):")
    for p in rogue_device["open_ports"]:
        print(f"      - Port {p['port']}/{p['protocol']:<3} : {p['name']} ({p['product']})")

    print("\n[*] Dispatching high-priority alerts to configured security channels...")
    time.sleep(0.8)

    # Dispatches live alert (Telegram / Webhook / alerts.log)
    send_alert(rogue_device)


def stage_5_audit_and_remediation(rogue_device: Dict[str, Any]):
    print("\n\033[1;35m[STAGE 5] AUDIT LOGGING & INCIDENT TRIAGE\033[0m")
    print("--------------------------------------------------------------------------------")
    print(f"[*] Checking SIEM audit log file: '{LOG_FILE}'...")
    
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
            recent_lines = lines[-2:] if len(lines) >= 2 else lines
            print("\n  Latest Audit Trail Entry:")
            for line in recent_lines:
                print(f"  \033[0;33m{line.strip()}\033[0m")
    
    print("\nRecommended Incident Response Actions:")
    print("  1. Physical Containment: Trace cable to switch port and execute 'shutdown'.")
    print("  2. Logical Quarantine: Move switch port to restricted Isolation VLAN.")
    print("  3. If Legitimate: Authorize the asset into the whitelist using:")
    print(f"     \033[1mpython baseline.py --add \"{rogue_device['mac']}\" --label \"Authorized Testing Pi\" --ip \"{rogue_device['ip']}\"\033[0m")


def main():
    # Enable ANSI escape color codes in Windows Command Prompt if needed
    if os.name == "nt":
        os.system("")

    banner()
    
    print("This guided demonstration walks through an intrusion scenario step-by-step.")
    pause("Press [ENTER] to begin Step 1 (Inspect Baseline)...")

    stage_1_baseline()
    pause("Press [ENTER] to begin Step 2 (Normal Routine Monitoring)...")

    stage_2_normal_cycle()
    pause("Press [ENTER] to begin Step 3 (Simulate Intrusion Event)...")

    rogue = stage_3_rogue_infiltration()
    pause("Press [ENTER] to begin Step 4 (Execute Detection & Real-Time Alerting)...")

    stage_4_detection_and_alert(rogue)
    pause("Press [ENTER] to begin Step 5 (Review Audit Trail & Remediation)...")

    stage_5_audit_and_remediation(rogue)

    print("\n\033[1;32m================================================================================")
    print("  DEMONSTRATION COMPLETE: Full Security Lifecycle Successfully Verified!")
    print("================================================================================\033[0m\n")


if __name__ == "__main__":
    main()
