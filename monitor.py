"""
monitor.py - Continuous Rogue Device Detection Daemon
=====================================================
Cybersecurity Principles & Architecture:
- Continuous Security Monitoring (NIST CSF DE.CM / NIST SP 800-137):
  Point-in-time security audits leave vast attack windows open for adversaries.
  Threat actors often connect temporary physical dropboxes (e.g., Raspberry Pi,
  Hak5 LAN Turtle, rubber ducky LAN implants) or deploy unauthorized Wi-Fi
  access points (Evil Twins) during off-hours. A continuous detection loop
  ensures the Mean Time to Detect (MTTD) rogue hardware is bounded strictly
  by the scan cycle (e.g., 2 minutes).

- Whitelist-Driven Anomaly Detection:
  Every active Layer 2 hardware signature (MAC) identified in a cycle is
  cross-referenced against the authoritative baseline store (`trusted_devices.json`).
  Any device not present is classified as an immediate security violation:
  `STATUS: UNAUTHORIZED / ROGUE`.

- Alert Fatigue Mitigation (Cooldown & State Tracking):
  Flooding an on-call security engineer with a new webhook alert every 120 seconds
  for the same rogue device leads to alert fatigue and ignored warnings.
  The daemon implements stateful cooldown tracking: immediate alerting on discovery,
  with periodic re-notifications only if the rogue persists across a defined
  threshold (e.g. 30 minutes) or changes its IP address.
"""

import sys
import time
import signal
import logging
from typing import Dict, Any, Set

from config import (
    DEFAULT_SUBNET,
    SCAN_INTERVAL_SECONDS,
    BASELINE_FILE,
    DEFAULT_WEBHOOK_URL,
    ALERT_COOLDOWN_SECONDS,
    ENABLE_PORT_SCAN,
)
from scanner import scan_network, scan_device_ports, normalize_mac
from baseline import load_baseline
from alerter import send_alert, audit_logger


class RogueDeviceMonitor:
    """
    Orchestrates continuous network sweeps, baseline verification,
    and alert dispatching.
    """

    def __init__(
        self,
        subnet: str = DEFAULT_SUBNET,
        interval: int = SCAN_INTERVAL_SECONDS,
        baseline_file: str = BASELINE_FILE,
        webhook_url: str = DEFAULT_WEBHOOK_URL,
        cooldown: int = ALERT_COOLDOWN_SECONDS,
        port_scan: bool = ENABLE_PORT_SCAN,
    ):
        self.subnet = subnet
        self.interval = interval
        self.baseline_file = baseline_file
        self.webhook_url = webhook_url
        self.cooldown = cooldown
        self.port_scan = port_scan

        # State tracking: maps MAC -> {"last_alerted": epoch_seconds, "last_ip": str}
        self.alerted_rogues: Dict[str, Dict[str, Any]] = {}
        self.cycle_count = 0
        self.total_rogues_flagged = 0
        self.is_running = True

    def reload_whitelist(self) -> Set[str]:
        """
        Dynamically loads the authorized MAC addresses from the baseline file.
        Normalizes all MACs to uppercase colon-separated format.
        """
        baseline_data = load_baseline(self.baseline_file)
        devices = baseline_data.get("devices", {})
        whitelist: Set[str] = {normalize_mac(mac) for mac in devices.keys()}
        return whitelist

    def should_alert_webhook(self, mac: str, ip: str) -> bool:
        """
        Determines whether to trigger an external webhook notification based on
        cooldown period and whether the rogue device changed its IP address.
        """
        now = time.time()
        if mac not in self.alerted_rogues:
            return True

        record = self.alerted_rogues[mac]
        elapsed = now - record["last_alerted"]
        ip_changed = record["last_ip"] != ip

        # Re-alert if cooldown expired or if the rogue device hopped to a new IP
        return (elapsed >= self.cooldown) or ip_changed

    def mark_alerted(self, mac: str, ip: str) -> None:
        """
        Updates the cooldown tracker for an alerted rogue device.
        """
        self.alerted_rogues[mac] = {
            "last_alerted": time.time(),
            "last_ip": ip,
        }

    def execute_scan_cycle(self) -> None:
        """
        Executes a single monitoring cycle:
        1. Reloads whitelist from disk (enables hot-reloading).
        2. Conducts ARP discovery scan.
        3. Identifies unauthorized hardware.
        4. Triggers alerts & port profiling.
        """
        self.cycle_count += 1
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        print(f"\n[{timestamp_str}] [Cycle #{self.cycle_count}] Scanning {self.subnet}...")

        whitelist = self.reload_whitelist()
        if not whitelist:
            print("[!] WARNING: Whitelist is empty! Run 'python baseline.py --scan' to create one.")

        # Step 1: Scan active devices on local subnet
        try:
            discovered_devices = scan_network(subnet=self.subnet)
        except Exception as exc:
            audit_logger.error(f"Scan cycle #{self.cycle_count} aborted: {exc}")
            return

        rogue_devices = []
        authorized_count = 0

        # Step 2: Compare each active host against the whitelist
        for dev in discovered_devices:
            mac = dev["mac"]
            if mac in whitelist:
                authorized_count += 1
            else:
                rogue_devices.append(dev)

        print(
            f"[*] Scan complete: {len(discovered_devices)} total hosts | "
            f"{authorized_count} authorized | {len(rogue_devices)} UNAUTHORIZED"
        )

        # Step 3: Handle unauthorized devices
        for rogue in rogue_devices:
            mac = rogue["mac"]
            ip = rogue["ip"]
            vendor = rogue["vendor"]
            self.total_rogues_flagged += 1

            print(f"\n[🚨] ROGUE DEVICE DETECTED!")
            print(f"     IP:       {ip}")
            print(f"     MAC:      {mac}")
            print(f"     Vendor:   {vendor}")
            print(f"     Hostname: {rogue.get('hostname') or 'None'}")

            # Optional deep service fingerprinting
            if self.port_scan:
                print(f"[*] Interrogating {ip} for open ports...")
                open_ports = scan_device_ports(ip)
                rogue["open_ports"] = open_ports
                if open_ports:
                    print(f"    Discovered {len(open_ports)} exposed port(s):")
                    for p in open_ports:
                        print(f"      - {p['port']}/{p['protocol']} ({p['name']})")
            else:
                rogue["open_ports"] = []

            # Check alert cooldown logic
            if self.should_alert_webhook(mac, ip):
                print(f"[*] Dispatching high-priority security alert...")
                send_alert(rogue, webhook_url=self.webhook_url)
                self.mark_alerted(mac, ip)
            else:
                elapsed_mins = int((time.time() - self.alerted_rogues[mac]["last_alerted"]) / 60)
                print(
                    f"[*] Webhook notification suppressed by cooldown ({elapsed_mins}m ago). "
                    f"Logged to audit file."
                )
                from alerter import log_unauthorized_device
                log_unauthorized_device(rogue)

    def start(self) -> None:
        """
        Runs the continuous detection daemon until interrupted.
        """
        print("=" * 80)
        print("   UNAUTHORIZED (ROGUE) DEVICE DETECTION SYSTEM - ACTIVE MONITOR")
        print("=" * 80)
        print(f" Target Subnet:   {self.subnet}")
        print(f" Scan Interval:   {self.interval} seconds ({self.interval / 60:.1f} minutes)")
        print(f" Baseline Store:  {self.baseline_file}")
        print(f" Webhook Target:  {self.webhook_url}")
        print(f" Port Interrogate:{'Enabled' if self.port_scan else 'Disabled'}")
        print("=" * 80)
        print("[*] Press Ctrl+C at any time to halt monitoring safely.\n")

        while self.is_running:
            start_time = time.time()
            self.execute_scan_cycle()

            # Calculate sleep duration to keep strict interval alignment
            elapsed = time.time() - start_time
            sleep_time = max(0.0, self.interval - elapsed)

            if not self.is_running:
                break

            print(f"[*] Next sweep in {int(sleep_time)} seconds...\n")
            try:
                # Sleep in short increments to respond quickly to Ctrl+C
                slept = 0.0
                while slept < sleep_time and self.is_running:
                    time.sleep(min(1.0, sleep_time - slept))
                    slept += 1.0
            except KeyboardInterrupt:
                break

        self.shutdown()

    def shutdown(self) -> None:
        """
        Handles clean daemon termination and summary reporting.
        """
        print("\n\n" + "=" * 60)
        print("  MONITOR TERMINATED (SHUTDOWN SUMMARY)")
        print("=" * 60)
        print(f" Total Discovery Cycles:  {self.cycle_count}")
        print(f" Rogue Incidents Flagged: {self.total_rogues_flagged}")
        print(f" Persistent Audit Log:    alerts.log")
        print("=" * 60)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Continuous Rogue Device Detection Monitoring Daemon"
    )
    parser.add_argument(
        "--subnet",
        type=str,
        default=DEFAULT_SUBNET,
        help=f"Target subnet to monitor (default: {DEFAULT_SUBNET})",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=SCAN_INTERVAL_SECONDS,
        help=f"Continuous scan frequency in seconds (default: {SCAN_INTERVAL_SECONDS}s = 2 mins)",
    )
    parser.add_argument(
        "--webhook",
        type=str,
        default=DEFAULT_WEBHOOK_URL,
        help="Alert destination webhook URL (Discord, Slack, or generic HTTP POST)",
    )
    parser.add_argument(
        "--baseline",
        type=str,
        default=BASELINE_FILE,
        help=f"Path to trusted baseline JSON file (default: {BASELINE_FILE})",
    )
    parser.add_argument(
        "--port-scan",
        action="store_true",
        help="Enable active Nmap port scanning when an unauthorized device is detected",
    )

    args = parser.parse_args()

    monitor = RogueDeviceMonitor(
        subnet=args.subnet,
        interval=args.interval,
        baseline_file=args.baseline,
        webhook_url=args.webhook,
        port_scan=args.port_scan,
    )

    # Register graceful signal handlers
    def sig_handler(sig, frame):
        monitor.is_running = False

    signal.signal(signal.SIGINT, sig_handler)
    try:
        signal.signal(signal.SIGTERM, sig_handler)
    except (AttributeError, ValueError):
        pass

    monitor.start()
