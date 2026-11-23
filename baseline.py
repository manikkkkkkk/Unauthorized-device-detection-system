"""
baseline.py - Trusted Device Profiling & Whitelist Management
=============================================================
Cybersecurity Principles & Architecture:
- Zero Trust Architecture (NIST SP 800-207) & Default-Deny Posture:
  Traditional perimeter security assumed that any device connected to an
  internal physical switch port or Wi-Fi SSID was implicitly trusted.
  In modern threat landscapes (evil twins, compromised guest credentials,
  malicious IoT dropboxes, physical LAN tampering), implicit trust is fatal.
  A strict whitelisting model adopts a 'Default Deny' stance: no device is
  granted network legitimacy unless its cryptographic or hardware identity
  is explicitly registered in an authorized baseline inventory.

- Asset Inventory Management (CIS Control 1):
  CIS Critical Security Control 1 mandates: "Actively manage (inventory, track,
  and correct) all enterprise assets connected to the infrastructure physically,
  virtually, remotely, and within cloud environments." This module establishes
  and maintains that authoritative baseline record.

- Baseline Integrity & Tamper Resistance:
  In enterprise deployments, the baseline store (`trusted_devices.json` or
  database) must be secured with strict file ACLs (read-only to the monitoring
  service account) to prevent adversaries from self-whitelisting their hardware.
"""

import os
import sys
import json
import time
import argparse
from typing import Dict, Any, Optional

from config import BASELINE_FILE, DEFAULT_SUBNET
from scanner import scan_network, normalize_mac, lookup_vendor


def load_baseline(filepath: str = BASELINE_FILE) -> Dict[str, Any]:
    """
    Loads and parses the existing trusted devices baseline JSON file.
    Returns a standardized dictionary structure.
    """
    if not os.path.exists(filepath):
        return {
            "metadata": {
                "created_at": None,
                "last_updated": None,
                "subnet": None,
                "total_devices": 0,
            },
            "devices": {},
        }

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Ensure required schema structure exists
            if "devices" not in data or not isinstance(data["devices"], dict):
                data = {"metadata": {}, "devices": {}}
            return data
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[!] Warning: Failed to read existing baseline ({exc}). Initializing fresh structure.")
        return {"metadata": {}, "devices": {}}


def save_baseline(baseline_data: Dict[str, Any], filepath: str = BASELINE_FILE) -> None:
    """
    Saves updated baseline data to the JSON store with atomic file writing semantics.
    """
    baseline_data["metadata"]["last_updated"] = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
    )
    baseline_data["metadata"]["total_devices"] = len(baseline_data.get("devices", {}))

    temp_filepath = f"{filepath}.tmp"
    with open(temp_filepath, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f, indent=4)
    os.replace(temp_filepath, filepath)
    print(f"[+] Baseline successfully written to '{filepath}' ({baseline_data['metadata']['total_devices']} devices).")


def build_baseline_from_scan(
    subnet: str = DEFAULT_SUBNET,
    filepath: str = BASELINE_FILE,
    interactive: bool = False,
) -> Dict[str, Any]:
    """
    Executes a clean ARP scan on the subnet and populates the trusted baseline.
    
    If interactive is True, prompts the operator to provide a descriptive label
    (e.g., 'Hunter Laptop', 'Primary Gateway Router') for each identified device.
    """
    print(f"\n[*] Profiling trusted hardware on network: {subnet}")
    print("[*] Ensure ONLY authorized, known hardware is connected during this initial baseline scan!\n")

    discovered = scan_network(subnet=subnet)
    if not discovered:
        print("[!] No active hosts discovered. Verify network interface, subnet, and administrative permissions.")
        return load_baseline(filepath)

    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    baseline = {
        "metadata": {
            "created_at": timestamp,
            "last_updated": timestamp,
            "subnet": subnet,
            "total_devices": len(discovered),
        },
        "devices": {},
    }

    print(f"\n[+] Processing {len(discovered)} discovered device(s):")
    for dev in discovered:
        mac = dev["mac"]
        ip = dev["ip"]
        vendor = dev["vendor"]
        hostname = dev["hostname"]

        label = f"{vendor} device"
        if interactive:
            print(f"\nTarget: IP={ip} | MAC={mac} | Vendor={vendor} | Hostname={hostname}")
            user_label = input(f"Enter descriptive label (or press Enter for default '{label}'): ").strip()
            if user_label:
                label = user_label

        baseline["devices"][mac] = {
            "mac": mac,
            "ip": ip,
            "vendor": vendor,
            "hostname": hostname,
            "label": label,
            "added_at": timestamp,
        }

    save_baseline(baseline, filepath)
    return baseline


def add_trusted_device(
    mac: str,
    label: str,
    ip: Optional[str] = "",
    filepath: str = BASELINE_FILE,
) -> None:
    """
    Manually appends or updates a single authorized hardware device in the whitelist.
    """
    norm_mac = normalize_mac(mac)
    vendor = lookup_vendor(norm_mac)
    baseline = load_baseline(filepath)

    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if not baseline["metadata"].get("created_at"):
        baseline["metadata"]["created_at"] = timestamp

    baseline["devices"][norm_mac] = {
        "mac": norm_mac,
        "ip": ip or "Static Entry",
        "vendor": vendor,
        "hostname": "",
        "label": label,
        "added_at": timestamp,
    }

    save_baseline(baseline, filepath)
    print(f"[+] Manually authorized device [{norm_mac}] - Label: '{label}', Vendor: '{vendor}'")


def remove_trusted_device(mac: str, filepath: str = BASELINE_FILE) -> None:
    """
    Revokes authorization for a device by removing its MAC address from the baseline.
    """
    norm_mac = normalize_mac(mac)
    baseline = load_baseline(filepath)

    if norm_mac in baseline.get("devices", {}):
        removed = baseline["devices"].pop(norm_mac)
        save_baseline(baseline, filepath)
        print(f"[-] Successfully revoked authorization for MAC: {norm_mac} ({removed.get('label')})")
    else:
        print(f"[!] MAC address {norm_mac} not found in trusted baseline.")


def list_trusted_devices(filepath: str = BASELINE_FILE) -> None:
    """
    Displays the current whitelist in a formatted tabular security report.
    """
    baseline = load_baseline(filepath)
    devices = baseline.get("devices", {})

    print("\n" + "=" * 90)
    print(f"  AUTHORIZED HARDWARE WHITELIST (BASELINE: {filepath})")
    print(f"  Total Assets: {len(devices)}  |  Subnet: {baseline.get('metadata', {}).get('subnet', 'N/A')}")
    print("=" * 90)

    if not devices:
        print("  [!] Whitelist is currently empty. Run 'python baseline.py --scan' to profile.")
        print("=" * 90 + "\n")
        return

    print(f"{'MAC Address':<20} {'IP Address':<16} {'Vendor':<24} {'Label / Description'}")
    print("-" * 90)
    for mac, data in devices.items():
        vendor_short = (data.get("vendor") or "Unknown")[:22]
        print(f"{mac:<20} {data.get('ip', 'N/A'):<16} {vendor_short:<24} {data.get('label', '')}")
    print("-" * 90 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Trusted Hardware Profiling and Whitelist Management Utility"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--scan",
        action="store_true",
        help="Perform a clean ARP network sweep and write connected devices as baseline",
    )
    group.add_argument(
        "--list",
        action="store_true",
        help="Display all currently whitelisted devices",
    )
    group.add_argument(
        "--add",
        type=str,
        metavar="MAC",
        help="Manually authorize a device by MAC address (requires --label)",
    )
    group.add_argument(
        "--remove",
        type=str,
        metavar="MAC",
        help="Revoke trust and remove a device by MAC address",
    )

    parser.add_argument(
        "--subnet",
        type=str,
        default=DEFAULT_SUBNET,
        help=f"Subnet for baseline scanning (default: {DEFAULT_SUBNET})",
    )
    parser.add_argument(
        "--label",
        type=str,
        default="Authorized Device",
        help="Descriptive label when manually adding a device",
    )
    parser.add_argument(
        "--ip",
        type=str,
        default="",
        help="Optional IP address when manually adding a device",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Interactively prompt for human-readable labels during baseline scan",
    )
    parser.add_argument(
        "--file",
        type=str,
        default=BASELINE_FILE,
        help=f"Path to trusted baseline JSON file (default: {BASELINE_FILE})",
    )

    args = parser.parse_args()

    try:
        if args.scan:
            build_baseline_from_scan(
                subnet=args.subnet, filepath=args.file, interactive=args.interactive
            )
        elif args.list:
            list_trusted_devices(filepath=args.file)
        elif args.add:
            add_trusted_device(
                mac=args.add, label=args.label, ip=args.ip, filepath=args.file
            )
        elif args.remove:
            remove_trusted_device(mac=args.remove, filepath=args.file)
    except (PermissionError, RuntimeError) as err:
        print(f"\n[!] Execution halted: {err}", file=sys.stderr)
        sys.exit(1)
