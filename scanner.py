"""
scanner.py - Network Discovery & Hardware Fingerprinting Module
================================================================
Cybersecurity Principles & Architecture:
- Layer 2 ARP Discovery vs. Layer 3 ICMP/TCP Sweeps:
  Host firewalls (e.g., Windows Defender, macOS pf, iptables) frequently drop
  or stealth ICMP Echo Requests ('ping') and unsolicited TCP SYN packets.
  However, devices connected to an Ethernet or Wi-Fi local broadcast domain
  CANNOT drop Layer 2 Address Resolution Protocol (ARP) requests if they wish
  to communicate over IPv4 (RFC 826). ARP scanning provides high-fidelity,
  unstealthable network asset discovery within the local broadcast domain.

- Hardware OUI (Organizationally Unique Identifier):
  The first 3 bytes (24 bits) of a MAC address are assigned by IEEE to the
  hardware manufacturer. While MAC addresses can be spoofed by skilled adversaries,
  OUI resolution provides vital initial triage data for asset classification
  (e.g., distinguishing an authorized Dell laptop from an unknown Raspberry Pi
  or Espressif microcontroller).

- Limitations & Defense-in-Depth:
  ARP broadcasts cannot cross Layer 3 router boundaries without an ARP relay.
  Therefore, this scanner monitors the immediate local broadcast domain (VLAN).
  In enterprise deployments, active scanning is complemented by 802.1X Network
  Access Control (NAC) and Dynamic ARP Inspection (DAI) on managed switches.
"""

import sys
import time
import socket
import logging
from typing import List, Dict, Optional, Any

try:
    # Scapy handles Layer 2 packet crafting and network packet capture
    from scapy.all import Ether, ARP, srp, conf
except ImportError:
    Ether = None
    ARP = None
    srp = None
    conf = None

try:
    import requests
except ImportError:
    requests = None

try:
    import nmap
except ImportError:
    nmap = None

from config import (
    DEFAULT_SUBNET,
    ARP_TIMEOUT_SECONDS,
    ARP_RETRY_COUNT,
    NMAP_DEFAULT_PORTS,
    ENABLE_PORT_SCAN,
)

logger = logging.getLogger("RogueDetector.Scanner")

# Curated offline database for top hardware vendors to ensure instantaneous,
# reliable OUI identification even when internet access or API rate limits fail.
COMMON_OUI_CACHE: Dict[str, str] = {
    # Raspberry Pi Foundation
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "28:CD:C1": "Raspberry Pi Trading Ltd",
    "D8:3A:DD": "Raspberry Pi Trading Ltd",
    # Espressif (IoT microcontrollers, ESP8266/ESP32, often used in rogue hardware implants)
    "24:0A:C4": "Espressif Inc.",
    "30:AE:A4": "Espressif Inc.",
    "A4:CF:12": "Espressif Inc.",
    "24:6F:28": "Espressif Inc.",
    "84:CC:A8": "Espressif Inc.",
    # Apple
    "F0:18:98": "Apple, Inc.",
    "AC:BC:32": "Apple, Inc.",
    "3C:06:30": "Apple, Inc.",
    "BC:D1:D3": "Apple, Inc.",
    "F4:34:F0": "Apple, Inc.",
    # Cisco Systems
    "00:00:0C": "Cisco Systems, Inc.",
    "00:01:42": "Cisco Systems, Inc.",
    "00:01:96": "Cisco Systems, Inc.",
    "F4:4B:2A": "Cisco Systems, Inc.",
    # Intel Corporation
    "00:1B:21": "Intel Corporate",
    "3C:FD:FE": "Intel Corporate",
    "A4:4C:C8": "Intel Corporate",
    # TP-Link
    "50:C7:BF": "TP-Link Technologies",
    "E8:48:B8": "TP-Link Technologies",
    "00:31:92": "TP-Link Technologies",
    # Netgear
    "00:1E:E5": "Netgear",
    "20:4E:7F": "Netgear",
    "A0:04:60": "Netgear",
    # Ubiquiti Networks
    "78:8A:20": "Ubiquiti Networks Inc.",
    "B4:FB:E4": "Ubiquiti Networks Inc.",
    "FC:EC:DA": "Ubiquiti Networks Inc.",
    # Google
    "F4:F5:D8": "Google, Inc.",
    "54:60:09": "Google, Inc.",
    "D8:6C:63": "Google, Inc.",
    # Amazon
    "44:65:0D": "Amazon Technologies Inc.",
    "FC:A6:67": "Amazon Technologies Inc.",
    "68:54:5A": "Amazon Technologies Inc.",
    # Dell
    "18:66:DA": "Dell Inc.",
    "D4:BE:D9": "Dell Inc.",
    "B8:85:84": "Dell Inc.",
}

# Runtime memory cache for dynamic API lookups
_DYNAMIC_VENDOR_CACHE: Dict[str, str] = {}


def normalize_mac(mac: str) -> str:
    """
    Normalizes MAC address format to standard uppercase colon-delimited string.
    Example: '00-1a-2b-3c-4d-5e' -> '00:1A:2B:3C:4D:5E'
    """
    clean_mac = mac.replace("-", ":").replace(".", "").strip().upper()
    if len(clean_mac) == 12 and ":" not in clean_mac:
        clean_mac = ":".join(clean_mac[i:i+2] for i in range(0, 12, 2))
    return clean_mac


def lookup_vendor(mac_address: str) -> str:
    """
    Identifies the hardware vendor corresponding to a MAC address OUI.
    
    Resolution hierarchy:
    1. Static common OUI lookup table (instant, offline).
    2. Scapy's built-in IEEE OUI database (conf.manuf).
    3. External REST API (maclookup / macvendors) with caching and short timeout.
    4. Fallback to 'Unknown / Unresolved Vendor'.
    """
    normalized = normalize_mac(mac_address)
    oui = normalized[:8]  # First 3 octets, e.g. 'AA:BB:CC'

    # Check fast static cache
    if oui in COMMON_OUI_CACHE:
        return COMMON_OUI_CACHE[oui]

    # Check dynamic session cache
    if oui in _DYNAMIC_VENDOR_CACHE:
        return _DYNAMIC_VENDOR_CACHE[oui]

    # Try Scapy's local manuf database if available
    try:
        if conf and hasattr(conf, "manuf"):
            vendor_from_scapy = conf.manuf.resolve(normalized)
            if vendor_from_scapy and vendor_from_scapy != normalized:
                _DYNAMIC_VENDOR_CACHE[oui] = vendor_from_scapy
                return vendor_from_scapy
    except Exception:
        pass

    # Online API resolution fallback (1.5 second timeout to keep scan fast)
    if requests is not None:
        try:
            url = f"https://api.maclookup.app/v2/macs/{normalized}"
            response = requests.get(url, timeout=1.5, headers={"User-Agent": "RogueDeviceDetector/1.0"})
            if response.status_code == 200:
                data = response.json()
                company = data.get("company", "").strip()
                if company:
                    _DYNAMIC_VENDOR_CACHE[oui] = company
                    return company
        except Exception:
            # Fallback to secondary vendor lookup service
            try:
                alt_url = f"https://macvendors.co/api/{normalized}"
                alt_response = requests.get(alt_url, timeout=1.5, headers={"User-Agent": "RogueDeviceDetector/1.0"})
                if alt_response.status_code == 200:
                    data = alt_response.json()
                    company = data.get("result", {}).get("company", "").strip()
                    if company:
                        _DYNAMIC_VENDOR_CACHE[oui] = company
                        return company
            except Exception:
                pass

    _DYNAMIC_VENDOR_CACHE[oui] = "Unknown Vendor"
    return "Unknown Vendor"


def resolve_hostname(ip_address: str) -> str:
    """
    Attempts reverse DNS resolution to locate a NetBIOS/DNS hostname for the target IP.
    Returns hostname or empty string if resolution times out or fails.
    """
    try:
        host, _, _ = socket.gethostbyaddr(ip_address)
        return host
    except (socket.herror, socket.gaierror, socket.timeout):
        return ""


def scan_network(
    subnet: str = DEFAULT_SUBNET,
    timeout: int = ARP_TIMEOUT_SECONDS,
    retry: int = ARP_RETRY_COUNT,
) -> List[Dict[str, Any]]:
    """
    Executes an active Layer 2 ARP scan across the specified subnet.
    
    Crafts an Ethernet broadcast packet (dst: FF:FF:FF:FF:FF:FF) wrapping an ARP request
    (who-has <target_subnet>), broadcasts it, and parses incoming ARP responses.
    
    Returns:
        List of dictionaries containing:
        - ip: IPv4 address
        - mac: Normalized MAC address
        - vendor: Hardware manufacturer
        - hostname: Resolved reverse DNS name (if any)
        - first_seen: ISO-8601 timestamp
    """
    if srp is None or Ether is None or ARP is None:
        raise RuntimeError(
            "Scapy is not installed. Please install Scapy: 'pip install scapy'."
        )

    logger.info(f"Initiating Layer 2 ARP discovery sweep on subnet: {subnet}")
    print(f"[*] Scanning subnet {subnet} via ARP broadcast (timeout={timeout}s, retry={retry})...")

    # Step 1: Craft the Layer 2 Ethernet broadcast frame and ARP payload
    # Destination MAC FF:FF:FF:FF:FF:FF forces every network interface on the local
    # broadcast domain to process the frame up to the ARP stack.
    broadcast_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = ARP(pdst=subnet)
    packet_chain = broadcast_frame / arp_request

    # Step 2: Send and receive packets at Layer 2 (srp = Send and Receive Packets at Layer 2)
    try:
        answered, _ = srp(
            packet_chain,
            timeout=timeout,
            retry=retry,
            verbose=False,
            iface=None,
        )
    except PermissionError:
        logger.error("Root/Administrator privileges required for raw socket access.")
        raise PermissionError(
            "Raw socket access denied. Run this script as Administrator (Windows) or root/sudo (Linux)."
        )
    except Exception as exc:
        logger.error(f"Scapy scan failed: {exc}")
        raise RuntimeError(
            f"ARP scan encountered an error: {exc}. On Windows, ensure Npcap is installed "
            "with 'WinPcap API-compatible Mode' enabled."
        )

    # Step 3: Parse answered packets and extract IP / MAC pairs
    active_devices: List[Dict[str, Any]] = []
    current_timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    for sent, received in answered:
        ip = received.psrc
        mac = normalize_mac(received.hwsrc)
        vendor = lookup_vendor(mac)
        hostname = resolve_hostname(ip)

        device_profile = {
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "discovered_at": current_timestamp,
        }
        active_devices.append(device_profile)

    logger.info(f"Scan complete. Discovered {len(active_devices)} active host(s).")
    return active_devices


def scan_device_ports(ip_address: str, ports: str = NMAP_DEFAULT_PORTS) -> List[Dict[str, Any]]:
    """
    Conducts targeted TCP SYN/Connect port scanning on a suspected rogue device
    using python-nmap to profile running network services (e.g., SSH, HTTP, SMB).
    
    Gracefully degrades if Nmap binary is not installed on the system.
    """
    if nmap is None:
        logger.debug("python-nmap package is not available; skipping port profiling.")
        return []

    try:
        nm = nmap.PortScanner()
        logger.info(f"Conducting port interrogation against {ip_address} on ports: {ports}")
        nm.scan(hosts=ip_address, ports=ports, arguments="-sT -T4 --open")

        open_services: List[Dict[str, Any]] = []
        if ip_address in nm.all_hosts():
            for proto in nm[ip_address].all_protocols():
                port_list = sorted(nm[ip_address][proto].keys())
                for port in port_list:
                    service_info = nm[ip_address][proto][port]
                    open_services.append({
                        "port": port,
                        "protocol": proto,
                        "state": service_info.get("state", "open"),
                        "name": service_info.get("name", "unknown"),
                        "product": service_info.get("product", ""),
                        "version": service_info.get("version", ""),
                    })
        return open_services
    except (nmap.PortScannerError, FileNotFoundError, Exception) as exc:
        logger.warning(f"Nmap scan could not be executed for {ip_address}: {exc}")
        return []


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Active Layer 2 ARP Discovery Scanner for Rogue Device Detection"
    )
    parser.add_argument(
        "--subnet",
        type=str,
        default=DEFAULT_SUBNET,
        help=f"Target CIDR subnet (default: {DEFAULT_SUBNET})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=ARP_TIMEOUT_SECONDS,
        help=f"ARP packet wait timeout in seconds (default: {ARP_TIMEOUT_SECONDS})",
    )
    parser.add_argument(
        "--port-scan",
        action="store_true",
        help="Run optional Nmap port interrogation on discovered hosts",
    )

    args = parser.parse_args()

    print("=================================================================")
    print("  NETWORK DISCOVERY SCANNER (LAYER 2 ARP)")
    print("=================================================================")
    try:
        devices = scan_network(subnet=args.subnet, timeout=args.timeout)
        print(f"\n[+] Discovered {len(devices)} active host(s) on {args.subnet}:\n")
        print(f"{'IP Address':<18} {'MAC Address':<20} {'Vendor':<28} {'Hostname'}")
        print("-" * 80)
        for d in devices:
            print(f"{d['ip']:<18} {d['mac']:<20} {d['vendor'][:26]:<28} {d['hostname']}")
            if args.port_scan:
                services = scan_device_ports(d["ip"])
                if services:
                    print("    Open Ports:")
                    for s in services:
                        print(f"      - Port {s['port']}/{s['protocol']} ({s['name']} {s['product']})")
        print("-" * 80)
    except (PermissionError, RuntimeError) as e:
        print(f"\n[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
