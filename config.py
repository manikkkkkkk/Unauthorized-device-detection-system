"""
config.py - Centralized Configuration for Rogue Device Detection System
========================================================================
Cybersecurity Principles:
- Single Source of Truth: Centralized configuration reduces configuration drift
  and ensures uniform security policies across discovery, monitoring, and alerting.
- Defense-in-Depth: Defaults are configured safely with environment-variable overrides
  to avoid hardcoding sensitive secrets (e.g., webhook tokens) in source code.
"""

import os
import socket
import ipaddress


def detect_local_subnet() -> str:
    """
    Dynamically identifies the host's primary IPv4 interface and derives
    the local /24 subnet. Falls back to '192.168.1.0/24' if unable to detect.
    """
    try:
        # Create a dummy UDP socket to a public DNS IP (no packet is actually sent)
        # to determine which interface the OS routing table would select.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        # Assume standard class C /24 subnet for home/office LANs
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(network)
    except Exception:
        return "192.168.1.0/24"


# Network Scanner Configuration
DEFAULT_SUBNET: str = os.getenv("ROGUE_SUBNET", detect_local_subnet())
ARP_TIMEOUT_SECONDS: int = int(os.getenv("ARP_TIMEOUT_SECONDS", "2"))
ARP_RETRY_COUNT: int = int(os.getenv("ARP_RETRY_COUNT", "2"))

# Monitoring Cycle Configuration
# Continuous detection loop runs every 2 minutes (120 seconds) as specified
SCAN_INTERVAL_SECONDS: int = int(os.getenv("SCAN_INTERVAL_SECONDS", "120"))

# Alerting Cooldown (in seconds)
# Prevents flooding the alert channel every 2 minutes for the same rogue device
# during an ongoing incident. Default: 1800 seconds (30 minutes).
ALERT_COOLDOWN_SECONDS: int = int(os.getenv("ALERT_COOLDOWN_SECONDS", "1800"))

# Webhook & Telegram Alerting Configuration
# Provide a webhook URL (Discord, Slack, or generic JSON endpoint).
# Defaults to httpbin.org mock post endpoint for safe out-of-the-box testing.
DEFAULT_WEBHOOK_URL: str = os.getenv(
    "ROGUE_WEBHOOK_URL",
    "https://httpbin.org/post"
)

# Telegram Bot API Configuration
# Get your BOT_TOKEN from @BotFather and CHAT_ID from @userinfobot on Telegram.
# Telegram Bot API Configuration
TELEGRAM_BOT_TOKEN: str = "8875802045:AAHKfg-LZ9xZZcV70hd-iJUrY7rHcNCrwgA"
TELEGRAM_CHAT_ID: str = "1985662407"

# Storage & Logging Paths
BASELINE_FILE: str = os.getenv("ROGUE_BASELINE_FILE", "trusted_devices.json")
LOG_FILE: str = os.getenv("ROGUE_LOG_FILE", "alerts.log")

# Optional Advanced Fingerprinting
# Set to True to trigger an Nmap port sweep when an unauthorized device is flagged.
ENABLE_PORT_SCAN: bool = os.getenv("ENABLE_PORT_SCAN", "False").lower() in ("true", "1", "yes")
NMAP_DEFAULT_PORTS: str = os.getenv("NMAP_DEFAULT_PORTS", "21,22,23,25,80,443,445,3389,8080")
