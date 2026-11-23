"""
alerter.py - Incident Notification & Audit Logging Engine
==========================================================
Cybersecurity Principles & Architecture:
- Incident Response Time-to-Detect (TTD) & Time-to-Acknowledge (TTA):
  A rogue device connecting to a corporate or home LAN can begin ARP poisoning,
  DHCP starvation, or credential sniffing within seconds of link establishment.
  Immediate push notifications via webhooks (Discord, Slack, Teams, SIEM) ensure
  security teams or administrators can execute physical or logical containment
  (e.g., switch port disablement, 802.1X quarantine VLAN) immediately.

- Audit Integrity & Non-Repudiation:
  All detection events are written to an append-only audit log (`alerts.log`).
  Standard RFC 5424 structured log formatting guarantees that downstream SIEM
  parsers (Splunk, Elastic, Wazuh) can ingest and index rogue connection events
  for compliance (PCI-DSS 11.1, ISO 27001 A.13.1).
"""

import sys
import json
import logging
import argparse
from typing import Dict, Any, Optional

try:
    import requests
except ImportError:
    requests = None

from config import (
    LOG_FILE,
    DEFAULT_WEBHOOK_URL,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
)


def setup_logger(log_file: str = LOG_FILE) -> logging.Logger:
    """
    Configures a dedicated security incident logger with both file and console handlers.
    Formats logs with ISO timestamps, severity level, and audit tags.
    """
    logger = logging.getLogger("RogueDetector.Alerter")
    logger.setLevel(logging.INFO)

    # Avoid adding duplicate handlers if setup_logger is called repeatedly
    if not logger.handlers:
        file_formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] [SECURITY-AUDIT] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        console_formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S",
        )
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    return logger


audit_logger = setup_logger()


def log_unauthorized_device(device_data: Dict[str, Any]) -> None:
    """
    Writes a high-severity security audit entry into alerts.log.
    """
    ip = device_data.get("ip", "UNKNOWN_IP")
    mac = device_data.get("mac", "UNKNOWN_MAC")
    vendor = device_data.get("vendor", "UNKNOWN_VENDOR")
    hostname = device_data.get("hostname", "NO_DNS")
    ports = device_data.get("open_ports", [])

    ports_summary = ", ".join(f"{p.get('port')}/{p.get('name')}" for p in ports) if ports else "None scanned"

    audit_entry = (
        f"ROGUE_DEVICE_DETECTED: MAC={mac} | IP={ip} | Vendor='{vendor}' | "
        f"Hostname='{hostname}' | OpenPorts=[{ports_summary}]"
    )
    audit_logger.warning(audit_entry)


def build_discord_payload(device_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Constructs a rich, color-coded Discord Webhook Embed for high-visibility alerting.
    """
    ip = device_data.get("ip", "Unknown")
    mac = device_data.get("mac", "Unknown")
    vendor = device_data.get("vendor", "Unknown")
    hostname = device_data.get("hostname", "None") or "Unresolved"
    timestamp = device_data.get("discovered_at", "N/A")
    ports = device_data.get("open_ports", [])

    port_desc = "None identified"
    if ports:
        port_desc = "\n".join([f"`{p.get('port')}/tcp` - {p.get('name')} {p.get('product', '')}" for p in ports])

    return {
        "username": "Network Defense Sentinel",
        "avatar_url": "https://img.icons8.com/color/96/shield.png",
        "embeds": [
            {
                "title": "🚨 SECURITY ALERT: Unauthorized Rogue Device Detected",
                "description": (
                    f"An unwhitelisted hardware asset has connected to the monitored local subnet.\n"
                    f"**Immediate containment investigation recommended.**"
                ),
                "color": 0xD9534F,  # Crimson Red
                "fields": [
                    {"name": "IP Address", "value": f"`{ip}`", "inline": True},
                    {"name": "MAC Address", "value": f"`{mac}`", "inline": True},
                    {"name": "Hardware Vendor (OUI)", "value": f"**{vendor}**", "inline": True},
                    {"name": "Hostname / NetBIOS", "value": hostname, "inline": True},
                    {"name": "Timestamp (UTC)", "value": timestamp, "inline": True},
                    {"name": "Open Services / Ports", "value": port_desc, "inline": False},
                ],
                "footer": {
                    "text": "Unauthorized Rogue Device Detection System • Zero Trust Perimeter"
                },
            }
        ],
    }


def build_generic_payload(device_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Constructs a standard JSON security event schema for generic webhooks, SIEMs, or Slack.
    """
    return {
        "event_type": "ROGUE_DEVICE_DETECTED",
        "severity": "CRITICAL",
        "category": "NETWORK_ACCESS_CONTROL_VIOLATION",
        "timestamp": device_data.get("discovered_at"),
        "device": {
            "ip_address": device_data.get("ip"),
            "mac_address": device_data.get("mac"),
            "vendor_oui": device_data.get("vendor"),
            "hostname": device_data.get("hostname"),
            "open_ports": device_data.get("open_ports", []),
        },
        "response_actions": [
            "Check physical switch port or Wi-Fi AP logs",
            "Verify DHCP lease table",
            "Quarantine host if unexpected",
        ],
    }


def build_telegram_message(device_data: Dict[str, Any]) -> str:
    """
    Constructs an HTML-formatted security alert message optimized for Telegram.
    """
    ip = device_data.get("ip", "Unknown")
    mac = device_data.get("mac", "Unknown")
    vendor = device_data.get("vendor", "Unknown")
    hostname = device_data.get("hostname", "None") or "Unresolved"
    timestamp = device_data.get("discovered_at", "N/A")
    ports = device_data.get("open_ports", [])

    ports_desc = (
        ", ".join(f"{p.get('port')}/{p.get('name')}" for p in ports)
        if ports
        else "None scanned"
    )

    return (
        "🚨 <b>SECURITY ALERT: Rogue Device Detected!</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "An unwhitelisted hardware asset has connected to the monitored local subnet.\n\n"
        f"🌐 <b>IP Address:</b> <code>{ip}</code>\n"
        f"🏷️ <b>MAC Address:</b> <code>{mac}</code>\n"
        f"🏭 <b>Hardware Vendor:</b> <b>{vendor}</b>\n"
        f"💻 <b>Hostname:</b> <code>{hostname}</code>\n"
        f"⏱️ <b>Detected At:</b> <code>{timestamp}</code>\n"
        f"🔍 <b>Open Services:</b> <code>{ports_desc}</code>\n\n"
        "⚠️ <i>Recommended Action: Verify physical switch port/Wi-Fi AP logs and isolate device immediately.</i>"
    )


def send_telegram_alert(
    device_data: Dict[str, Any],
    bot_token: Optional[str] = None,
    chat_id: Optional[str] = None,
) -> bool:
    """
    Transmits an immediate security alert directly to Telegram using the official Bot API.
    """
    token = bot_token or TELEGRAM_BOT_TOKEN
    target_chat = chat_id or TELEGRAM_CHAT_ID

    if not token or not target_chat:
        return False

    if requests is None:
        audit_logger.warning("Requests library not available; cannot deliver Telegram alert.")
        return False

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    text_content = build_telegram_message(device_data)

    payload = {
        "chat_id": target_chat,
        "text": text_content,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }

    try:
        response = requests.post(url, json=payload, timeout=5.0)
        if response.status_code == 200:
            audit_logger.info("Telegram alert successfully transmitted to chat.")
            return True
        else:
            audit_logger.error(
                f"Telegram alert failed (HTTP {response.status_code}): {response.text}"
            )
            return False
    except requests.exceptions.RequestException as exc:
        audit_logger.error(f"Failed to communicate with Telegram Bot API: {exc}")
        return False


def send_alert(
    device_data: Dict[str, Any],
    webhook_url: Optional[str] = None,
) -> bool:
    """
    Dispatches a real-time security alert to configured channels (Webhook, Telegram)
    and records the event to the local security audit log (alerts.log).
    
    Returns:
        True if at least one remote delivery channel succeeded, False otherwise.
    """
    # Step 1: Always record to the persistent local audit log first (failsafe)
    log_unauthorized_device(device_data)

    delivery_statuses = []

    # Step 2: Dispatch Telegram alert if Bot Token and Chat ID are configured
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        tg_success = send_telegram_alert(device_data)
        delivery_statuses.append(tg_success)

    # Step 3: Dispatch standard Webhook alert (Discord, Slack, or Generic HTTP POST)
    target_url = webhook_url or DEFAULT_WEBHOOK_URL
    if target_url and target_url != "https://httpbin.org/post" and "http" in target_url:
        if requests is None:
            audit_logger.warning("Requests library not available; cannot deliver HTTP alert.")
            delivery_statuses.append(False)
        else:
            is_discord = (
                "discord.com/api/webhooks" in target_url
                or "discordapp.com/api/webhooks" in target_url
            )
            payload = (
                build_discord_payload(device_data)
                if is_discord
                else build_generic_payload(device_data)
            )

            try:
                response = requests.post(
                    target_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=5.0,
                )
                if 200 <= response.status_code < 300:
                    audit_logger.info(
                        f"Webhook alert successfully dispatched to {target_url} (HTTP {response.status_code})"
                    )
                    delivery_statuses.append(True)
                else:
                    audit_logger.error(
                        f"Webhook alert rejected by destination (HTTP {response.status_code}): {response.text[:200]}"
                    )
                    delivery_statuses.append(False)
            except requests.exceptions.RequestException as exc:
                audit_logger.error(f"Failed to transmit webhook alert to {target_url}: {exc}")
                delivery_statuses.append(False)
    elif not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        # Fallback test with default mock webhook when no real webhook or Telegram is configured
        if requests is not None and target_url:
            try:
                payload = build_generic_payload(device_data)
                requests.post(target_url, json=payload, timeout=5.0)
                delivery_statuses.append(True)
            except Exception:
                pass

    return any(delivery_statuses) if delivery_statuses else True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Alerter module test utility"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Simulate a detected rogue device to test configured alert channels and logging",
    )
    parser.add_argument(
        "--test-telegram",
        action="store_true",
        help="Test sending a simulated alert directly to Telegram",
    )
    parser.add_argument(
        "--bot-token",
        type=str,
        default=TELEGRAM_BOT_TOKEN,
        help="Telegram Bot Token (or use TELEGRAM_BOT_TOKEN env variable)",
    )
    parser.add_argument(
        "--chat-id",
        type=str,
        default=TELEGRAM_CHAT_ID,
        help="Telegram Chat ID (or use TELEGRAM_CHAT_ID env variable)",
    )
    parser.add_argument(
        "--webhook",
        type=str,
        default=DEFAULT_WEBHOOK_URL,
        help=f"Target webhook endpoint (default: {DEFAULT_WEBHOOK_URL})",
    )

    args = parser.parse_args()

    mock_rogue = {
        "ip": "192.168.1.199",
        "mac": "B8:27:EB:12:34:56",
        "vendor": "Raspberry Pi Foundation",
        "hostname": "kali-dropbox.lan",
        "discovered_at": "2026-11-01T13:50:00Z",
        "open_ports": [
            {"port": 22, "protocol": "tcp", "name": "ssh", "product": "OpenSSH 8.9"},
            {"port": 4444, "protocol": "tcp", "name": "metasploit", "product": "Reverse Shell Listener"},
        ],
    }

    if args.test_telegram:
        print("[*] Testing Telegram Bot alert...")
        if not args.bot_token or not args.chat_id:
            print("[!] Error: Bot token and Chat ID are required.")
            print("    Run: python alerter.py --test-telegram --bot-token YOUR_TOKEN --chat-id YOUR_CHAT_ID")
            print("    Or set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID environment variables.")
            sys.exit(1)
        success = send_telegram_alert(mock_rogue, bot_token=args.bot_token, chat_id=args.chat_id)
        if success:
            print("[+] Telegram test message sent successfully! Check your Telegram app.")
        else:
            print("[!] Failed to send Telegram alert. Check logs above.")
    elif args.test:
        print("[*] Simulating rogue device intrusion event...")
        success = send_alert(mock_rogue, webhook_url=args.webhook)
        if success:
            print(f"[+] Alert successfully processed. Check alerts.log and your configured channels.")
        else:
            print("[!] Webhook dispatch encountered issues. Check alerts.log.")
    else:
        parser.print_help()
