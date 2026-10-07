"""
notifier.py - Alerting & Structured Incident Reporting Module
AutoShield Project (CYB333 Security Automation).

Role: Alerting & Reporting Lead (Role 4 - Cody Zibura)
Objective:
    Appends remediation records to a persistent JSON audit file and
    dispatches incident alerts to Discord via webhooks.
"""

from datetime import datetime, timezone
import json
import os
from dotenv import load_dotenv
import requests

# Load environment variables from .env
load_dotenv()

Log_File = "blocked_threats.json"
# Read webhook URL securely from the environment
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")


def log_remediation_record(record_data: dict, filepath: str = Log_File):
    """
    Appends remediation records to a local structured JSON audit log,
    and dispatches a formatted alert card to a Discord webhook if configured.
    """
    records = []

    # 1. Read existing audit file if present and non-empty
    if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
        try:
            with open(filepath, "r") as f:
                records = json.load(f)
        except json.JSONDecodeError:
            print(f"[!] Warning: {filepath} is corrupted or empty, initializing a new log structure.")

    # 2. Append new incident record and write to disk
    records.append(record_data)
    with open(filepath, "w") as f:
        json.dump(records, f, indent=4)
    print(f"[+] Remediation record logged to {filepath}")

    # 3. Guard: skip network call if no valid webhook URL is set
    if not DISCORD_WEBHOOK_URL or DISCORD_WEBHOOK_URL == "https://discord.com" or "your_discord_webhook" in DISCORD_WEBHOOK_URL:
        print("[*] Notice: DISCORD_WEBHOOK_URL not configured. Skipping Discord alert.")
        return

    # 4. Dispatch alert to Discord webhook
    try:
        payload = {
            "embeds": [
                {
                    "title": "🚨 Security Incident Remediation Triggered",
                    "description": f"```json\n{json.dumps(record_data, indent=4)}\n```",
                    "color": 15158332,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            ]
        }
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)

        if response.status_code in (200, 204):
            print("[+] Remediation record successfully sent to Discord.")
        else:
            print(f"[-] Failed to send remediation record to Discord. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"[!] Error occurred while sending remediation record outbound: {e}")


if __name__ == "__main__":
    print("=== AutoShield: notifier.py Standalone Test Run ===")
    sample_payload = {
        "ip": "1.2.3.4",
        "confidence_score": 90,
        "country": "US",
        "action": "BLOCK"
    }
    log_remediation_record(sample_payload)