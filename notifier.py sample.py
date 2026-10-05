import json
import os
from datetime import datetime, timezone
import requests

Log_File = "blocked_threats.json"
DISCORD_WEBHOOK_URL = "https://discord.com"

def log_remediation_record(record_data: dict, filepath: str = Log_File):
    records = []
    if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
        try:
            with open(filepath, "r") as f:
                records = json.load(f)
        except json.JSONDecodeError:
            print(f"Warning: {filepath} is corrupted or empty, initializing a new log structure.")
            
    records.append(record_data)
    with open(filepath, "w") as f:
        json.dump(records, f, indent=4)
    print(f"Remediation record logged to {filepath}")
    try:
        payload = {
            "embeds": [
                {
                    "title": "Security Incident Remediation Triggered",
                    "description": f"```json\n{json.dumps(record_data, indent=4)}\n```",
                    "color": 15158332,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            ]
        }
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload)

        if response.status_code == 204:
            print("Remediation record successfully sent to Discord.")
        else:
            print(f"Failed to send remediation record to Discord. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error occurred while sending remediation record outbound: {e}")

