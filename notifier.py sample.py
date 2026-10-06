import json
#imports json lib
import os
#imports build in os module allowing code to work with os
from datetime import datetime, timezone
#imports datetime with timezone for tracking purposes from datetime
import requests
#imports requests lib

Log_File = "blocked_threats.json"
#Location to send threats with the file name
DISCORD_WEBHOOK_URL = "https://discord.com"
#URL for where all records will be sent for easy viewing in discord channel

def log_remediation_record(record_data: dict, filepath: str = Log_File):
#filepath where recorded data will be sent
    records = []
#records list
    if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
        try:
            with open(filepath, "r") as f:
                records = json.load(f)
##ensures that the filepath exists and isn't empty before trying to open the filepath in read mode and translate using json to Python so it can be stored in the records list
        except json.JSONDecodeError:
            print(f"Warning: {filepath} is corrupted or empty, initializing a new log structure.")
#except stage prevents python from crashing if error is met
            
    records.append(record_data)
    with open(filepath, "w") as f:
        json.dump(records, f, indent=4)
    print(f"Remediation record logged to {filepath}")
#updates data using append, opens filepath in write mode, then converts Python format back to json, and shows that the remediation was loggged through the print statement
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
#try statement to build an automatic payload to be sent to the discord webhook with the title, description, red color, and timestamp features

        if response.status_code == 204:
            print("Remediation record successfully sent to Discord.")
#Error code 204 means successful posting to the webhook so print statement reflects that
        else:
            print(f"Failed to send remediation record to Discord. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error occurred while sending remediation record outbound: {e}")
#If any other code comes back, respond with the else print statement, any network failures prints the except statement

