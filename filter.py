"""filter.py - Data Parsing, Validation & Threat Scoring Module.

Part of the AutoShield Project (CYB333 Security Automation).

Role: Data Parsing & Validation Lead (Role 2)
Objective:
    1. Ingest raw candidate IP strings provided by Member 1 (ingestion.py).
    2. Extract IPv4 addresses using regular expressions and validate mathematical
       syntax using Python's native 'ipaddress' module.
    3. Filter out private subnets (RFC 1918) and loopback addresses to prevent
       accidental self-lockouts or internal network disruption.
    4. Query the AbuseIPDB REST API v2 to retrieve live threat confidence scores.
    5. Construct and output a structured list of dictionaries for Member 3 (enforcer.py).

Prerequisites & Installation:
    Before running this module, install the required third-party libraries:
    
    pip install requests python-dotenv
    - requests: Dispatches HTTP GET queries to the AbuseIPDB REST API v2.
    - python-dotenv: Parses local credentials (ABUSEIPDB_API_KEY) from .env.
    (Built-in libraries 'ipaddress', 'os', and 're' require no extra installation).
"""

import ipaddress
import os
import re
from dotenv import load_dotenv
import requests


# Configuration & Secret Management
# Load environment variables from the local .env file.
# Ensures API keys and threat thresholds are not hardcoded in the codebase.
load_dotenv()

# Precompiled regular expression to match standard IPv4 dot-decimal patterns.
# Used to extract raw candidate IP tokens from unstructured text or dirty log entries.
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")



# Module Functions
def extract_and_validate_ips(
    raw_candidates: list[str],
) -> tuple[list[str], list[str], list[str]]:
  """This will extract, validate, and partition the candidates IP strings into public, internal, and malformed sets.

  Args:
      raw_candidates (list[str]): A list of candidate lines or IP strings
        received from the ingestion layer.

  Returns:
      tuple: A 3-element tuple containing:
          - valid_public_ips (list[str]): Valid, globally routable IPv4
            addresses.
          - dropped_internal (list[str]): Addresses flagged as private (RFC
            1918) or loopback.
          - dropped_invalid (list[str]): Malformed strings or non-numeric tokens
            failing validation.
  """
  # Use a set to automatically deduplicate repeated IP entries from noisy log streams
  valid_public_ips = set()
  dropped_internal = []
  dropped_invalid = []

  for entry in raw_candidates:
    # Type check: reject non-string items cleanly
    if not isinstance(entry, str):
      dropped_invalid.append(str(entry))
      continue

    # Search for IPv4 patterns within the candidate string
    found_matches = IPV4_REGEX.findall(entry.strip())
    if not found_matches:
      dropped_invalid.append(entry)
      continue

    # Validate each extracted regex candidate against Python's ipaddress library
    for candidate in found_matches:
      try:
        ip_obj = ipaddress.ip_address(candidate)

        # Defensive whitelisting: drop local loopback (127.0.0.1) and private
        # RFC 1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        if ip_obj.is_private or ip_obj.is_loopback:
          dropped_internal.append(str(ip_obj))
        else:
          # Routable public IP: safe to proceed to threat intelligence scoring
          valid_public_ips.add(str(ip_obj))
      except ValueError:
        # Fails standard octet boundary checks (e.g., octet values > 255)
        dropped_invalid.append(candidate)

  return list(valid_public_ips), dropped_internal, dropped_invalid


def check_abuseipdb_reputation(ip: str, api_key: str | None = None) -> dict:
  """This queries the AbuseIPDB REST API v2 for a given public IP address.

  Args:
      ip (str): The validated public IPv4 string to query.
      api_key (str | None): Optional API key override. If not provided,
        retrieves the value from the ABUSEIPDB_API_KEY environment variable.

  Returns:
      dict: The parsed JSON response data from AbuseIPDB, or a mock response if
      no key is configured.
  """
  # Retrieve the key from arguments or environment variables
  resolved_key = api_key or os.getenv("ABUSEIPDB_API_KEY")

  # Fallback to simulated offline data if no valid key is provided
  if not resolved_key or resolved_key == "your_abuseipdb_api_key_here":
    print(f"[*] [OFFLINE/MOCK] Simulating threat intelligence score for {ip}")
    return {
        "ipAddress": ip,
        "abuseConfidenceScore": 85 if ip.startswith("185.") else 15,
        "totalReports": 50,
        "countryCode": "US",
    }

  # AbuseIPDB API v2 Endpoint Configuration
  url = "https://api.abuseipdb.com/api/v2/check"
  headers = {"Accept": "application/json", "Key": resolved_key}
  params = {
      "ipAddress": ip,
      "maxAgeInDays": 90,  # Query reports submitted within the last 90 days
      "verbose": "",  # Exclude detailed individual user reports to keep payload compact
  }

  try:
    # Send HTTP GET request with a 5-second timeout to prevent socket hangs
    response = requests.get(url, headers=headers, params=params, timeout=5)
    response.raise_for_status()
    data = response.json()
    return data.get("data", {})
  except requests.RequestException as err:
    # Log network or HTTP status errors without terminating the broader pipeline
    print(f"[!] Warning: Failed querying AbuseIPDB for {ip}: {err}")
    return {"ipAddress": ip, "abuseConfidenceScore": 0, "error": str(err)}


def sanitize_and_score(
    raw_ip_list: list[str],
    threshold: int | None = None,
    api_key: str | None = None,
) -> list[dict]:
  """Main integration entry point invoked by the orchestrator (main.py).

  Ingests raw candidates, extracts valid public IPs, queries threat reputation,
  and constructs the actionable block payload for the firewall enforcer.

  Args:
      raw_ip_list (list[str]): Candidate entries from ingestion.py.
      threshold (int | None): Minimum abuse confidence score (0-100) required to
        queue an IP for blocking. Defaults to THREAT_SCORE_THRESHOLD or 75.
      api_key (str | None): Optional API key override for AbuseIPDB.

  Returns:
      list[dict]: A list of actionable target records formatted for enforcer.py.
  """
  # Determine confidence score threshold from parameters or .env
  if threshold is None:
    threshold = int(os.getenv("THREAT_SCORE_THRESHOLD", "75"))

  # Step 1: Clean, deduplicate, and validate IPs
  clean_public_ips, internal_dropped, invalid_dropped = (
      extract_and_validate_ips(raw_ip_list)
  )

  actionable_blocks = []

  # Step 2: Corroborate each public candidate against threat intelligence
  for target_ip in clean_public_ips:
    report = check_abuseipdb_reputation(target_ip, api_key=api_key)
    score = report.get("abuseConfidenceScore", 0)

    # Step 3: Filter by confidence threshold to avoid false positives
    if score >= threshold:
      actionable_blocks.append({
          "ip": target_ip,
          "confidence_score": score,
          "total_reports": report.get("totalReports", 0),
          "country": report.get("countryCode", "UNKNOWN"),
          "action": "BLOCK",
      })

  return actionable_blocks


# -----------------------------------------------------------------------------
# Standalone Unit Test Runner
# -----------------------------------------------------------------------------
if __name__ == "__main__":
  print("=== AutoShield: filter.py Standalone Test Run ===")

  # Representative test cases covering various log formats and threat scenarios
  test_ips = [
      "185.220.101.5",  # Public threat actor (should evaluate score >= 75 and flag)
      "192.168.1.100",  # RFC 1918 Class C private IP (should be dropped)
      "127.0.0.1",  # Localhost loopback (should be dropped)
      "8.8.8.8",  # Benign public DNS (score < 75; should not be queued for blocking)
  ]

  # Execute the sanitization and scoring pipeline
  results = sanitize_and_score(test_ips, threshold=75)

  print("\n--- Final Actionable Block Payload for enforcer.py ---")
  for entry in results:
    print(entry)