"""
main.py - AutoShield Security Automation Pipeline Orchestrator
CYB333 Final Project Defense Engine.

Architecture:
    Phase 1 (ingestion.py): Ingests auth.log and extracts candidate threat IPs.
    Phase 2 (filter.py): Drops RFC 1918 subnets and evaluates AbuseIPDB reputation scores.
    Phase 3 (enforcer.py): Applies temporary UFW block preview/rules via SQLite leases.
    Phase 4 (notifier.py): Records audit events to JSON and posts alerts to Discord.
"""

import argparse
from ingestion import get_failed_login_ips
from filter import sanitize_and_score
from enforcer import apply_blocks, DEFAULT_STATE_FILE
from notifier import log_remediation_record


def run_pipeline(log_file: str = "auth.log", live_apply: bool = False):
    print("=" * 65)
    print("            AutoShield Security Defense Pipeline            ")
    print("=" * 65)
    print(f"[*] Target Authentication Log : {log_file}")
    print(f"[*] Execution Mode            : {'LIVE ENFORCEMENT' if live_apply else 'DRY-RUN (Safe Preview)'}")
    print("-" * 65)

    # Phase 1: Ingestion (Role 1 - Jonathan Santoyo)
    print("\n[Phase 1: Ingestion] Reading authentication telemetry...")
    raw_ips = get_failed_login_ips(log_file)
    print(f"[+] Total candidate IPs found: {len(raw_ips)}")
    print(f"    Extracted IPs: {raw_ips}")

    if not raw_ips:
        print("[*] No authentication failures observed. Pipeline finished.")
        return

    # Phase 2: Validation & Reputation Scoring (Role 2 - Fabian Ferretti)
    print("\n[Phase 2: Validation] Filtering RFC 1918 and querying AbuseIPDB...")
    actionable_threats = sanitize_and_score(raw_ips)
    print(f"[+] Confirmed high-confidence threats: {len(actionable_threats)}")
    for threat in actionable_threats:
        print(f"    - IP: {threat['ip']} | Confidence: {threat['confidence_score']}% | Country: {threat.get('country', 'N/A')}")

    if not actionable_threats:
        print("[*] No threats met the blocking threshold. Pipeline finished.")
        return

    # Phase 3: Host Firewall Enforcement (Role 3 - Jesse Smith)
    print("\n[Phase 3: Enforcement] Dispatching to UFW enforcer engine...")
    threat_ips = [threat["ip"] for threat in actionable_threats]
    apply_blocks(
        threat_ips,
        ttl_seconds=86400,
        apply=live_apply,
        state_file=DEFAULT_STATE_FILE,
        audit_file=None
    )

    # Phase 4: Alerting & Structured Audit Logging (Role 4 - Cody Zibura)
    print("\n[Phase 4: Alerting] Writing audit log and notifying Discord...")
    for threat in actionable_threats:
        log_remediation_record(threat)

    print("\n" + "=" * 65)
    print("[+] AutoShield Pipeline executed successfully.")
    print("=" * 65)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoShield Security Automation Orchestrator")
    parser.add_argument("--log", default="auth.log", help="Path to authentication log file (default: auth.log)")
    parser.add_argument("--apply", action="store_true", help="Apply live firewall rules (defaults to dry-run preview)")
    args = parser.parse_args()

    run_pipeline(log_file=args.log, live_apply=args.apply)