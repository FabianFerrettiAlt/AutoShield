# AutoShield: Automated Threat Intelligence & Host Firewall Enforcer
**CYB333: Security Automation — Team 3 Final Project**

AutoShield is an automated defensive security pipeline that parses raw authentication logs, evaluates candidate IP reputation against external threat intelligence (AbuseIPDB), enforces host-level firewall drop rules via Linux UFW, and generates structured incident reports.

---

## Project Overview

- **Threat Ingestion (`ingestion.py`):** Ingests system authentication telemetry (`auth.log`), extracts source IP addresses from repeated failed password attempts via regular expressions, and emits raw candidate IPs.
- **Validation & Intelligence (`filter.py`):** Normalizes IP strings, validates standard IPv4/IPv6 syntax, drops private/loopback subnets (RFC 1918) to prevent self-lockouts, queries the AbuseIPDB REST API v2, and outputs structured high-confidence threat dictionaries.
- **Firewall Enforcement (`enforcer.py` & `feed_verifier.py`):** Consumes actionable threat dictionaries, manages expiring lease states (`blocks.sqlite3`), and executes host-level packet filtering commands (`ufw insert 1 deny from <IP>`). Defaults to a non-destructive `--dry-run` simulation mode.
- **Incident Alerting (`notifier.py`):** Appends confirmed incident records to a persistent local audit file (`blocked_threats.json`) and dispatches formatted threat cards to an external Discord webhook.
- **Pipeline Orchestrator (`main.py`):** Coordinates in-memory data handoffs sequentially across Phases 1 through 4 from a single execution entry point.

---

## Team Contributions & Role Breakdown

* **Jonathan Santoyo (Threat Ingestion Lead — `ingestion.py`):** Developed authentication log ingestion, regular expression extraction of failed login candidates, and initial test drivers.
* **Fabian Ferretti (Data Parsing & Validation Lead — `filter.py`):** Implemented syntax validation, RFC 1918 private IP whitelisting, live AbuseIPDB REST API scoring, error handling, and pipeline orchestration.
* **Jesse Smith (Firewall Automation Lead — `enforcer.py` & `feed_verifier.py`):** Built the host firewall execution engine, SQLite expiration lease tracking, detached GPG feed verification, and dry-run preview capabilities.
* **Cody Zibura (Alerting & Reporting Lead — `notifier.py`):** Implemented the structured JSON remediation logger (`blocked_threats.json`) and outbound Discord webhook alerting logic.

---

## Architecture & Data Flow

```text
[ auth.log ] 
      │
      ▼
1. ingestion.py ──(Raw Candidate IPs)──► 2. filter.py 
                                               │
                                      (AbuseIPDB Scoring &
                                      RFC 1918 Whitelisting)
                                               │
                                               ▼
4. notifier.py ◄──(Remediation Event)── 3. enforcer.py
        │                                      │
 ┌──────┴──────────────┐                       ▼
 ▼                     ▼               [ UFW Host Firewall ]
blocked_threats.json  Discord Alert      (SQLite Lease DB)