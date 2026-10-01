# AutoShield: Automated Threat Intelligence & Firewall Enforcer

AutoShield is a defensive security automation pipeline designed to detect suspect network activity, corroborate malicious indicators via external threat intelligence, and programmatically enforce host-level firewall drop rules.

---

## Project Overview

- **Threat Ingestion (`ingestion.py`):** Extracts candidate IP addresses from authentication logs (e.g., `/var/log/auth.log`) or open threat intelligence feeds.
- **Validation & Intelligence (`filter.py`):** Cleans raw data, validates standard IPv4/IPv6 syntax, drops private/loopback subnets (RFC 1918), and queries the AbuseIPDB API for abuse confidence scoring.
- **Firewall Enforcement (`enforcer.py`):** Uses Python's `subprocess` library to execute host firewall commands (`ufw insert 1 deny from <IP>`). Supports a `--dry-run` flag for safe local execution.
- **Incident Alerting (`notifier.py`):** Logs remediation records to `blocked_threats.json` and dispatches structured event cards via Discord webhooks.
- **Pipeline Orchestrator (`main.py`):** Coordinates data flow across modules from a single execution entry point.

---

## Prerequisites & Installation

- **Environment:** Ubuntu Linux (Native, VM, or WSL2)
- **Python Runtime:** Python 3.10+

1. **Clone the repository:**

   git clone <REPO_URL>
   cd <REPO_FOLDER>

-------------------------------------------------------------------------------

## Quick Reference & Development Guidelines

### Git Workflow & Collaboration
* **Pull First:** Always run `git pull origin main` before starting new edits to prevent merge conflicts.
* **Feature Branches:** Develop in personal branches (e.g., `git checkout -b feature/filter-module`) before opening a pull request to `main`.
* **Atomic Commits:** Keep commits focused and descriptive (e.g., `git commit -m "feat(filter): add RFC 1918 regex validation"`).
* **Verify Status:** Check `git status` frequently to avoid accidentally staging untracked files or cache directories.

### Environment & Safety
* **Active Environment:** Ensure your terminal prompt shows your isolated virtual environment before running code or installing libraries.
* **Firewall Safety:** Test locally using `--dry-run` mode to verify command outputs before running live system modifications.
* **Never Hardcode Secrets:** Load API keys and webhook URLs exclusively from environment variables or a local `.env` file[cite: 1]. Verify that keys are not committed to GitHub.
* **Protect Local Subnets:** Always validate candidate IPs against private and loopback ranges (`127.0.0.1`, `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`) before rule generation.

### Code Quality & Standards
* **PEP 8 Formatting:** Use 4-space indentation, descriptive variable names, and keep functions small and modular[cite: 1].
* **Meaningful Logging:** Favor structured log statements (JSON/logging module) over loose `print()` calls for tracking script execution.
* **Defensive Input Handling:** Wrap all external HTTP API requests and system command calls in `try...except` blocks to handle network timeouts and permission errors gracefully[cite: 1].