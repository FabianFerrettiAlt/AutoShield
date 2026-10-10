# AutoShield

AutoShield is a defensive Linux endpoint project for validating threat indicators, applying temporary host firewall blocks, and recording auditable decisions.
# AutoShield: Automated Threat Intelligence & Host Firewall Enforcer
**CYB333: Security Automation - Team 3 Final Project**

AutoShield is an automated defensive security pipeline that parses raw authentication logs, evaluates candidate IP reputation against external threat intelligence (AbuseIPDB), enforces host-level firewall drop rules via Linux UFW, and generates structured incident reports.

> **Current scope:** Batch IP enforcement, temporary UFW rules, JSONL audit events, SQLite lease state, and detached OpenPGP feed verification are implemented. Authentication-log ingestion, AbuseIPDB lookups and its 75% threshold, orchestration of those stages, and webhook alerts remain planned. The enforcement and GPG integration require Linux/UFW/GPG integration testing before production use.

## Design

```text
IP arguments or a signed one-IP-per-line feed
                 |
                 v
   Verify detached signature (when importing a feed)
                 |
                 v
  Validate public addresses and deduplicate the batch
                 |
                 v
 Persist 24-hour leases and JSONL audit events
                 |
                 v
 Narrow sudoers permission -> root-owned UFW helper
                 |
                 v
 Periodic systemd timer removes expired managed rules
```
- **Threat Ingestion (`ingestion.py`):** Ingests system authentication telemetry (`auth.log`), extracts source IP addresses from repeated failed password attempts via regular expressions, and emits raw candidate IPs.
- **Validation & Intelligence (`filter.py`):** Normalizes IP strings, validates standard IPv4/IPv6 syntax, drops private/loopback subnets (RFC 1918) to prevent self-lockouts, queries the AbuseIPDB REST API v2, and outputs structured high-confidence threat dictionaries.
- **Firewall Enforcement (`enforcer.py` & `feed_verifier.py`):** Consumes actionable threat dictionaries, manages expiring lease states (`blocks.sqlite3`), and executes host-level packet filtering commands (`ufw insert 1 deny from <IP>`). Defaults to a non-destructive `--dry-run` simulation mode.
- **Incident Alerting (`notifier.py`):** Appends confirmed incident records to a persistent local audit file (`blocked_threats.json`) and dispatches formatted threat cards to an external Discord webhook.
- **Pipeline Orchestrator (`main.py`):** Coordinates in-memory data handoffs sequentially across Phases 1 through 4 from a single execution entry point.

The CLI defaults to preview-only behavior. A live request requires `--apply`. The UFW helper adds only deny rules for public host addresses, tags them with `AutoShield-managed`, and removes only rules carrying that tag. A SQLite database tracks lease expiration and makes repeated requests for an address idempotent. A systemd timer checks for expired leases once per minute; expiration therefore occurs on the first successful cleanup run after the deadline, not at a precise second. These are userspace-managed leases, not kernel-enforced timeouts: if the timer is disabled, the service account loses its sudo permission, or cleanup repeatedly fails, an expired rule can remain in UFW. Keep the state database and timer, monitor service failures, and maintain a recovery path.

Multiple addresses are validated, deduplicated, audited, and sent to the privileged helper in one batch (up to 256 addresses). UFW still receives a separate operation per address. The async validation API moves one whole batch to a worker thread so it does not block an async caller; it is not a claim of faster CPU-bound IP parsing. Network reputation lookups are not implemented yet.

## Run safely

Preview one or more public addresses:

```bash
python3 enforcer.py 8.8.8.8 1.1.1.1
python3 enforcer.py 8.8.8.8 --ttl 30m --dry-run
```

Preview all expired rules recorded in the state database:

```bash
python3 enforcer.py --expire --state-file /var/lib/autoshield/blocks.sqlite3
```

Live operation is explicit:

```bash
python3 enforcer.py 8.8.8.8 1.1.1.1 --ttl 24h --apply \
  --state-file /var/lib/autoshield/blocks.sqlite3 \
  --audit-file /var/log/autoshield/audit.jsonl
python3 enforcer.py --expire --apply \
  --state-file /var/lib/autoshield/blocks.sqlite3 \
  --audit-file /var/log/autoshield/audit.jsonl
```

The default lease is 24 hours; `--ttl` accepts positive seconds, minutes, hours, or days (for example `900s`, `30m`, `24h`, `7d`) and is capped at 30 days. Invalid, private, loopback, link-local, and other non-global addresses reject the entire batch. Audit records are JSON Lines with UTC timestamps, event IDs, actions, outcomes, IPs, and expiry times. Credentials and webhook URLs are not part of this enforcement module.

`--apply` expects a correctly installed root-owned helper at `/usr/local/sbin/autoshield-ufw`, UFW at `/usr/sbin/ufw`, and the narrowly scoped sudoers permission below. The tool will not install or edit sudoers rules itself.

## Least-privilege deployment

These are deployment templates, not an automatic installer. Review them for your host before enabling a system service.

1. Provision a dedicated non-login `autoshield` account. Install the application in a root-owned, non-writable location such as `/opt/autoshield`; do not point sudo at a copy writable by the service account.
2. Confirm UFW is installed at `/usr/sbin/ufw` (or update the root-owned helper to the verified absolute path). Install the helper and validate its ownership and permissions:

   ```bash
   sudo install -o root -g root -m 0755 autoshield_ufw.py /usr/local/sbin/autoshield-ufw
   sudo stat -c '%U:%G %a %n' /usr/local/sbin/autoshield-ufw
   ```

3. Review [the sudoers template](./deploy/autoshield-ufw.sudoers), install it as `/etc/sudoers.d/autoshield` with root ownership and mode `0440`, then validate it:

   ```bash
   sudo install -o root -g root -m 0440 deploy/autoshield-ufw.sudoers /etc/sudoers.d/autoshield
   sudo visudo -cf /etc/sudoers.d/autoshield
   ```

   The sudoers entry permits only the root-owned helper executable, not arbitrary UFW commands. The helper accepts only `add` or `remove` plus validated public IPs, uses fixed UFW arguments and a shell-free subprocess call, serializes operations with a root-owned lock, and checks UFW's tagged rules before acting. Because sudoers allows arguments to that helper, keeping the installed helper root-owned and reviewed is essential.

4. Create the state and log directories for the service account (and verify ownership):

   ```bash
   sudo install -d -o autoshield -g autoshield -m 0750 /var/lib/autoshield /var/log/autoshield
   ```

5. Install the app at `/opt/autoshield` and review [the expiry service](./deploy/autoshield-expire.service) and [timer](./deploy/autoshield-expire.timer). Enable the timer only after testing UFW behavior and sudo delegation:

   ```bash
   sudo install -o root -g root -m 0644 deploy/autoshield-expire.service /etc/systemd/system/
   sudo install -o root -g root -m 0644 deploy/autoshield-expire.timer /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now autoshield-expire.timer
   ```

The service uses the same state file as the CLI and runs under the dedicated account. It does not enable UFW, install keys, modify firewall defaults, or guarantee recovery from unrelated administrator changes. Test expiry and removal on a disposable Linux VM before using it on a host where connectivity matters. Keep an independent recovery path available.

## Legal and responsible use

AutoShield is a defensive administration tool, not legal advice or a certification of compliance. This project is intended for systems you own or for which you have explicit authorization to administer. Obtain any required written approval and follow the system owner's scope, school rules, employer policies, and incident-response procedures. Do not run it against third-party systems or use it to collect logs outside that authorization.

Authentication logs can contain IP addresses, usernames, and other information about people. Before implementing log ingestion, limit collection to what the project needs, restrict access to stored logs, set a short retention period, and use synthetic or redacted data for classroom demonstrations. Before sending indicators or incident data to an external API or webhook, review the service's terms and privacy practices and the data owner's rules; avoid sending usernames, raw log lines, or other unnecessary data. These integrations are planned and are not currently implemented.

Verify the usage and redistribution terms for each threat feed. A valid digital signature helps establish that feed content came from a particular signing key and was not changed; it does not grant permission to use or redistribute the feed. Blocking a public address can disrupt legitimate traffic, so use a test environment, an approved decision process, and a recovery plan.

This note is not a jurisdiction-by-jurisdiction legal review. Deployment outside the United States, production use, handling other people's data, or redistribution may trigger additional legal, contractual, privacy, or institutional requirements. Ask your instructor, system owner, privacy/compliance contact, or qualified attorney about the specific deployment before proceeding.

## Import a signed feed

The supported feed format is UTF-8 text with one IP address per line; empty lines and lines beginning with `#` are ignored. The detached OpenPGP signature must verify with GPG at `/usr/bin/gpg`, and at least one exact 40- or 64-hex-character signer fingerprint must be explicitly pinned. AutoShield does not download feeds, retrieve or import keys, or trust a key merely because it exists in the keyring. Signature verification establishes the signed content and signer, not feed freshness; use a trusted source process to reject stale feed releases.

```bash
python3 enforcer.py \
  --feed ./indicators.txt \
  --signature ./indicators.txt.asc \
  --trusted-fingerprint 0123456789ABCDEF0123456789ABCDEF01234567 \
  --gnupg-home /path/to/verified/keyring \
  --dry-run
```

Feed content is copied to a private temporary directory before verification and parsing, preventing a change between signature verification and consumption. Feed and signature sizes are capped. Protect the GPG keyring and independently verify signer fingerprints through a trusted channel.

## Planned end-to-end pipeline

The long-term pipeline will parse failed-authentication events (such as `/var/log/auth.log`) or verified feeds, normalize and validate candidate IPs, query AbuseIPDB, compare its abuse-confidence score with a configurable threshold (initially 75%), apply a temporary block, write an audit event, and send an incident card containing the IP, timestamp, and reputation score. Log ingestion, AbuseIPDB integration, scoring policy, and webhook delivery are not yet implemented. Reputation data must not override address validation or be treated as proof when a lookup fails.

## Tests

Run the standard-library unit tests without changing firewall state:

```bash
python3 -m unittest -v test_enforcer
```

Tests mock privileged commands and GPG; they do not replace Linux integration tests for UFW version differences and status formatting, sudoers parsing, actual expiry cleanup, or systemd sandbox behavior. The JSONL audit log is local operational evidence, not tamper-proof storage; protect and rotate it appropriately, and forward it to a separately administered log service for stronger audit guarantees.
## Team Contributions & Role Breakdown

* **Jonathan Santoyo (Threat Ingestion Lead - `ingestion.py`):** Developed authentication log ingestion, regular expression extraction of failed login candidates, and initial test drivers.
* **Fabian Ferretti (Data Parsing & Validation Lead - `filter.py`):** Implemented syntax validation, RFC 1918 private IP whitelisting, live AbuseIPDB REST API scoring, error handling, and pipeline orchestration.
* **Jesse Smith (Firewall Automation Lead - `enforcer.py` & `feed_verifier.py`):** Built the host firewall execution engine, SQLite expiration lease tracking, detached GPG feed verification, and dry-run preview capabilities.
* **Cody Zibura (Alerting & Reporting Lead - `notifier.py`):** Implemented the structured JSON remediation logger (`blocked_threats.json`) and outbound Discord webhook alerting logic.

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
