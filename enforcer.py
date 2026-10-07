"""Preview or apply expiring UFW blocks for validated public IP addresses."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from feed_verifier import FeedVerificationError, read_verified_feed

# Keep default blocks finite and place an upper bound on accidental long-lived rules.
DEFAULT_TTL_SECONDS = 24 * 60 * 60
MAX_TTL_SECONDS = 30 * 24 * 60 * 60
# Bound each subprocess argument list; large expiry queues are split into batches.
MAX_BATCH_SIZE = 256
# Put persistent state and audit output under a per-user state directory by default.
DEFAULT_STATE_FILE = Path.home() / ".local/state/autoshield/blocks.sqlite3"
DEFAULT_AUDIT_FILE = Path.home() / ".local/state/autoshield/audit.jsonl"
# Pin executable paths so PATH changes cannot select a different privileged program.
SUDO = "/usr/bin/sudo"
PRIVILEGED_HELPER = "/usr/local/sbin/autoshield-ufw"
# Accept only a positive integer followed by a supported duration unit.
_DURATION_PATTERN = re.compile(r"([1-9][0-9]*)([smhd])\Z")


class EnforcerError(Exception):
    """An expected validation, persistence, or enforcement failure."""


def parse_duration(value: str) -> int:
    """Parse a positive duration such as 30m or 24h, capped at 30 days."""
    # Full-match the input so extra characters cannot silently change the duration.
    match = _DURATION_PATTERN.fullmatch(value)
    if match is None:
        raise argparse.ArgumentTypeError(
            "duration must be a positive integer followed by s, m, h, or d"
        )
    # Convert the user-selected unit to seconds and reject excessive leases.
    amount = int(match.group(1))
    multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
    seconds = amount * multiplier
    if seconds > MAX_TTL_SECONDS:
        raise argparse.ArgumentTypeError("duration must not exceed 30 days")
    return seconds


def _normalize_public_ip(candidate: str) -> str:
    # Parse with the standard library; regex extraction alone is not validation.
    try:
        address = ipaddress.ip_address(candidate.strip())
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {candidate!r}") from exc
    # Avoid self-lockouts and unusable/special-purpose destinations.
    if not address.is_global:
        raise ValueError(f"refusing non-public IP address: {address}")
    return str(address)


def build_helper_command(action: str, candidates: Sequence[str]) -> list[str]:
    """Build a shell-free command for the fixed, root-owned helper."""
    # Limit operations to the helper's two supported actions.
    if action not in {"add", "remove"}:
        raise ValueError(f"unsupported helper action: {action}")
    # Normalize IP spellings and preserve only the first occurrence of each address.
    addresses = list(dict.fromkeys(_normalize_public_ip(value) for value in candidates))
    if not addresses:
        raise ValueError("at least one public IP address is required")
    if len(addresses) > MAX_BATCH_SIZE:
        raise ValueError(f"at most {MAX_BATCH_SIZE} addresses may be batched")
    # Pass every value as its own argv element; never interpolate into a shell string.
    return [
        SUDO,
        "-n",
        "--",
        PRIVILEGED_HELPER,
        action,
        *addresses,
    ]


def validate_candidates(candidates: Sequence[str]) -> list[str]:
    """Validate and deduplicate a batch, preserving input order."""
    # Enforce the same work limit before iterating over untrusted input.
    if len(candidates) > MAX_BATCH_SIZE:
        raise EnforcerError(f"at most {MAX_BATCH_SIZE} addresses may be batched")
    # Keep accepted values, duplicate detection, and validation errors separately.
    accepted: list[str] = []
    seen: set[str] = set()
    errors: list[str] = []
    for candidate in candidates:
        try:
            # Invalid input makes the whole batch fail rather than partially block.
            address = _normalize_public_ip(candidate)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        # Preserve ordering while eliminating repeated canonical addresses.
        if address not in seen:
            accepted.append(address)
            seen.add(address)
    # Report all rejected values together so an operator can correct a feed batch.
    if errors:
        raise EnforcerError("; ".join(errors))
    return accepted


async def validate_candidates_async(candidates: Sequence[str]) -> list[str]:
    """Validate a complete batch off the event loop for async pipeline callers."""
    # Parsing is small, but moving it to a worker avoids blocking future async callers.
    return await asyncio.to_thread(validate_candidates, candidates)


def _utc_timestamp(timestamp: float | None = None) -> str:
    # Use current UTC time unless the caller supplies a Unix expiry timestamp.
    value = time.time() if timestamp is None else timestamp
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def emit_event(
    event: str,
    *,
    audit_file: Path | None,
    address: str | None = None,
    status: str,
    expires_at: float | None = None,
    detail: str | None = None,
    to_stderr: bool = False,
) -> None:
    """Emit one JSON log event, appending it durably when an audit file is set."""
    # Adapt a single event to the same batched logging path used by larger operations.
    specification: dict[str, Any] = {"event": event, "status": status}
    if address is not None:
        specification["ip_address"] = address
    if expires_at is not None:
        specification["expires_at"] = expires_at
    if detail:
        specification["detail"] = detail
    emit_events([specification], audit_file=audit_file, to_stderr=to_stderr)


def emit_events(
    events: Sequence[Mapping[str, Any]],
    *,
    audit_file: Path | None,
    to_stderr: bool = False,
) -> None:
    """Append and emit a batch of JSON events with one durable file sync."""
    # Avoid file opens and output when there is nothing to record.
    if not events:
        return
    # Add correlation IDs and timestamps, then convert epoch expiries to UTC strings.
    records: list[dict[str, Any]] = []
    for specification in events:
        record: dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "timestamp": _utc_timestamp(),
            "event": specification["event"],
            "status": specification["status"],
        }
        if "ip_address" in specification:
            record["ip_address"] = specification["ip_address"]
        if "expires_at" in specification:
            record["expires_at"] = _utc_timestamp(specification["expires_at"])
        if "detail" in specification:
            record["detail"] = specification["detail"]
        records.append(record)
    # JSON Lines keeps each event independently machine-readable and appendable.
    output = "".join(
        json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n"
        for record in records
    )
    if audit_file is not None:
        try:
            # Create a private parent directory and append without following symlinks.
            audit_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(
                audit_file,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_APPEND
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                # Restrict an existing file too; the open mode only controls new files.
                fchmod = getattr(os, "fchmod", None)
                if fchmod is not None:
                    fchmod(descriptor, 0o600)
                # Handle partial OS writes and sync the completed batch to disk.
                payload = memoryview(output.encode("utf-8"))
                while payload:
                    written = os.write(descriptor, payload)
                    if written == 0:
                        raise OSError("audit append wrote no data")
                    payload = payload[written:]
                os.fsync(descriptor)
            finally:
                # Close the descriptor whether writing, syncing, or permission-setting fails.
                os.close(descriptor)
        except OSError as exc:
            raise EnforcerError(f"could not write audit event: {exc}") from exc
    # Echo the same JSON records to the selected stream for interactive use or errors.
    print(output, end="", file=sys.stderr if to_stderr else sys.stdout)


def _connect_state(state_file: Path, *, read_only: bool = False) -> sqlite3.Connection:
    # A previewed expiry scan must not create or alter the persistent database.
    if read_only:
        connection = sqlite3.connect(
            f"{state_file.resolve().as_uri()}?mode=ro",
            uri=True,
            timeout=30,
            isolation_level=None,
        )
        # Make accidental updates fail even if a later code path is added here.
        connection.execute("PRAGMA query_only = ON")
        return connection

    # Ensure the state directory exists, then allow concurrent clients to wait for locks.
    state_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    connection = sqlite3.connect(state_file, timeout=30, isolation_level=None)
    connection.execute("PRAGMA busy_timeout = 30000")
    # Store canonical IPs as primary keys for idempotency and track retryable transitions.
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS blocks (
            ip_address TEXT PRIMARY KEY,
            expires_at REAL NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('pending', 'active', 'removing')),
            updated_at REAL NOT NULL
        )
        """
    )
    try:
        # Restrict the database file because it controls which firewall rules are removed.
        state_file.chmod(0o600)
    except OSError:
        connection.close()
        raise
    return connection


def _run_helper(action: str, addresses: Sequence[str]) -> None:
    # Revalidate at the subprocess boundary before invoking the privileged helper.
    command = build_helper_command(action, addresses)
    try:
        # Capture output for a clear failure report and prevent indefinite command hangs.
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired as exc:
        # A timeout does not prove whether UFW applied some or all of the batch.
        raise EnforcerError(
            f"privileged UFW helper timed out during {action}; firewall state is unknown"
        ) from exc
    except OSError as exc:
        raise EnforcerError(f"could not execute privileged UFW helper: {exc}") from exc
    # Treat every non-zero helper result as a failed operation, not a success-shaped fallback.
    if result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip()
        message = f"privileged UFW helper failed during {action} (exit {result.returncode})"
        if details:
            message = f"{message}: {details}"
        raise EnforcerError(message)


def apply_blocks(
    addresses: Sequence[str],
    *,
    ttl_seconds: int,
    apply: bool,
    state_file: Path,
    audit_file: Path | None,
) -> int:
    # Validate again for library callers that bypass the command-line parser.
    addresses = validate_candidates(addresses)
    if not addresses:
        raise EnforcerError("at least one public IP address is required")
    if not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise EnforcerError(f"block duration must be between 1 and {MAX_TTL_SECONDS} seconds")
    # Persist one common expiry timestamp per address for this requested batch.
    now = time.time()
    expirations = {address: now + ttl_seconds for address in addresses}
    if not apply:
        # A preview may be audited, but it must not create state or call sudo.
        emit_events(
            [
                {
                    "event": "block_preview",
                    "ip_address": address,
                    "status": "dry_run",
                    "expires_at": expires_at,
                }
                for address, expires_at in expirations.items()
            ],
            audit_file=audit_file,
        )
        return 0

    try:
        # Open/create the private lease database before attempting live changes.
        connection = _connect_state(state_file)
    except (OSError, sqlite3.Error) as exc:
        raise EnforcerError(f"could not initialize block state: {exc}") from exc

    try:
        # Record intended state first so a crash or failed subprocess remains visible/retryable.
        connection.execute("BEGIN IMMEDIATE")
        emit_events(
            [
                {
                    "event": "block_requested",
                    "ip_address": address,
                    "status": "pending",
                    "expires_at": expires_at,
                }
                for address, expires_at in expirations.items()
            ],
            audit_file=audit_file,
        )
        connection.executemany(
            """
            INSERT INTO blocks(ip_address, expires_at, status, updated_at)
            VALUES (?, ?, 'pending', ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                expires_at = excluded.expires_at,
                status = 'pending',
                updated_at = excluded.updated_at
            """,
            (
                (address, expires_at, now)
                for address, expires_at in expirations.items()
            ),
        )
        # Commit the pending records before any system firewall command runs.
        connection.execute("COMMIT")

        # Hold a write transaction while the helper applies the batch and state transitions.
        connection.execute("BEGIN IMMEDIATE")
        _run_helper("add", addresses)
        updated_at = time.time()
        connection.executemany(
            "UPDATE blocks SET status = 'active', updated_at = ? WHERE ip_address = ?",
            ((updated_at, address) for address in expirations),
        )
        # Mark successful rules active only after the helper reports success.
        emit_events(
            [
                {
                    "event": "block_applied",
                    "ip_address": address,
                    "status": "active",
                    "expires_at": expires_at,
                }
                for address, expires_at in expirations.items()
            ],
            audit_file=audit_file,
        )
        connection.execute("COMMIT")
        return 0
    except Exception:
        # Revert only the uncommitted transaction; previously committed pending state survives.
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        # Always release SQLite handles and locks.
        connection.close()


def expire_blocks(
    *,
    apply: bool,
    state_file: Path,
    audit_file: Path | None,
) -> int:
    # Avoid creating an empty state database during a no-op expiry scan.
    if not state_file.exists():
        emit_event("expiry_scan", audit_file=audit_file, status="no_state")
        return 0
    try:
        # Preview opens read-only; live cleanup takes a write lock to serialize removals.
        connection = _connect_state(state_file, read_only=not apply)
    except (OSError, sqlite3.Error) as exc:
        raise EnforcerError(f"could not open block state: {exc}") from exc

    try:
        # Select due leases in stable order so repeated cleanup runs are predictable.
        connection.execute("BEGIN IMMEDIATE" if apply else "BEGIN")
        now = time.time()
        due = [
            row[0]
            for row in connection.execute(
                "SELECT ip_address FROM blocks WHERE expires_at <= ? ORDER BY ip_address",
                (now,),
            )
        ]
        if not due:
            emit_event("expiry_scan", audit_file=audit_file, status="nothing_due")
            connection.execute("COMMIT")
            return 0
        if not apply:
            # Report expired candidates without changing the database or the firewall.
            emit_events(
                [
                    {
                        "event": "block_expiry_preview",
                        "ip_address": address,
                        "status": "dry_run",
                    }
                    for address in due
                ],
                audit_file=audit_file,
            )
            connection.execute("COMMIT")
            return 0

        # Mark removals before touching UFW; failed cleanup leaves these rows for retry.
        emit_events(
            [
                {
                    "event": "block_expiry_requested",
                    "ip_address": address,
                    "status": "pending",
                }
                for address in due
            ],
            audit_file=audit_file,
        )
        connection.executemany(
            "UPDATE blocks SET status = 'removing', updated_at = ? WHERE ip_address = ?",
            ((now, address) for address in due),
        )
        # Split large expiry queues to respect the helper's per-call batch limit.
        for offset in range(0, len(due), MAX_BATCH_SIZE):
            _run_helper("remove", due[offset : offset + MAX_BATCH_SIZE])
        # Forget leases only after every corresponding UFW removal completed successfully.
        connection.executemany(
            "DELETE FROM blocks WHERE ip_address = ?",
            ((address,) for address in due),
        )
        emit_events(
            [
                {
                    "event": "block_expired",
                    "ip_address": address,
                    "status": "removed",
                }
                for address in due
            ],
            audit_file=audit_file,
        )
        connection.execute("COMMIT")
        return 0
    except Exception:
        # Keep leases for another timer run if a UFW call or audit write fails.
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        # Ensure the database file is not held open after the scan.
        connection.close()


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    # Define the CLI for direct addresses, signed feeds, expiry scans, and safety controls.
    parser = argparse.ArgumentParser(
        description="Preview or apply temporary UFW deny rules for public IPs."
    )
    # Accept a batch of addresses as positionals or load a signed feed instead.
    parser.add_argument(
        "ip_addresses",
        nargs="*",
        help="one or more public IPv4 or IPv6 addresses",
    )
    # A feed is trusted only when a detached signature and pinned signer are supplied.
    parser.add_argument("--feed", type=Path, help="plain-text, one-IP-per-line signed feed")
    parser.add_argument("--signature", type=Path, help="detached OpenPGP signature")
    # Bound duration and make the expiry operation explicit.
    parser.add_argument(
        "--trusted-fingerprint",
        action="append",
        default=[],
        help="pinned signer fingerprint (repeat for multiple trusted signers)",
    )
    parser.add_argument("--gnupg-home", type=Path, help="GPG keyring containing trusted keys")
    # Allow state and audit locations to be moved to service-owned Linux directories.
    parser.add_argument(
        "--ttl",
        type=parse_duration,
        default=DEFAULT_TTL_SECONDS,
        metavar="DURATION",
        help="block duration (e.g. 30m, 24h, 7d; default: 24h, maximum: 30d)",
    )
    parser.add_argument(
        "--expire",
        action="store_true",
        help="remove all expired AutoShield blocks",
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=DEFAULT_STATE_FILE,
        help=f"SQLite lease database (default: {DEFAULT_STATE_FILE})",
    )
    parser.add_argument(
        "--audit-file",
        type=Path,
        default=DEFAULT_AUDIT_FILE,
        help=f"JSONL audit log (default: {DEFAULT_AUDIT_FILE})",
    )
    # Require an explicit opt-in for system changes; preview remains the default.
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="preview changes without modifying the firewall (the default)",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        help="apply changes through the narrowly scoped privileged helper",
    )
    args = parser.parse_args(argv)

    # Reject ambiguous combinations early, before reading feeds or touching state.
    if args.expire:
        if args.ip_addresses or args.feed or args.signature or args.trusted_fingerprint:
            parser.error("--expire cannot be combined with IP addresses or feed options")
        if args.gnupg_home:
            parser.error("--gnupg-home is only valid with --feed")
    elif args.feed:
        if args.ip_addresses:
            parser.error("provide IP addresses or --feed, not both")
        if not args.signature or not args.trusted_fingerprint:
            parser.error(
                "--feed requires --signature and at least one --trusted-fingerprint"
            )
        if args.gnupg_home and not args.gnupg_home.is_dir():
            parser.error("--gnupg-home must be an existing directory")
    elif (
        args.signature
        or args.trusted_fingerprint
        or args.gnupg_home
        or not args.ip_addresses
    ):
        parser.error("provide one or more IP addresses or a fully verified --feed")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    # Parse and validate CLI intent before reading any candidate data.
    args = _parse_args(argv)
    try:
        # Select either command-line candidates or content authenticated by GPG.
        candidates = args.ip_addresses
        if args.feed:
            candidates = read_verified_feed(
                args.feed,
                args.signature,
                args.trusted_fingerprint,
                gnupg_home=args.gnupg_home,
            )
        # Keep validation API-compatible with an async orchestrator without blocking its loop.
        addresses = asyncio.run(validate_candidates_async(candidates))
        if args.expire:
            # Expiry mode operates only on previously recorded AutoShield leases.
            return expire_blocks(
                apply=args.apply,
                state_file=args.state_file,
                audit_file=args.audit_file,
            )
        # Normal mode previews or applies the validated batch using the requested lease.
        return apply_blocks(
            addresses,
            ttl_seconds=args.ttl,
            apply=args.apply,
            state_file=args.state_file,
            audit_file=args.audit_file,
        )
    except (EnforcerError, FeedVerificationError, ValueError, OSError, sqlite3.Error) as exc:
        # Report operational failures as structured records, including audit-write failures.
        try:
            emit_event(
                "operation_failed",
                audit_file=args.audit_file,
                status="error",
                detail=str(exc),
                to_stderr=True,
            )
        except EnforcerError as audit_error:
            # Keep an error visible even when its configured audit destination is unavailable.
            print(
                json.dumps(
                    {
                        "event_id": str(uuid.uuid4()),
                        "timestamp": _utc_timestamp(),
                        "event": "operation_failed",
                        "status": "error",
                        "detail": str(exc),
                        "audit_error": str(audit_error),
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
        return 1


if __name__ == "__main__":
    # Convert the CLI's integer result into the process exit code.
    raise SystemExit(main())
