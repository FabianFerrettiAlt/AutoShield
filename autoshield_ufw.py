#!/usr/bin/python3
"""Root-side allowlisted adapter for AutoShield-managed UFW deny rules.

Install a root-owned copy at /usr/local/sbin/autoshield-ufw. Do not execute a
user-writable copy through sudo.
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import subprocess
import sys
from collections.abc import Sequence

UFW = "/usr/sbin/ufw"
COMMENT = "AutoShield-managed"
LOCK_FILE = "/run/lock/autoshield-ufw.lock"
STATUS_LINE = re.compile(
    r"^\[\s*\d+\]\s+.+?\s+DENY\s+IN\s+"
    r"(?P<source>\S+)(?:\s+\(v6\))?\s+#\s+AutoShield-managed\s*$"
)
MAX_ADDRESSES = 256


class HelperError(Exception):
    """A helper request or UFW operation failed."""


def normalize_public_ip(candidate: str) -> str:
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise HelperError(f"invalid IP address: {candidate!r}") from exc
    if not address.is_global:
        raise HelperError(f"refusing non-public IP address: {address}")
    return str(address)


def managed_rule_counts(status_output: str) -> dict[str, int]:
    """Count exact single-host sources from AutoShield-commented UFW rules."""
    result: dict[str, int] = {}
    for line in status_output.splitlines():
        match = STATUS_LINE.match(line.strip())
        if match is None:
            continue
        source = match.group("source")
        try:
            network = ipaddress.ip_network(source, strict=False)
        except ValueError:
            continue
        if network.prefixlen == network.max_prefixlen:
            address = str(network.network_address)
            result[address] = result.get(address, 0) + 1
    return result


def managed_addresses(status_output: str) -> set[str]:
    """Extract managed single-host addresses from numbered UFW status output."""
    return set(managed_rule_counts(status_output))


def _run_ufw(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
    environment["LC_ALL"] = "C"
    try:
        result = subprocess.run(
            [UFW, *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise HelperError("UFW command timed out") from exc
    except OSError as exc:
        raise HelperError(f"could not execute UFW: {exc}") from exc
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        raise HelperError(f"UFW command failed (exit {result.returncode}): {message}")
    return result


def _status() -> dict[str, int]:
    result = _run_ufw(["status", "numbered"])
    return managed_rule_counts(result.stdout)


def _apply(action: str, addresses: Sequence[str]) -> list[dict[str, str]]:
    if action not in {"add", "remove"}:
        raise HelperError("action must be add or remove")
    if not addresses or len(addresses) > MAX_ADDRESSES:
        raise HelperError(f"provide between 1 and {MAX_ADDRESSES} addresses")
    normalized = list(dict.fromkeys(normalize_public_ip(address) for address in addresses))

    results: list[dict[str, str]] = []
    rule_counts = _status()
    for address in normalized:
        try:
            count = rule_counts.get(address, 0)
            changed = False
            if action == "add" and count == 0:
                _run_ufw(
                    [
                        "insert",
                        "1",
                        "deny",
                        "from",
                        address,
                        "comment",
                        COMMENT,
                    ]
                )
                rule_counts[address] = 1
                changed = True
            elif action == "remove" and count:
                for _ in range(count):
                    _run_ufw(
                        [
                            "--force",
                            "delete",
                            "deny",
                            "from",
                            address,
                            "comment",
                            COMMENT,
                        ]
                    )
                rule_counts.pop(address, None)
                changed = True
            results.append(
                {
                    "ip_address": address,
                    "action": action,
                    "status": "ok",
                    "changed": str(changed).lower(),
                }
            )
        except HelperError as exc:
            results.append(
                {
                    "ip_address": address,
                    "action": action,
                    "status": "error",
                    "detail": str(exc),
                }
            )
    if action == "remove":
        remaining = _status()
        for result in results:
            if (
                result["status"] == "ok"
                and result["ip_address"] in remaining
            ):
                result["status"] = "error"
                result["detail"] = "managed UFW rule remains after removal"
    return results


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if platform.system() != "Linux":
        print("Error: the UFW helper is supported only on Linux.", file=sys.stderr)
        return 1
    effective_uid = getattr(os, "geteuid", lambda: -1)()
    if effective_uid != 0:
        print("Error: the UFW helper must run as root.", file=sys.stderr)
        return 1
    if len(arguments) < 2 or arguments[0] not in {"add", "remove"}:
        print("Usage: autoshield-ufw {add|remove} PUBLIC_IP [PUBLIC_IP ...]", file=sys.stderr)
        return 2

    try:
        normalized = [normalize_public_ip(address) for address in arguments[1:]]
        if len(normalized) > MAX_ADDRESSES:
            raise HelperError(f"at most {MAX_ADDRESSES} addresses may be batched")
        import fcntl

        lock_descriptor = os.open(
            LOCK_FILE,
            os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            lock_stat = os.fstat(lock_descriptor)
            if lock_stat.st_uid != 0 or lock_stat.st_mode & 0o022:
                raise HelperError("lock file must be root-owned and not group/world-writable")
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            results = _apply(arguments[0], normalized)
        finally:
            os.close(lock_descriptor)
    except (HelperError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({"results": results}, separators=(",", ":"), sort_keys=True))
    return 0 if all(item["status"] == "ok" for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
