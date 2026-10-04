"""Verify detached OpenPGP signatures before parsing threat-feed content."""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path
from typing import Sequence

MAX_FEED_BYTES = 5 * 1024 * 1024
MAX_SIGNATURE_BYTES = 1024 * 1024
GPG = "/usr/bin/gpg"
_FINGERPRINT_PATTERN = re.compile(r"(?:[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\Z")


class FeedVerificationError(Exception):
    """The feed is malformed, too large, or not signed by a pinned key."""


def _pinned_fingerprints(values: Sequence[str]) -> set[str]:
    if not values:
        raise FeedVerificationError("at least one trusted fingerprint is required")
    fingerprints = {value.replace(" ", "").upper() for value in values}
    if any(_FINGERPRINT_PATTERN.fullmatch(value) is None for value in fingerprints):
        raise FeedVerificationError("trusted fingerprint must be a 40- or 64-digit hex value")
    return fingerprints


def _read_limited(path: Path, limit: int, label: str) -> bytes:
    try:
        with path.open("rb") as stream:
            content = stream.read(limit + 1)
    except OSError as exc:
        raise FeedVerificationError(f"could not read {label}: {exc}") from exc
    if len(content) > limit:
        raise FeedVerificationError(f"{label} exceeds the {limit}-byte size limit")
    return content


def verify_detached_signature(
    feed_path: Path,
    signature_path: Path,
    trusted_fingerprints: Sequence[str],
    *,
    gnupg_home: Path | None = None,
) -> bytes:
    """Return feed bytes only if GPG validates a signature by a pinned key."""
    pinned = _pinned_fingerprints(trusted_fingerprints)
    feed_bytes = _read_limited(feed_path, MAX_FEED_BYTES, "feed")
    signature_bytes = _read_limited(signature_path, MAX_SIGNATURE_BYTES, "signature")
    if not Path(GPG).is_file():
        raise FeedVerificationError("gpg is required to verify signed feeds")

    with tempfile.TemporaryDirectory(prefix="autoshield-feed-") as temporary_directory:
        temp_dir = Path(temporary_directory)
        temporary_feed = temp_dir / "feed.txt"
        temporary_signature = temp_dir / "feed.txt.asc"
        temporary_feed.write_bytes(feed_bytes)
        temporary_signature.write_bytes(signature_bytes)
        command = [
            GPG,
            "--batch",
            "--no-tty",
            "--no-options",
            "--no-auto-key-retrieve",
        ]
        if gnupg_home is not None:
            command.extend(["--homedir", str(gnupg_home)])
        command.extend(
            [
                "--status-fd",
                "1",
                "--verify",
                str(temporary_signature),
                str(temporary_feed),
            ]
        )
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired as exc:
            raise FeedVerificationError("gpg signature verification timed out") from exc
        except OSError as exc:
            raise FeedVerificationError(f"could not execute gpg: {exc}") from exc

    valid_signers: set[str] = set()
    forbidden_statuses = {
        "BADSIG",
        "ERRSIG",
        "EXPSIG",
        "EXPKEYSIG",
        "REVKEYSIG",
        "KEYREVOKED",
    }
    for line in result.stdout.splitlines():
        if not line.startswith("[GNUPG:] "):
            continue
        fields = line.split()
        if len(fields) > 1 and fields[1] in forbidden_statuses:
            raise FeedVerificationError("feed signature or signing key is expired or revoked")
        if len(fields) < 3 or fields[1] != "VALIDSIG":
            continue
        if len(fields) >= 3:
            valid_signers.add(fields[2].upper())
        if len(fields) >= 12:
            valid_signers.add(fields[-1].upper())
    if result.returncode != 0 or not (valid_signers & pinned):
        raise FeedVerificationError(
            "feed signature is invalid or was not made by a pinned trusted key"
        )
    return feed_bytes


def read_verified_feed(
    feed_path: Path,
    signature_path: Path,
    trusted_fingerprints: Sequence[str],
    *,
    gnupg_home: Path | None = None,
) -> list[str]:
    """Read a verified UTF-8 plain-text feed containing one IP per line."""
    content = verify_detached_signature(
        feed_path,
        signature_path,
        trusted_fingerprints,
        gnupg_home=gnupg_home,
    )
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FeedVerificationError("verified feed must be UTF-8 text") from exc
    candidates = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not candidates:
        raise FeedVerificationError("verified feed contains no IP addresses")
    return candidates
