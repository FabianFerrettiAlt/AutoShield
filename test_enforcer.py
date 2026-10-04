import asyncio
import argparse
import contextlib
import io
import json
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import Mock, patch

import autoshield_ufw
import enforcer
import feed_verifier

TRUSTED_FINGERPRINT = "0123456789ABCDEF" * 2 + "01234567"


class AddressValidationTests(unittest.TestCase):
    def test_normalizes_public_ipv4_and_ipv6(self):
        self.assertEqual(enforcer.validate_candidates([" 8.8.8.8 "]), ["8.8.8.8"])
        self.assertEqual(
            enforcer.validate_candidates(["2001:4860:4860::8888"]),
            ["2001:4860:4860::8888"],
        )

    def test_deduplicates_normalized_addresses_preserving_order(self):
        self.assertEqual(
            enforcer.validate_candidates(["8.8.8.8", " 8.8.8.8 ", "1.1.1.1"]),
            ["8.8.8.8", "1.1.1.1"],
        )

    def test_rejects_invalid_and_non_public_addresses(self):
        for candidate in ("not-an-ip", "10.0.0.1", "127.0.0.1", "169.254.1.1", "::1"):
            with self.subTest(candidate=candidate):
                with self.assertRaises(enforcer.EnforcerError):
                    enforcer.validate_candidates([candidate])

    def test_async_batch_validation(self):
        self.assertEqual(
            asyncio.run(enforcer.validate_candidates_async(["8.8.8.8", "1.1.1.1"])),
            ["8.8.8.8", "1.1.1.1"],
        )

    def test_duration_parser_caps_duration(self):
        self.assertEqual(enforcer.parse_duration("24h"), 86400)
        self.assertEqual(enforcer.parse_duration("7d"), 604800)
        for invalid in ("0h", "2w", "31d", "-2h", "2h "):
            with self.subTest(invalid=invalid):
                with self.assertRaises(argparse.ArgumentTypeError):
                    enforcer.parse_duration(invalid)


class AuditAndBlockStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        root = Path(self.temporary_directory.name)
        self.state_file = root / "state" / "blocks.sqlite3"
        self.audit_file = root / "logs" / "audit.jsonl"

    def read_events(self):
        return [
            json.loads(line)
            for line in self.audit_file.read_text(encoding="utf-8").splitlines()
        ]

    def test_dry_run_does_not_create_state_or_run_helper(self):
        with patch("enforcer._run_helper") as run:
            result = enforcer.apply_blocks(
                ["8.8.8.8"],
                ttl_seconds=3600,
                apply=False,
                state_file=self.state_file,
                audit_file=self.audit_file,
            )

        self.assertEqual(result, 0)
        self.assertFalse(self.state_file.exists())
        run.assert_not_called()
        self.assertEqual(self.read_events()[0]["status"], "dry_run")

    def test_applies_deduplicated_batch_and_persists_expiry(self):
        with patch("enforcer._run_helper") as run:
            result = enforcer.apply_blocks(
                ["8.8.8.8", "8.8.8.8", "1.1.1.1"],
                ttl_seconds=3600,
                apply=True,
                state_file=self.state_file,
                audit_file=self.audit_file,
            )

        self.assertEqual(result, 0)
        run.assert_called_once_with("add", ["8.8.8.8", "1.1.1.1"])
        with closing(sqlite3.connect(self.state_file)) as connection, connection:
            rows = connection.execute(
                "SELECT ip_address, expires_at, status FROM blocks ORDER BY ip_address"
            ).fetchall()
        self.assertEqual([row[0] for row in rows], ["1.1.1.1", "8.8.8.8"])
        self.assertTrue(all(row[2] == "active" for row in rows))
        events = self.read_events()
        self.assertEqual(sum(event["event"] == "block_applied" for event in events), 2)

    def test_failed_add_remains_scheduled_for_expiry_cleanup(self):
        with patch("enforcer._run_helper", side_effect=enforcer.EnforcerError("failed")):
            with self.assertRaisesRegex(enforcer.EnforcerError, "failed"):
                enforcer.apply_blocks(
                    ["8.8.8.8"],
                    ttl_seconds=3600,
                    apply=True,
                    state_file=self.state_file,
                    audit_file=self.audit_file,
                )

        with closing(sqlite3.connect(self.state_file)) as connection, connection:
            status = connection.execute(
                "SELECT status FROM blocks WHERE ip_address = '8.8.8.8'"
            ).fetchone()[0]
        self.assertEqual(status, "pending")

    def test_expiry_removes_due_blocks_and_retains_future_blocks(self):
        with patch("enforcer._run_helper"):
            enforcer.apply_blocks(
                ["8.8.8.8", "1.1.1.1"],
                ttl_seconds=3600,
                apply=True,
                state_file=self.state_file,
                audit_file=self.audit_file,
            )
        with closing(sqlite3.connect(self.state_file)) as connection, connection:
            connection.execute(
                "UPDATE blocks SET expires_at = ? WHERE ip_address = ?",
                (time.time() - 1, "8.8.8.8"),
            )

        with patch("enforcer._run_helper") as run:
            result = enforcer.expire_blocks(
                apply=True,
                state_file=self.state_file,
                audit_file=self.audit_file,
            )

        self.assertEqual(result, 0)
        run.assert_called_once_with("remove", ["8.8.8.8"])
        with closing(sqlite3.connect(self.state_file)) as connection, connection:
            remaining = connection.execute(
                "SELECT ip_address FROM blocks"
            ).fetchall()
        self.assertEqual(remaining, [("1.1.1.1",)])

    def test_expiry_preview_does_not_remove_or_delete_state(self):
        with patch("enforcer._run_helper"):
            enforcer.apply_blocks(
                ["8.8.8.8"],
                ttl_seconds=1,
                apply=True,
                state_file=self.state_file,
                audit_file=self.audit_file,
            )
        with closing(sqlite3.connect(self.state_file)) as connection, connection:
            connection.execute(
                "UPDATE blocks SET expires_at = ?",
                (time.time() - 1,),
            )
        with patch("enforcer._run_helper") as run:
            state_mtime_before = self.state_file.stat().st_mtime_ns
            enforcer.expire_blocks(
                apply=False,
                state_file=self.state_file,
                audit_file=self.audit_file,
            )
            state_mtime_after = self.state_file.stat().st_mtime_ns
        run.assert_not_called()
        self.assertEqual(state_mtime_after, state_mtime_before)
        with closing(sqlite3.connect(self.state_file)) as connection, connection:
            count = connection.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]
        self.assertEqual(count, 1)

    def test_expiry_batches_more_than_helper_limit(self):
        addresses = [
            f"8.8.{index // 254}.{index % 254 + 1}"
            for index in range(enforcer.MAX_BATCH_SIZE + 1)
        ]
        connection = enforcer._connect_state(self.state_file)
        try:
            connection.executemany(
                "INSERT INTO blocks(ip_address, expires_at, status, updated_at) "
                "VALUES (?, ?, 'active', ?)",
                ((address, time.time() - 1, time.time()) for address in addresses),
            )
        finally:
            connection.close()

        with (
            patch("enforcer.emit_events"),
            patch("enforcer._run_helper") as run,
        ):
            enforcer.expire_blocks(
                apply=True,
                state_file=self.state_file,
                audit_file=None,
            )

        self.assertEqual([len(call.args[1]) for call in run.call_args_list], [256, 1])


class FeedSignatureTests(unittest.TestCase):
    def test_accepts_only_a_valid_signature_from_a_pinned_fingerprint(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            feed = root / "feed.txt"
            signature = root / "feed.txt.asc"
            feed.write_text("8.8.8.8\n", encoding="utf-8")
            signature.write_text("signature", encoding="ascii")
            valid_status = f"[GNUPG:] VALIDSIG {TRUSTED_FINGERPRINT} date time"
            with (
                patch("feed_verifier.Path.is_file", return_value=True),
                patch(
                    "feed_verifier.subprocess.run",
                    return_value=Mock(returncode=0, stdout=valid_status, stderr=""),
                ) as run,
            ):
                result = feed_verifier.read_verified_feed(
                    feed,
                    signature,
                    [TRUSTED_FINGERPRINT.lower()],
                )

        self.assertEqual(result, ["8.8.8.8"])
        self.assertEqual(run.call_args.args[0][0], feed_verifier.GPG)
        self.assertIn("--verify", run.call_args.args[0])
        self.assertIn("--no-auto-key-retrieve", run.call_args.args[0])
        self.assertFalse(run.call_args.kwargs.get("shell", False))

    def test_rejects_valid_signature_from_unpinned_fingerprint(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            feed = root / "feed.txt"
            signature = root / "feed.txt.asc"
            feed.write_text("8.8.8.8\n", encoding="utf-8")
            signature.write_text("signature", encoding="ascii")
            with (
                patch("feed_verifier.Path.is_file", return_value=True),
                patch(
                    "feed_verifier.subprocess.run",
                    return_value=Mock(
                        returncode=0,
                        stdout=f"[GNUPG:] VALIDSIG {'A' * 40}",
                        stderr="",
                    ),
                ),
            ):
                with self.assertRaisesRegex(
                    feed_verifier.FeedVerificationError, "not made by a pinned"
                ):
                    feed_verifier.verify_detached_signature(
                        feed,
                        signature,
                        [TRUSTED_FINGERPRINT],
                    )

    def test_rejects_expired_signing_key_even_if_signature_is_valid(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            feed = root / "feed.txt"
            signature = root / "feed.txt.asc"
            feed.write_text("8.8.8.8\n", encoding="utf-8")
            signature.write_text("signature", encoding="ascii")
            statuses = (
                f"[GNUPG:] VALIDSIG {TRUSTED_FINGERPRINT} date time\n"
                f"[GNUPG:] EXPKEYSIG {TRUSTED_FINGERPRINT} signer"
            )
            with (
                patch("feed_verifier.Path.is_file", return_value=True),
                patch(
                    "feed_verifier.subprocess.run",
                    return_value=Mock(returncode=0, stdout=statuses, stderr=""),
                ),
            ):
                with self.assertRaisesRegex(
                    feed_verifier.FeedVerificationError, "expired or revoked"
                ):
                    feed_verifier.verify_detached_signature(
                        feed,
                        signature,
                        [TRUSTED_FINGERPRINT],
                    )

    def test_rejects_invalid_fingerprint_before_running_gpg(self):
        with patch("feed_verifier.subprocess.run") as run:
            with self.assertRaises(feed_verifier.FeedVerificationError):
                feed_verifier.verify_detached_signature(
                    Path("unused"),
                    Path("unused.asc"),
                    ["not-a-fingerprint"],
                )
        run.assert_not_called()


class CommandLineTests(unittest.TestCase):
    def test_dry_run_cli_is_structured_and_does_not_create_state(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            state_file = root / "state.sqlite3"
            audit_file = root / "audit.jsonl"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = enforcer.main(
                    [
                        "8.8.8.8",
                        "--ttl",
                        "30m",
                        "--dry-run",
                        "--state-file",
                        str(state_file),
                        "--audit-file",
                        str(audit_file),
                    ]
                )

        self.assertEqual(result, 0)
        self.assertFalse(state_file.exists())
        self.assertEqual(json.loads(output.getvalue())["status"], "dry_run")

    def test_failed_apply_writes_structured_error_to_audit(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            state_file = root / "state.sqlite3"
            audit_file = root / "audit.jsonl"
            errors = io.StringIO()
            with (
                contextlib.redirect_stderr(errors),
                patch("enforcer._run_helper", side_effect=enforcer.EnforcerError("denied")),
            ):
                result = enforcer.main(
                    [
                        "8.8.8.8",
                        "--apply",
                        "--state-file",
                        str(state_file),
                        "--audit-file",
                        str(audit_file),
                    ]
                )

            self.assertEqual(result, 1)
            self.assertEqual(
                json.loads(errors.getvalue())["event"],
                "operation_failed",
            )
            events = [
                json.loads(line)
                for line in audit_file.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(events[-1]["status"], "error")


class PrivilegedHelperTests(unittest.TestCase):
    def test_command_uses_fixed_helper_and_validated_argument_list(self):
        self.assertEqual(
            enforcer.build_helper_command("add", [" 8.8.8.8 "]),
            [
                enforcer.SUDO,
                "-n",
                "--",
                enforcer.PRIVILEGED_HELPER,
                "add",
                "8.8.8.8",
            ],
        )

    def test_status_parser_only_accepts_exact_managed_host_rules(self):
        output = (
            "Status: active\n"
            "[ 1] Anywhere DENY IN 8.8.8.8 # AutoShield-managed\n"
            "[ 2] Anywhere DENY IN 1.1.1.1 # manual rule\n"
            "[ 3] Anywhere DENY IN 10.0.0.0/24 # AutoShield-managed\n"
            "[ 4] Anywhere (v6) DENY IN 2001:4860:4860::8888 # AutoShield-managed\n"
        )
        self.assertEqual(
            autoshield_ufw.managed_addresses(output),
            {"8.8.8.8", "2001:4860:4860::8888"},
        )

    def test_command_rejects_oversized_unique_batch(self):
        addresses = [
            f"8.8.{index // 254}.{index % 254 + 1}"
            for index in range(enforcer.MAX_BATCH_SIZE + 1)
        ]
        with self.assertRaisesRegex(ValueError, "at most"):
            enforcer.build_helper_command("remove", addresses)

    def test_add_is_idempotent_when_rule_is_already_present(self):
        with (
            patch(
                "autoshield_ufw._status",
                side_effect=[{"8.8.8.8": 1}, {"8.8.8.8": 1}],
            ),
            patch("autoshield_ufw._run_ufw") as run,
        ):
            results = autoshield_ufw._apply("add", ["8.8.8.8"])
        run.assert_not_called()
        self.assertEqual(results[0]["changed"], "false")

    def test_remove_targets_only_managed_rule(self):
        with (
            patch(
                "autoshield_ufw._status",
                side_effect=[{"8.8.8.8": 1}, {}],
            ),
            patch("autoshield_ufw._run_ufw") as run,
        ):
            results = autoshield_ufw._apply("remove", ["8.8.8.8"])
        self.assertEqual(
            run.call_args.args[0],
            [
                "--force",
                "delete",
                "deny",
                "from",
                "8.8.8.8",
                "comment",
                "AutoShield-managed",
            ],
        )
        self.assertEqual(results[0]["status"], "ok")

    def test_remove_cleans_duplicate_managed_rules_in_one_pass(self):
        with (
            patch(
                "autoshield_ufw._status",
                side_effect=[{"8.8.8.8": 2}, {}],
            ),
            patch("autoshield_ufw._run_ufw") as run,
        ):
            results = autoshield_ufw._apply("remove", ["8.8.8.8"])

        self.assertEqual(run.call_count, 2)
        self.assertEqual(results[0]["status"], "ok")


if __name__ == "__main__":
    unittest.main()
