#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check_gitleaks_exceptions.py")


class GitleaksExceptionCheckerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.report = self.root / "current.json"
        self.delta_report = self.root / "delta.json"
        self.exceptions = self.root / "exceptions.yml"
        self.evidence = self.root / "evidence.txt"
        self.approved_value = "fixture-" + "approved-value"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def finding(self, value: str, line: int = 10) -> dict:
        return {
            "RuleID": "generic-api-key",
            "File": "tests/fixture.txt",
            "Secret": value,
            "StartLine": line,
        }

    def write_exception(self, occurrences: int = 2, expires_on: str = "2099-01-01") -> None:
        fingerprint = hashlib.sha256(self.approved_value.encode("utf-8")).hexdigest()
        self.exceptions.write_text(
            "\n".join(
                [
                    "version: 1",
                    "exceptions:",
                    "  - rule: generic-api-key",
                    "    path: tests/fixture.txt",
                    f'    value_sha256: "{fingerprint}"',
                    f"    occurrences: {occurrences}",
                    '    reason: "Synthetic unit-test fixture"',
                    '    mitigation: "Exact value and count are pinned"',
                    f'    expires_on: "{expires_on}"',
                    '    owner: "maintainers"',
                    "",
                ]
            ),
            encoding="utf-8",
        )

    def run_checker(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--report",
                str(self.report),
                "--delta-report",
                str(self.delta_report),
                "--exceptions",
                str(self.exceptions),
                "--root",
                str(self.root),
                "--evidence",
                str(self.evidence),
                "--commit",
                "unit-test-commit",
                "--scanner-version",
                "unit-test",
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_accepts_exact_current_baseline_and_approved_delta(self) -> None:
        self.write_exception()
        self.report.write_text(
            json.dumps([self.finding(self.approved_value), self.finding(self.approved_value, 20)]),
            encoding="utf-8",
        )
        self.delta_report.write_text(
            json.dumps([self.finding(self.approved_value)]), encoding="utf-8"
        )

        result = self.run_checker()

        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = self.evidence.read_text(encoding="utf-8")
        self.assertIn("result=pass", evidence)
        self.assertNotIn(self.approved_value, evidence + result.stdout + result.stderr)

    def test_rejects_unapproved_delta_without_disclosing_value(self) -> None:
        self.write_exception()
        self.report.write_text(
            json.dumps([self.finding(self.approved_value), self.finding(self.approved_value, 20)]),
            encoding="utf-8",
        )
        unknown_value = "fixture-" + "unapproved-value"
        self.delta_report.write_text(
            json.dumps([self.finding(unknown_value)]), encoding="utf-8"
        )

        result = self.run_checker()

        self.assertEqual(result.returncode, 1)
        self.assertIn("Unapproved candidate-history finding", result.stderr)
        self.assertNotIn(unknown_value, result.stdout + result.stderr)
        self.assertIn("result=fail", self.evidence.read_text(encoding="utf-8"))

    def test_rejects_expired_exception_and_occurrence_drift(self) -> None:
        self.write_exception(occurrences=3, expires_on="2000-01-01")
        self.report.write_text(
            json.dumps([self.finding(self.approved_value), self.finding(self.approved_value, 20)]),
            encoding="utf-8",
        )
        self.delta_report.write_text("[]", encoding="utf-8")

        result = self.run_checker()

        self.assertEqual(result.returncode, 1)
        self.assertIn("expired on 2000-01-01", result.stderr)
        self.assertIn("Exception occurrence mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
