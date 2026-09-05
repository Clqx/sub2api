#!/usr/bin/env python3
"""Validate Gitleaks findings against a narrow, expiring exception baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path


REQUIRED_FIELDS = {
    "rule",
    "path",
    "value_sha256",
    "occurrences",
    "reason",
    "mitigation",
    "expires_on",
    "owner",
}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def split_kv(line: str) -> tuple[str, str]:
    key, value = line.split(":", 1)
    value = value.strip()
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        value = value[1:-1]
    return key.strip(), value


def parse_exceptions(path: Path) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    version_seen = False

    with path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("version:"):
                _, value = split_kv(line)
                if value != "1":
                    raise ValueError(f"Unsupported exception schema version: {value}")
                version_seen = True
                continue
            if line == "exceptions:":
                continue
            if line.startswith("- "):
                if current is not None:
                    entries.append(current)
                current = {}
                line = line[2:].strip()
                if line:
                    key, value = split_kv(line)
                    current[key] = value
                continue
            if current is not None and ":" in line:
                key, value = split_kv(line)
                current[key] = value

    if current is not None:
        entries.append(current)
    if not version_seen:
        raise ValueError("Exception file is missing version: 1")
    return entries


def normalize_path(value: str, root: Path) -> str:
    candidate = Path(value)
    if candidate.is_absolute():
        try:
            return candidate.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return candidate.as_posix()
    normalized = value.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def finding_key(finding: dict, root: Path) -> tuple[str, str, str]:
    rule = str(finding.get("RuleID") or "").strip()
    finding_path = normalize_path(str(finding.get("File") or "").strip(), root)
    value = finding.get("Secret")
    if not rule or not finding_path or not isinstance(value, str):
        raise ValueError("Gitleaks finding is missing RuleID, File, or Secret")
    value_sha256 = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return rule, finding_path, value_sha256


def load_findings(
    report_path: Path, root: Path
) -> tuple[Counter[tuple[str, str, str]], dict[tuple[str, str, str], list[int]]]:
    with report_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if payload is None:
        payload = []
    if not isinstance(payload, list):
        raise ValueError(f"Gitleaks report must contain a JSON array: {report_path}")

    counts: Counter[tuple[str, str, str]] = Counter()
    lines: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    for finding in payload:
        if not isinstance(finding, dict):
            raise ValueError(f"Invalid Gitleaks finding in {report_path}")
        key = finding_key(finding, root)
        counts[key] += 1
        line = finding.get("StartLine")
        if isinstance(line, int):
            lines[key].append(line)
    return counts, lines


def parse_iso_date(value: str) -> date | None:
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def build_exception_index(
    entries: list[dict[str, str]], today: date
) -> tuple[dict[tuple[str, str, str], int], list[str]]:
    index: dict[tuple[str, str, str], int] = {}
    errors: list[str] = []

    for entry in entries:
        missing = sorted(field for field in REQUIRED_FIELDS if not entry.get(field))
        label = f"{entry.get('rule', '<unknown>')}:{entry.get('path', '<unknown>')}"
        if missing:
            errors.append(f"Exception {label} is missing fields: {', '.join(missing)}")
            continue

        rule = entry["rule"].strip()
        finding_path = entry["path"].replace("\\", "/").lstrip("./")
        value_sha256 = entry["value_sha256"].strip().lower()
        if not SHA256_PATTERN.fullmatch(value_sha256):
            errors.append(f"Exception {label} has an invalid value_sha256")
            continue
        try:
            occurrences = int(entry["occurrences"])
        except ValueError:
            occurrences = 0
        if occurrences <= 0:
            errors.append(f"Exception {label} must have positive occurrences")
            continue

        expires_on = parse_iso_date(entry["expires_on"])
        if expires_on is None:
            errors.append(f"Exception {label} has an invalid expires_on date")
            continue
        if expires_on < today:
            errors.append(f"Exception {label} expired on {expires_on.isoformat()}")

        key = (rule, finding_path, value_sha256)
        if key in index:
            errors.append(f"Duplicate exception for {rule}:{finding_path}")
            continue
        index[key] = occurrences

    return index, errors


def write_evidence(path: Path, fields: dict[str, str | int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for key, value in fields.items():
            handle.write(f"{key}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--delta-report", type=Path)
    parser.add_argument("--exceptions", required=True, type=Path)
    parser.add_argument("--root", default=Path("."), type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--scanner-version", required=True)
    args = parser.parse_args()

    errors: list[str] = []
    try:
        entries = parse_exceptions(args.exceptions)
        exception_index, exception_errors = build_exception_index(entries, date.today())
        errors.extend(exception_errors)
        current_counts, current_lines = load_findings(args.report, args.root)
        if args.delta_report:
            delta_counts, delta_lines = load_findings(args.delta_report, Path("."))
        else:
            delta_counts, delta_lines = Counter(), {}
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"Secret scan validation error: {exc}\n")
        write_evidence(
            args.evidence,
            {
                "schema_version": 1,
                "commit": args.commit,
                "scanner": "gitleaks",
                "scanner_version": args.scanner_version,
                "result": "error",
            },
        )
        return 1

    for key, actual in current_counts.items():
        expected = exception_index.get(key)
        rule, finding_path, _ = key
        if expected is None:
            errors.append(
                "Unapproved current-tree finding: "
                f"rule={rule} path={finding_path} occurrences={actual} "
                f"lines={sorted(current_lines.get(key, []))}"
            )
        elif actual != expected:
            errors.append(
                "Exception occurrence mismatch: "
                f"rule={rule} path={finding_path} expected={expected} actual={actual}"
            )

    for key, expected in exception_index.items():
        actual = current_counts.get(key, 0)
        if actual != expected and key not in current_counts:
            rule, finding_path, _ = key
            errors.append(
                "Stale exception or missing expected fixture: "
                f"rule={rule} path={finding_path} expected={expected} actual=0"
            )

    for key, actual in delta_counts.items():
        if key in exception_index:
            continue
        rule, finding_path, _ = key
        errors.append(
            "Unapproved candidate-history finding: "
            f"rule={rule} path={finding_path} occurrences={actual} "
            f"lines={sorted(delta_lines.get(key, []))}"
        )

    unapproved_current = sum(
        count for key, count in current_counts.items() if key not in exception_index
    )
    unapproved_delta = sum(
        count for key, count in delta_counts.items() if key not in exception_index
    )
    result = "fail" if errors else "pass"
    write_evidence(
        args.evidence,
        {
            "schema_version": 1,
            "commit": args.commit,
            "scanner": "gitleaks",
            "scanner_version": args.scanner_version,
            "scope": "tracked-tree-and-candidate-history",
            "current_findings": sum(current_counts.values()),
            "candidate_history_findings": sum(delta_counts.values()),
            "approved_exception_groups": len(exception_index),
            "unapproved_current_findings": unapproved_current,
            "unapproved_candidate_history_findings": unapproved_delta,
            "result": result,
        },
    )

    if errors:
        sys.stderr.write("\n".join(errors) + "\n")
        return 1
    print(
        "Gitleaks exceptions validated: "
        f"{sum(current_counts.values())} current findings across "
        f"{len(current_counts)} approved groups."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
