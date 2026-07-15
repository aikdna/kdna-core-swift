#!/usr/bin/env python3
"""Fail closed on retired KDNA responsibility names and mutable Actions."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = ROOT / "scripts" / "post-cutover-token-authority.json"
AUTHORITY_SHA256 = "124e7d38f9148fdba1b352f1d09133072b11ddbf0fef9846313d4bf221a4bd08"
AUTHORITY_COUNT = 62
ACTION = re.compile(r"^\s*(?:-\s*)?uses:\s*[^@\s]+@([^\s#]+)", re.MULTILINE)
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")

# These rules cover Swift-owned fixture labels and public dual-reader types in
# addition to the exact authority inherited from the canonical Node cutover.
OWNED_PATTERNS = (
    ("owned fixture generation", re.compile(rb"(?i)(?:^|[/_.-])golden[-_]v[0-9]+(?=[./_-]|$)")),
    ("owned crypto fixture generation", re.compile(rb"(?i)\b(?:scrypt_password|licensed_entry)[_-]v[0-9]+\b")),
    ("owned KDNA identifier generation", re.compile(rb"(?i)\bkdna[-/._][A-Za-z0-9./_-]*[-_/]v[0-9]+(?:\b|(?=[_.-]))")),
    ("owned Runtime generation", re.compile(rb"(?i)\b(?:KDNA(?:\s+Core)?|Core|Container|Capsule|Runtime|ConsumptionPlan|JudgmentTrace|Agent\s+Host|Host|Trace|Schema|Payload|Envelope|Cluster|Assay|Studio)[\s/_-]+v[0-9]+(?:\.[0-9]+){0,2}\b")),
    ("owned API generation", re.compile(rb"\b(?:[a-z][A-Za-z0-9_]*(?:Capsule|Plan|Host|Trace|Core|KDNA|Container|Profile|Schema|Payload|Envelope|Cluster|Runtime)V[0-9]+|[A-Z][A-Z0-9_]*_V[0-9]+)\b")),
)
RETIRED_SWIFT_PUBLIC = tuple(
    value.encode("utf-8")
    for value in (
        "Trace" + "Projector",
        "KDNA" + "ProductContractTrace",
        "KDNA" + "ContractJudgmentDelta",
        "Asset" + "Identity",
        "Asset" + "Loaded",
        "Cluster" + "Identity",
        "Applicability" + "Actual",
        "Projection" + "Actual",
        "Selection" + "Actual",
        "Selection" + "Rejected",
        "Source" + "Attribution",
        "Transfer" + "Depth",
        "Trace" + "Conflict",
        "Trace" + "Decision",
        "Trace" + "DomainEntry",
        "Trace" + "RejectedEntry",
        "Trace" + "Cost",
        "Trace" + "Provenance",
        "Answer" + "Projection",
        "Compact" + "Projection",
        "trace" + "_version",
        "kdna" + "_trace",
        "field" + "Aliases",
        "detect" + "OldFieldNames",
    )
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_authority(path: Path = AUTHORITY) -> tuple[bytes, ...]:
    data = path.read_bytes()
    if sha256(data) != AUTHORITY_SHA256:
        raise ValueError("retired-token authority file digest mismatch")
    value = json.loads(data)
    expected_keys = {
        "schema", "schema_version", "repository", "encoding", "count",
        "token_set_sha256", "tokens",
    }
    if set(value) != expected_keys:
        raise ValueError("retired-token authority fields are not exact")
    tokens = value.get("tokens")
    if (
        value.get("schema") != "kdna.post-cutover-token-authority"
        or value.get("schema_version") != "0.1.0"
        or value.get("repository") != "open/kdna"
        or value.get("encoding") != "base64"
        or value.get("count") != AUTHORITY_COUNT
        or not isinstance(tokens, list)
        or len(tokens) != AUTHORITY_COUNT
        or tokens != sorted(tokens)
    ):
        raise ValueError("retired-token authority coordinate is invalid")
    encoded = json.dumps(tokens, separators=(",", ":")).encode("utf-8")
    if sha256(encoded) != value.get("token_set_sha256"):
        raise ValueError("retired-token authority set digest mismatch")
    decoded = tuple(base64.b64decode(item, validate=True) for item in tokens)
    if any(not item for item in decoded) or len(set(decoded)) != AUTHORITY_COUNT:
        raise ValueError("retired-token authority is empty or not unique")
    return decoded


def repository_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    paths = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        path = ROOT / raw.decode("utf-8", errors="strict")
        if path.is_file():
            paths.append(path)
    return paths


def findings(data: bytes, retired: tuple[bytes, ...]) -> list[str]:
    result: list[str] = []
    for token in retired + RETIRED_SWIFT_PUBLIC:
        if token in data:
            result.append("retired exact responsibility token")
    for name, pattern in OWNED_PATTERNS:
        if pattern.search(data):
            result.append(name)
    return sorted(set(result))


def scan(label: str, path: str, data: bytes, retired: tuple[bytes, ...], failures: list[str]) -> None:
    for finding in findings(data, retired):
        failures.append(f"{label}:{path}: {finding}")


def main() -> int:
    failures: list[str] = []
    try:
        retired = load_authority()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"authority:{error}", file=sys.stderr)
        return 1

    files = repository_files()
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        scan("repository-path", relative, relative.encode("utf-8"), retired, failures)
        scan("repository-content", relative, path.read_bytes(), retired, failures)

    package = subprocess.run(
        ["swift", "package", "dump-package"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    scan("package", "swift package dump-package", package, retired, failures)

    workflows = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8")
        for revision in ACTION.findall(text):
            if not FULL_SHA.fullmatch(revision):
                failures.append(
                    f"workflow:{workflow.relative_to(ROOT)}: action is not pinned to a full SHA"
                )

    required = (
        ROOT / "Sources/KDNACore/KDNARuntimeCapsule.swift",
        ROOT / "Sources/KDNACore/KDNARuntimeContracts.swift",
        ROOT / "Sources/KDNACore/Resources/Schemas/runtime-capsule.schema.json",
        ROOT / "Sources/KDNACore/Resources/Schemas/judgment-trace.schema.json",
    )
    for path in required:
        if not path.is_file():
            failures.append(f"required:{path.relative_to(ROOT)}: missing current Runtime surface")

    if failures:
        for failure in sorted(set(failures)):
            print(failure, file=sys.stderr)
        return 1

    print(
        f"Responsibility cutover audit passed: {len(files)} repository files, "
        f"{len(workflows)} workflows, {len(retired)} exact retired tokens, package surface clean"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
