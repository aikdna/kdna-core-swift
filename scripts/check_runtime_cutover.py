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
AUTHORITY_SHA256 = "3d810cd1c8cabe83e4b9d5ec0a2c74473d93b94968a332ac98ef0077022298b9"
AUTHORITY_COUNT = 73
PACKAGE_SWIFT_SHA256 = "d6fc75029b8082fb0c391a057e2d42812b7ee5f28df2a8dcb8b7215f7d63867e"
PACKAGE_RESOLVED_SHA256 = "d1bb9f640abe59cca6d731c8c5d17a39ba9859323703cce6826af472ff8b6ec0"
LOADER_COMPATIBILITY_TEST_SHA256 = "f315173e5d8acdf4509feb8c76041b087b02a4f7edbf37e61ba459d1fcbcaa46"
CI_WORKFLOW_SHA256 = "fe67a2e34c92b39617cdacf8b77886793b8508552af98d3389f83f271aebd49c"
ARGON2KIT_DEPENDENCY = (
    b"https://github.com/rkreutz/Argon2Kit.git",
    b"from",
    b"0.1.1",
)
ARGON2KIT_LOCK = {
    "identity": "argon2kit",
    "kind": "remoteSourceControl",
    "location": "https://github.com/rkreutz/Argon2Kit.git",
    "state": {
        "revision": "87b9ca9c42304b8c6a5c14d7f6d6a0342917e71c",
        "version": "0.1.1",
    },
}
PACKAGE_DEPENDENCY = re.compile(
    rb'\.package\(\s*url:\s*"([^"]+)"\s*,\s*(from|exact):\s*"([^"]+)"\s*\)'
)
EXPECTED_CI_WORKFLOW = rb"""name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  test:
    runs-on: macos-14
    timeout-minutes: 30
    env:
      KDNA_CONFORMANCE_COMMIT: 76bbc587ce05f7e575c2373832cc5c9eee9df98a
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
      - uses: actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38
        with:
          node-version: '22.23.1'
          check-latest: false
      - name: Bind exact Node executable
        run: |
          test "$(node --version)" = "__EXPECTED_NODE_OUTPUT__"
          node_path="$(command -v node)"
          test -n "$node_path"
          test "${node_path#/}" != "$node_path"
          test -x "$node_path"
          printf 'NODE=%s\n' "$node_path" >> "$GITHUB_ENV"
      - name: Audit public surface
        run: python3 scripts/check_public_surface.py
      - name: Audit Runtime cutover and workflow pins
        run: |
          python3 scripts/check_runtime_cutover.py
          python3 scripts/test_runtime_cutover_hostile.py
      - name: Checkout fixed kdna conformance fixtures
        run: |
          cd ..
          git init kdna
          cd kdna
          git remote add origin https://github.com/aikdna/kdna.git
          git fetch --depth 1 origin "$KDNA_CONFORMANCE_COMMIT"
          git checkout --detach FETCH_HEAD
      - name: Build
        run: |
          swift build \
            --scratch-path "${{ runner.temp }}/kdna-core-swift-swiftpm-scratch" \
            --cache-path "${{ runner.temp }}/kdna-core-swift-swiftpm-cache" \
            --config-path "${{ runner.temp }}/kdna-core-swift-swiftpm-config" \
            --security-path "${{ runner.temp }}/kdna-core-swift-swiftpm-security" \
            --force-resolved-versions \
            -Xcc -fmodules-cache-path="${{ runner.temp }}/kdna-core-swift-module-cache"
      - name: Build iOS 16 generic library
        run: |
          xcodebuild \
            -scheme kdna-core-swift \
            -destination 'generic/platform=iOS' \
            -derivedDataPath "${{ runner.temp }}/kdna-core-swift-ios-derived-data" \
            -clonedSourcePackagesDirPath "${{ runner.temp }}/kdna-core-swift-ios-packages" \
            -packageCachePath "${{ runner.temp }}/kdna-core-swift-ios-package-cache" \
            -disableAutomaticPackageResolution \
            -onlyUsePackageVersionsFromResolvedFile \
            CODE_SIGNING_ALLOWED=NO \
            build
      - name: Test
        env:
          KDNA_CONFORMANCE_ROOT: ${{ github.workspace }}/../kdna
        run: |
          swift test \
            --scratch-path "${{ runner.temp }}/kdna-core-swift-swiftpm-scratch" \
            --cache-path "${{ runner.temp }}/kdna-core-swift-swiftpm-cache" \
            --config-path "${{ runner.temp }}/kdna-core-swift-swiftpm-config" \
            --security-path "${{ runner.temp }}/kdna-core-swift-swiftpm-security" \
            --force-resolved-versions \
            -Xcc -fmodules-cache-path="${{ runner.temp }}/kdna-core-swift-module-cache"
""".replace(b"__EXPECTED_NODE_OUTPUT__", b"v" + b"22.23.1")
ACTION = re.compile(r"^\s*(?:-\s*)?uses:\s*[^@\s]+@([^\s#]+)", re.MULTILINE)
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
GENERATION_LABEL = re.compile(
    rb"(?<![A-Za-z0-9_])[Vv][0-9]+(?:\.[0-9]+){0,2}(?![A-Za-z0-9_])"
)
LOWER_V = b"v"
GENERATION_SOURCE_ALLOWLIST = {
    (
        ".github/workflows/ci.yml",
        b'test "$(node --version)" = "' + LOWER_V + b'22.23.1"',
    ),
    ("Package.swift", b".macOS(." + LOWER_V + b"13),"),
    ("Package.swift", b".iOS(." + LOWER_V + b"16)"),
    (
        "Sources/KDNACore/KDNAProtectedCrypto.swift",
        b"version: ." + LOWER_V + b"13",
    ),
}

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


def dependency_authority_failures(
    package: bytes,
    resolved: bytes,
    gitignore: bytes,
    require_exact_bytes: bool = True,
) -> list[str]:
    failures: list[str] = []
    dependencies = PACKAGE_DEPENDENCY.findall(package)
    declarations = re.findall(rb"\.package\s*\(", package)
    if len(declarations) != 1 or dependencies != [ARGON2KIT_DEPENDENCY]:
        failures.append("Package.swift does not match the declared candidate dependency requirement")
    if require_exact_bytes and sha256(package) != PACKAGE_SWIFT_SHA256:
        failures.append("Package.swift bytes differ from candidate validation authority")
    try:
        lock = json.loads(resolved)
    except (UnicodeDecodeError, json.JSONDecodeError):
        failures.append("Package.resolved is not valid JSON")
    else:
        if set(lock) != {"pins", "version"} or lock.get("version") != 2:
            failures.append("Package.resolved top-level contract is not exact")
        if lock.get("pins") != [ARGON2KIT_LOCK]:
            failures.append("Package.resolved does not pin the exact Argon2Kit revision")
    if b"package.resolved" in gitignore.lower():
        failures.append("Package.resolved remains ignored")
    if require_exact_bytes and sha256(resolved) != PACKAGE_RESOLVED_SHA256:
        failures.append("Package.resolved bytes differ from candidate authority")
    return failures


def controlled_node_test_failures(
    source: bytes,
    require_exact_bytes: bool = True,
) -> list[str]:
    failures: list[str] = []
    required = (
        b'environment["NODE"]',
        b'(nodePath as NSString).isAbsolutePath',
        b'FileManager.default.fileExists(atPath: nodePath, isDirectory: &nodeIsDirectory)',
        b'FileManager.default.isExecutableFile(atPath: nodePath)',
        b'sha256Hex(moduleData) == "6bc0a34ebcada8181bde391eae3e60a39751dda7e6aca423babad0e9846aac9d"',
        b'process.executableURL = nodeExecutableURL',
        b'process.arguments = ["-e", script, fixtureURL.path, moduleURL.path]',
        b'process.environment = [:]',
    )
    for fragment in required:
        if source.count(fragment) != 1:
            failures.append("LoaderCompatibilityTests does not bind controlled NODE exactly")
            break
    forbidden = (
        b'URL(fileURLWithPath: "/usr/bin/env")',
        b'process.arguments = ["node",',
        b'environment["PATH"]',
    )
    if any(fragment in source for fragment in forbidden):
        failures.append("LoaderCompatibilityTests retains a PATH or env fallback")
    if require_exact_bytes and sha256(source) != LOADER_COMPATIBILITY_TEST_SHA256:
        failures.append("LoaderCompatibilityTests bytes differ from candidate authority")
    return failures


def ci_workflow_failures(workflow: bytes) -> list[str]:
    failures: list[str] = []
    if workflow != EXPECTED_CI_WORKFLOW:
        failures.append("CI workflow differs from the exact single-job release gate")
    if sha256(workflow) != CI_WORKFLOW_SHA256:
        failures.append("CI workflow digest differs from candidate authority")
    return failures


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


def owned_generation_labels(path: str, data: bytes) -> list[str]:
    result: list[str] = []
    for line_number, line in enumerate(data.splitlines(), 1):
        stripped = line.strip()
        for match in GENERATION_LABEL.finditer(line):
            if (path, stripped) in GENERATION_SOURCE_ALLOWLIST:
                continue
            result.append(
                f"KDNA-owned generation label at line {line_number}: "
                f"{match.group().decode('ascii')}"
            )
    return result


def scan(label: str, path: str, data: bytes, retired: tuple[bytes, ...], failures: list[str]) -> None:
    for finding in findings(data, retired):
        failures.append(f"{label}:{path}: {finding}")
    if label in {"repository-path", "repository-content"}:
        for finding in owned_generation_labels(path, data):
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

    authority_paths = {
        "Package.swift": ROOT / "Package.swift",
        "Package.resolved": ROOT / "Package.resolved",
        ".gitignore": ROOT / ".gitignore",
        "LoaderCompatibilityTests": ROOT / "Tests/KDNACoreTests/LoaderCompatibilityTests.swift",
        "CI workflow": ROOT / ".github/workflows/ci.yml",
    }
    authority_bytes: dict[str, bytes] = {}
    for label, path in authority_paths.items():
        try:
            authority_bytes[label] = path.read_bytes()
        except OSError as error:
            failures.append(f"authority:{label}: unavailable: {error}")
    if {"Package.swift", "Package.resolved", ".gitignore"} <= authority_bytes.keys():
        failures.extend(dependency_authority_failures(
            authority_bytes["Package.swift"],
            authority_bytes["Package.resolved"],
            authority_bytes[".gitignore"],
        ))
    if "LoaderCompatibilityTests" in authority_bytes:
        failures.extend(controlled_node_test_failures(
            authority_bytes["LoaderCompatibilityTests"]
        ))
    if "CI workflow" in authority_bytes:
        failures.extend(ci_workflow_failures(authority_bytes["CI workflow"]))

    workflows = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8")
        for revision in ACTION.findall(text):
            if not FULL_SHA.fullmatch(revision):
                failures.append(
                    f"workflow:{workflow.relative_to(ROOT)}: action is not pinned to a full SHA"
                )

    required = (
        ROOT / "Package.resolved",
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
