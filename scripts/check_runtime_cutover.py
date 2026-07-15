#!/usr/bin/env python3
"""Fail closed on retired Runtime surfaces and mutable GitHub Actions."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

# Construct retired spellings so this guard does not contain the spellings it
# rejects as literal bytes.
RETIRED = tuple(
    value.encode("utf-8")
    for value in (
        "KDNA" + "Capsule" + "V2",
        "KDNA" + "Context" + "Capsule",
        "load" + "V" + "2",
        "kdna.context." + "capsule",
        "kdna-capsule-" + "digests-v1",
        "kdna-capsule-" + "jcs-v1",
        "kdna-container-" + "bytes-v1",
        "kdna-content-" + "tree-v1",
        "kdna-runtime-entry-" + "set-v1",
        "judgment-profile-" + "v1",
        "capsule-" + "v1",
        "capsule-" + "v2",
    )
)
GENERATION = re.compile(rb"(?i)\bcapsule[ _-]+(?:v?[12])\b")
ACTION = re.compile(r"^\s*(?:-\s*)?uses:\s*[^@\s]+@([^\s#]+)", re.MULTILINE)
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


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


def scan(label: str, path: str, data: bytes, failures: list[str]) -> None:
    lowered = data.lower()
    for retired in RETIRED:
        if retired.lower() in lowered:
            failures.append(f"{label}:{path}: retired Runtime spelling")
    if GENERATION.search(data):
        failures.append(f"{label}:{path}: retired Capsule generation grammar")


def main() -> int:
    failures: list[str] = []
    files = repository_files()
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        scan("repository", relative, relative.encode("utf-8"), failures)
        scan("repository", relative, path.read_bytes(), failures)

    package = subprocess.run(
        ["swift", "package", "dump-package"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    scan("package", "swift package dump-package", package, failures)

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
        f"Runtime cutover audit passed: {len(files)} repository files, "
        f"{len(workflows)} workflows, package surface clean"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
