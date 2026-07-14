#!/usr/bin/env python3
"""Fail when any Git-tracked text file exposes a configured private name or machine path."""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from pathlib import Path

SELF = "scripts/check_public_surface.py"
MAX_TEXT_BYTES = 1_000_000
FORBIDDEN_HASHES = {
    "068c8b48752eba18baf46af3324f3ffb9306457c54b6624fade5792109af536b",
    "e2f6321a5972a38700c02f6b4344c8b9deb52b523fceb7ce25a255fb44f0917c",
    "5f60fde8e355d8d81ffbb60095c2bb25a52f723940c4c01a77473badd3faa8cd",
    "ad832a18658e09393a42c9966b94625c82effd30dfe8bc0a6d8c000fa8056222",
    "4c94af7ca105abc9c4e2c9c7dce3b778b4bde7e6445c9e68101a0d9eb59f97bd",
    "0f89e837194f291beef89dcde345233adf1443f61763f05ee5cef5ad12d44c0a",
    "5de109ce9d5d074259ce2b3757d33b0a68afaaf88ca599ed77d78a46797cfdb0",
    "3ce236400925c24e9e5416bdc69abe5427b3183e2abe6f848b297334cfdeaa25",
    "32a183bfe17c2d785b66d5a328402623bc5ab674c86bd8ad29905a05c1a6319c",
    "7206c17a81fdc22e097e4b78d33fee460804b0c5bf4c0e461adc7114d16d85ed",
    "5a02d80676cf1acf987c1787c1201a7648f8cc606b6014a29ecda4eed68e6315",
    "61e79d887fa6b41acfebaeee47c2ba816bc76c892b1f72a3c2ba3f34900a22f8",
    "a1f44465ac220babc075de0f4489642440192302357a2fe90265fb2ad2c376e5",
}
TOKEN_PATTERN = re.compile(
    r"@[a-z][a-z0-9_-]*/[a-z][a-z0-9_-]*|"
    r"[a-z][a-z0-9_-]*/[a-z][a-z0-9_-]*|"
    r"[a-z][a-z0-9_-]*",
    re.IGNORECASE,
)
LOCAL_PATH_PATTERN = re.compile(
    r"/Users/(?!<user>/|you/|username/)[^/\s]+/|/private/tmp/kdna",
    re.IGNORECASE,
)


def digest(value: str) -> str:
    return hashlib.sha256(value.lower().encode("utf-8")).hexdigest()


def tracked_files() -> list[str]:
    output = subprocess.check_output(["git", "ls-files", "-z"])
    return [item.decode("utf-8") for item in output.split(b"\0") if item]


findings: list[tuple[str, int, str, str]] = []
scanned = 0
for file_name in tracked_files():
    if file_name == SELF:
        continue
    try:
        content = Path(file_name).read_bytes()
    except OSError:
        continue
    if len(content) > MAX_TEXT_BYTES or b"\0" in content:
        continue
    scanned += 1
    for line_number, line in enumerate(content.decode("utf-8", errors="replace").splitlines(), 1):
        local_path = LOCAL_PATH_PATTERN.search(line)
        if local_path:
            findings.append((file_name, line_number, "local-filesystem-path", local_path.group(0)))
        for token in TOKEN_PATTERN.findall(line):
            if digest(token) in FORBIDDEN_HASHES:
                findings.append((file_name, line_number, "private-name-token", token))

if findings:
    print(
        f"public-surface check failed: {len(findings)} finding(s) across {scanned} files",
        file=sys.stderr,
    )
    for file_name, line_number, rule, match in findings:
        print(f"{file_name}:{line_number} [{rule}] {match}", file=sys.stderr)
    raise SystemExit(1)

print(f"public-surface check passed: {scanned} tracked text files, 0 findings")
