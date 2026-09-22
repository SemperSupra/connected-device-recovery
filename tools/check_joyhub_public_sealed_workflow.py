#!/usr/bin/env python3
"""Fail closed if the public JOYHUB runtime workflow crosses the sealed boundary."""
from __future__ import annotations

from pathlib import Path

WORKFLOW = Path(".github/workflows/joyhub-public-sealed-startup.yml")

def require(text: str, needle: str) -> None:
    if needle not in text:
        raise SystemExit(f"missing required sealed-runtime invariant: {needle}")

def forbid(text: str, needle: str) -> None:
    if needle in text:
        raise SystemExit(f"forbidden public-boundary token present: {needle}")

def main() -> int:
    text = WORKFLOW.read_text(encoding="utf-8")

    for needle in (
        "agent-dispatch-private",
        "connected-device-recovery-private",
        "android-artifact-recovery-private",
        "secrets.",
        "GITHUB_TOKEN",
        "Authorization:",
        "Cookie:",
    ):
        forbid(text, needle)

    for needle in (
        "workset_id:",
        "delegation_id:",
        "assignment_id:",
        "age_recipient:",
        "age --encrypt",
        ".sealed/result.age",
        ".sealed/receipt.json",
        "rm -rf private-result work",
        "ghcr.io/efforg/apkeep:stable",
        "mini1.net.joyhub",
    ):
        require(text, needle)

    upload_tail = text.split("- name: Upload sealed mailbox", 1)[1]
    forbid(upload_tail, "private-result")
    forbid(upload_tail, "work/")
    require(upload_tail, ".sealed/result.age")
    require(upload_tail, ".sealed/receipt.json")

    print("public sealed-runtime boundary: PASS")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
