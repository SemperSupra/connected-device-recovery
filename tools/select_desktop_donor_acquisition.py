#!/usr/bin/env python3
"""Fail-conservative, incremental admission for signed macOS/Linux donor runs.

The pull_request.paths filter covers the *cumulative* PR diff, so source-only or
docs commits may trigger a job. Compare only synchronize.before..after; on
missing ancestry, git errors, manual events or fresh PRs run conservatively.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess

SHA = re.compile(r"^[a-fA-F0-9]{40}$")
SOURCE_CHANGES = {
    "macos": frozenset({
        ".github/workflows/chatgpt-macos-oracle.yml",
        "tools/characterize_desktop_bundle.py",
        "tools/select_static_macho_codex.py",
    }),
    "linux": frozenset({
        ".github/workflows/chatgpt-linux-oracle.yml",
        "tools/characterize_desktop_bundle.py",
        "tools/qualify_rpm_signature.py",
    }),
}


def select(event_name: str, event: dict, profile: str) -> tuple[bool, str]:
    if profile not in SOURCE_CHANGES:
        return True, "UNKNOWN_DONOR_PROFILE_RUN_CONSERVATIVELY"
    if event_name != "pull_request" or event.get("action") != "synchronize":
        return True, "INITIAL_OR_MANUAL_EVENT"
    before, after = event.get("before"), event.get("after")
    if not (isinstance(before,str) and SHA.fullmatch(before) and
            isinstance(after,str) and SHA.fullmatch(after)):
        return True, "UNVERIFIABLE_ANCESTRY_RUN_CONSERVATIVELY"
    try:
        diff = subprocess.run(
            ["git","diff","--name-only","--no-renames",before,after],
            capture_output=True,text=True,check=True,timeout=15,
        )
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired):
        return True, "UNVERIFIABLE_DIFF_RUN_CONSERVATIVELY"
    paths={line.strip() for line in diff.stdout.splitlines() if line.strip()}
    if paths & SOURCE_CHANGES[profile]:
        return True, "ORIGINAL_DONOR_PRODUCER_CHANGED"
    return False, "SOURCE_ONLY_CHANGE_SKIP_ORIGINAL_DONOR"


def main() -> int:
    try:
        event=json.loads(Path(os.environ.get("GITHUB_EVENT_PATH","")).read_text(encoding="utf-8"))
    except (OSError,ValueError):
        event={}
    profile=os.environ.get("DONOR_PROFILE","UNKNOWN")
    acquire,reason=select(os.environ.get("GITHUB_EVENT_NAME",""),event,profile)
    output=os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output,"a",encoding="utf-8") as f:
            f.write("acquire="+("true" if acquire else "false")+"\n")
            f.write("reason="+reason+"\n")
    print(json.dumps({
        "schema":"cdr-desktop-original-donor-admission/v1",
        "profile":profile if profile in SOURCE_CHANGES else "UNKNOWN",
        "acquire":acquire,"reason":reason,
        "original_runtime_verified":False,
        "claim_boundary":"A skipped donor job is NOT original signed-app or protocol qualification.",
    },sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
