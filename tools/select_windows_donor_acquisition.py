"""Admit expensive Windows donor acquisition only for relevant PR-head changes.

GitHub PR path filters match the entire PR diff, causing repeated ~GB downloads
when unrelated source-only tests change. This selector examines the actual
synchronize before..after commit range, and fails open to RUN when ancestry or
event metadata cannot be verified. A skipped donor job is NOT a passing runtime
or original-package qualification.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess

ACQUISITION_INPUTS = frozenset({
    ".github/workflows/chatgpt-windows-oracle.yml",
    "tools/characterize_asar_header.cjs",
})
SHA = re.compile(r"^[a-fA-F0-9]{40}$")


def needs_acquisition(event: dict, changed_paths: list[str] | None) -> bool:
    if event.get("action") != "synchronize":
        return True
    if changed_paths is None:
        return True
    return bool(ACQUISITION_INPUTS.intersection(changed_paths))


def select(event_name: str, event: dict) -> tuple[bool, str]:
    if event_name != "pull_request" or event.get("action") != "synchronize":
        return True, "INITIAL_OR_MANUAL_EVENT"
    before, after = event.get("before"), event.get("after")
    if not (isinstance(before, str) and SHA.fullmatch(before)
            and isinstance(after, str) and SHA.fullmatch(after)):
        return True, "UNVERIFIABLE_ANCESTRY_RUN_CONSERVATIVELY"
    try:
        p = subprocess.run(
            ["git", "diff", "--name-only", "--no-renames", before, after],
            check=True, capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return True, "UNVERIFIABLE_DIFF_RUN_CONSERVATIVELY"
    changes = [v.strip() for v in p.stdout.splitlines() if v.strip()]
    admitted = needs_acquisition(event, changes)
    return admitted, "ACQUISITION_INPUT_CHANGED" if admitted else "SOURCE_ONLY_CHANGE_SKIP_ACQUISITION"


def main() -> int:
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    event_path = pathlib.Path(os.environ.get("GITHUB_EVENT_PATH", ""))
    try:
        event = json.loads(event_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        event = {}
    accepted, reason = select(event_name, event)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as fp:
            fp.write(f"acquire={'true' if accepted else 'false'}\\n")
            fp.write(f"reason={reason}\\n")
    print(json.dumps({
        "schema": "cdr-windows-acquisition-selector/v1",
        "acquire": accepted,
        "reason": reason,
        "runtime_qualified": False,
        "claim_boundary": "A skipped donor job is NOT a successful original-package qualification.",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
