#!/usr/bin/env python3
"""Unauthenticated Chrome DOM-shape sensor, no screenshots or source published.

Runs a fresh temporary headless browser profile on the public ChatGPT home page.
No user cookies, login or authenticated sessions supplied. No clicks or POSTs.
The DOM is processed in-memory into numeric allowlisted structural counters.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile

URL = "https://chatgpt.com/"
DOM_READ_CAP = 4_000_000
BROWSER_TIMEOUT_SECONDS = 45
TAGS = frozenset({"html","body","header","main","nav","footer","button","input",
                  "form","a","script","iframe","dialog","textarea","select","article"})
ROLES = frozenset({"button","textbox","dialog","menuitem","searchbox",
                   "checkbox","navigation","main","form","link","combobox",
                   "listbox","option","tab","tabpanel","alert"})
INPUTS = frozenset({"text","search","email","password","file","hidden",
                    "checkbox","radio","submit","button"})


def detect_interstitial(sample: bytes) -> bool:
    """Classify only explicit access-challenge signatures; never bypass."""
    low = sample.lower()
    return any(sig in low for sig in (
        b"challenge-platform", b"cf_chl_", b"cf-turnstile",
        b"just a moment",
    ))


class SafeDOMShape(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = Counter()
        self.roles = Counter()
        self.inputs = Counter()
        self.unknown_roles = 0
        self.events = 0

    def handle_starttag(self, tag, attrs):
        self.events += 1
        if tag in TAGS:
            self.tags[tag] += 1
        pairs = dict(attrs)
        role = pairs.get("role")
        if isinstance(role, str):
            if role in ROLES:
                self.roles[role] += 1
            else:
                self.unknown_roles += 1
        if tag == "input":
            kind = pairs.get("type")
            self.inputs[kind if kind in INPUTS else "other_or_unspecified"] += 1

    def report(self):
        return {"observed_element_starts":self.events,
                "allowlisted_tag_counts":dict(sorted(self.tags.items())),
                "allowlisted_role_counts":dict(sorted(self.roles.items())),
                "unreviewed_role_count":self.unknown_roles,
                "input_type_counts":dict(sorted(self.inputs.items()))}


def observe(browser: Path | None = None, seconds: int = BROWSER_TIMEOUT_SECONDS) -> dict:
    if not 1 <= seconds <= 90:
        raise ValueError("invalid browser time limit")
    if browser is None:
        discovered = shutil.which("google-chrome") or shutil.which("chromium")
        browser = Path(discovered) if discovered else None
    receipt = {
        "schema":"cdr-chatgpt-guest-dom-shape/v1",
        "mode":"LOGGED_OUT_EPHEMERAL_CHROME",
        "requested_url":URL,
        "authenticated":False,
        "user_session_supplied":False,
        "persistent_profile":False,
        "clicks_or_state_mutations":False,
        "raw_dom_or_screenshot_published":False,
        "original_runtime_feature_parity":"NOT_VERIFIED",
        "claim_boundary":"Unauthenticated first-party DOM structural sampling only; content, login, IPC, private state and CRUD effects are not qualified.",
    }
    if browser is None or not browser.is_file():
        return {**receipt,"status":"BROWSER_UNAVAILABLE"}
    with tempfile.TemporaryDirectory(prefix="cdr-guest-dom-") as td:
        temp=Path(td)
        dom=temp/"dom.html"
        cmd=[
            str(browser), "--headless=new", "--disable-gpu",
            "--no-first-run", "--no-default-browser-check",
            "--disable-extensions", "--disable-sync",
            "--disable-background-networking",
            "--user-data-dir="+str(temp/"profile"),
            "--virtual-time-budget=4000", "--dump-dom", URL,
        ]
        timed_out=False
        with dom.open("wb") as out:
            try:
                proc=subprocess.Popen(cmd,stdout=out,stderr=subprocess.DEVNULL,
                                      start_new_session=True)
            except OSError:
                return {**receipt,"status":"BROWSER_LAUNCH_FAILED"}
            try:
                code=proc.wait(timeout=seconds)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid,signal.SIGKILL)
                proc.wait()
                timed_out=True
                code=124
        if timed_out:
            return {**receipt,"status":"BROWSER_TIMED_OUT","exit_code":code}
        if code != 0:
            return {**receipt,"status":"BROWSER_FAILED","exit_code":code}
        with dom.open("rb") as file:
            sample=file.read(DOM_READ_CAP+1)
        truncated=len(sample)>DOM_READ_CAP
        sample=sample[:DOM_READ_CAP]
        parser=SafeDOMShape()
        parser.feed(sample.decode("utf-8","replace"))
        challenge = detect_interstitial(sample)
        return {**receipt,
                "status":("ACCESS_INTERSTITIAL_SIGNATURE_OBSERVED" if challenge else
                          "DOM_SHAPE_OBSERVED_NOT_AUTHENTICATED_APP"),
                "access_interstitial_signature_observed":challenge,
                "exit_code":code,
                "dom_sample_bytes":len(sample),
                "dom_sample_truncated":truncated,
                "dom_prefix_sha256":hashlib.sha256(sample).hexdigest(),
                "hash_scope":"bounded_prefix",
                "dom_shape":parser.report()}


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--output",required=True,type=Path)
    args=cli.parse_args()
    result=observe()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"schema":result["schema"],"status":result["status"]},sort_keys=True))


if __name__ == "__main__":
    main()
