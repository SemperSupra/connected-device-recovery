#!/usr/bin/env python3
"""Bounded anonymous JOYHUB bootstrap/content probe.

Sends exactly one POST to each recovered read-only candidate. No credentials,
cookies, account identifiers, enumeration, binding, social mutation, or firmware
actions are used. Output contains only structural summaries and hashes.
"""
from __future__ import annotations

import hashlib
import json
import sys
import urllib.error
import urllib.request

BASE = "https://appapi.joyhub.net/"
SYNTHETIC_DEVICE_ID = "cdr-anonymous-probe-20260922"

TARGETS = [
    ("api/config/Theme", None),
    ("api/config/community", None),
    ("api/config/waveLover", None),
    ("api/games/list", None),
    ("api/cfg/appCfg", {"deviceId": SYNTHETIC_DEVICE_ID}),
]


def summarize_json(obj):
    out = {"top_level_type": type(obj).__name__}
    if isinstance(obj, dict):
        out["top_level_keys"] = sorted(obj.keys())
        for key in ("code", "result", "status", "success", "responseCode", "responseMsg", "msg", "message"):
            if key in obj and isinstance(obj[key], (str, int, float, bool)) or obj.get(key) is None:
                if key in obj:
                    out[key] = obj[key]
        for key in ("data", "resultData", "rows", "list"):
            if key not in obj:
                continue
            value = obj[key]
            out[f"{key}_type"] = type(value).__name__
            if isinstance(value, list):
                out[f"{key}_length"] = len(value)
                if value and isinstance(value[0], dict):
                    out[f"{key}_item_keys"] = sorted(value[0].keys())
            elif isinstance(value, dict):
                out[f"{key}_keys"] = sorted(value.keys())
    elif isinstance(obj, list):
        out["length"] = len(obj)
        if obj and isinstance(obj[0], dict):
            out["item_keys"] = sorted(obj[0].keys())
    return out


def request(endpoint, body):
    url = BASE + endpoint
    data = None
    headers = {
        "Accept": "application/json",
        "User-Agent": "Connected-Device-Recovery/anonymous-read-probe",
    }
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    else:
        # Retrofit POST without @Body emits an empty request body.
        data = b""

    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read()
            status = response.status
            content_type = response.headers.get("Content-Type")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
        content_type = exc.headers.get("Content-Type")
    except Exception as exc:
        return {
            "endpoint": endpoint,
            "classification": "TRANSPORT_FAILURE",
            "error_type": type(exc).__name__,
            "error": str(exc)[:300],
        }

    row = {
        "endpoint": endpoint,
        "http_status": status,
        "content_type": content_type,
        "response_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "request_body_keys": sorted(body.keys()) if body else [],
        "authorization_sent": False,
        "cookie_sent": False,
    }
    try:
        parsed = json.loads(raw.decode("utf-8"))
        row["json"] = summarize_json(parsed)
    except Exception:
        row["json"] = None

    if 200 <= status < 300:
        row["classification"] = "ANONYMOUS_HTTP_OK"
    elif status in (401, 403):
        row["classification"] = "AUTH_BOUNDARY"
    else:
        row["classification"] = "CONTRACT_OR_SERVER_BOUNDARY"
    return row


def main():
    results = [request(endpoint, body) for endpoint, body in TARGETS]
    print(json.dumps({
        "schema": "cdr-joyhub-anonymous-bootstrap-probe/v1",
        "base": BASE,
        "request_count": len(results),
        "results": results,
        "policy": {
            "credentials_used": False,
            "cookies_used": False,
            "account_identifiers_used": False,
            "device_id": "synthetic-non-user",
            "raw_payloads_published": False,
        },
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
