#!/usr/bin/env python3
"""Second-stage anonymous JOYHUB context-header probe.

Repeats only the four endpoints that returned application code 9000 in the
minimal probe. Adds only non-auth request context recovered from the app's
common OkHttp interceptor. No Authorization, Cookie, account identity, binding,
social mutation, firmware action, or raw payload publication.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
import uuid

BASE = "https://appapi.joyhub.net/"
SYNTHETIC_DEVICE_ID = "cdr-anonymous-probe-20260922"

TARGETS = [
    "api/config/Theme",
    "api/config/community",
    "api/config/waveLover",
    "api/games/list",
]


def common_headers():
    return {
        "Accept": "application/json",
        "User-Agent": "okhttp/3.12.13",
        "JH-Device": "Android",
        "JH-FromApp": "Joyhub",
        "JH-DeviceId": SYNTHETIC_DEVICE_ID,
        "X-Request-ID": str(uuid.uuid4()),
        "JH-AppVersion": "2.14.2",
        "JH-SystemVersion": "0",
        "JH-DeviceModel": "CDR",
        "JH-Screen": "0x0",
        "JH-Lang": "en",
        "Content-Language": "en",
        "JH-clientTime": str(int(time.time() * 1000)),
        "JH-NetworkType": "unknown",
        "Time-Zone": "UTC",
        "Utc-Offset": "+00:00",
    }


def summarize_json(obj):
    out = {"top_level_type": type(obj).__name__}
    if isinstance(obj, dict):
        out["top_level_keys"] = sorted(obj.keys())
        for key in ("code", "result", "status", "success", "responseCode", "responseMsg", "msg", "message"):
            if key in obj and (obj[key] is None or isinstance(obj[key], (str, int, float, bool))):
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


def request(endpoint):
    headers = common_headers()
    req = urllib.request.Request(BASE + endpoint, data=b"", headers=headers, method="POST")
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
        "authorization_sent": False,
        "cookie_sent": False,
        "context_headers_sent": sorted(headers.keys()),
    }

    parsed = None
    try:
        parsed = json.loads(raw.decode("utf-8"))
        row["json"] = summarize_json(parsed)
    except Exception:
        row["json"] = None

    if status in (401, 403):
        row["classification"] = "AUTH_BOUNDARY"
    elif 200 <= status < 300 and isinstance(parsed, dict):
        app_code = parsed.get("code")
        app_status = parsed.get("status")
        if app_code == 0 or app_status == "success":
            row["classification"] = "ANONYMOUS_READ_OK"
        else:
            row["classification"] = "APPLICATION_BOUNDARY"
    elif 200 <= status < 300:
        row["classification"] = "ANONYMOUS_HTTP_NONJSON"
    else:
        row["classification"] = "CONTRACT_OR_SERVER_BOUNDARY"
    return row


def main():
    results = [request(endpoint) for endpoint in TARGETS]
    print(json.dumps({
        "schema": "cdr-joyhub-anonymous-context-probe/v1",
        "base": BASE,
        "request_count": len(results),
        "results": results,
        "policy": {
            "credentials_used": False,
            "authorization_header_sent": False,
            "cookies_used": False,
            "account_identifiers_used": False,
            "device_id": "synthetic-non-user",
            "raw_payloads_published": False,
        },
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
