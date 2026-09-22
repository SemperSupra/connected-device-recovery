#!/usr/bin/env python3
"""One-shot JOYHUB Theme probe with exact logged-out interceptor header shape.

Recovered from JOYHUB Android 2.14.2 common OkHttp interceptor:
Authorization and JH-userId are emitted as empty strings when no session/user
state exists; other JH-* headers are emitted with device/runtime context.

No credentials, account identity, cookies, mutation, enumeration or raw response
publication.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
import uuid

URL="https://appapi.joyhub.net/api/config/Theme"
SYNTHETIC_DEVICE_ID="cdr-theme-fidelity-20260922"


def exact_logged_out_headers():
    now=str(int(time.time()))
    return {
        "Accept":"application/json",
        "User-Agent":"okhttp/3.12.13",
        "Authorization":"",
        "JH-Device":"Android",
        "JH-FromApp":"Joyhub",
        "JH-DeviceId":SYNTHETIC_DEVICE_ID,
        "X-Request-ID":str(uuid.uuid4()),
        "JH-AppVersion":"2.14.2",
        "JH-AppChannel":"",
        "JH-SystemVersion":"android0",
        "JH-DeviceModel":"CDR",
        "JH-Screen":"",
        "JH-Latitude":"",
        "JH-Longitude":"",
        "JH-SimCountry":"",
        "JH-Lang":"en",
        "Content-Language":"en",
        "JH-userId":"",
        "JH-clientTime":now,
        "JH-IP":"",
        "JH-NetworkType":"unknown",
        "Time-Zone":"UTC",
        "Utc-Offset":"+00:00",
    }


def main():
    h=exact_logged_out_headers()
    req=urllib.request.Request(URL,data=b"",headers=h,method="POST")
    try:
        with urllib.request.urlopen(req,timeout=30) as resp:
            raw=resp.read()
            status=resp.status
            content_type=resp.headers.get("Content-Type")
    except urllib.error.HTTPError as exc:
        raw=exc.read()
        status=exc.code
        content_type=exc.headers.get("Content-Type")
    except Exception as exc:
        print(json.dumps({
            "schema":"cdr-joyhub-theme-loggedout-fidelity/v1",
            "classification":"TRANSPORT_FAILURE",
            "error_type":type(exc).__name__,
            "error":str(exc)[:300],
        },indent=2,sort_keys=True))
        return 0

    parsed=None
    try:
        parsed=json.loads(raw.decode("utf-8"))
    except Exception:
        pass

    app_code=parsed.get("code") if isinstance(parsed,dict) else None
    app_status=parsed.get("status") if isinstance(parsed,dict) else None
    if status in (401,403):
        classification="AUTH_BOUNDARY"
    elif 200<=status<300 and isinstance(parsed,dict) and (app_code==0 or app_status=="success"):
        classification="ANONYMOUS_READ_OK"
    elif 200<=status<300:
        classification="APPLICATION_BOUNDARY"
    else:
        classification="CONTRACT_OR_SERVER_BOUNDARY"

    structural=None
    if isinstance(parsed,dict):
        structural={
            "keys":sorted(parsed.keys()),
            "code":app_code,
            "status":app_status,
            "message":parsed.get("message") or parsed.get("msg"),
            "data_type":type(parsed.get("data")).__name__,
        }
        if isinstance(parsed.get("data"),dict):
            structural["data_keys"]=sorted(parsed["data"].keys())
        elif isinstance(parsed.get("data"),list):
            structural["data_length"]=len(parsed["data"])
            if parsed["data"] and isinstance(parsed["data"][0],dict):
                structural["data_item_keys"]=sorted(parsed["data"][0].keys())

    out={
        "schema":"cdr-joyhub-theme-loggedout-fidelity/v1",
        "endpoint":"api/config/Theme",
        "http_status":status,
        "content_type":content_type,
        "classification":classification,
        "response_bytes":len(raw),
        "sha256":hashlib.sha256(raw).hexdigest(),
        "json":structural,
        "request":{
            "authorization_value":"empty",
            "jh_user_id_value":"empty",
            "device_id":"synthetic-non-user",
            "header_names":sorted(h.keys()),
            "cookie_sent":False,
            "account_identifier_sent":False,
        },
        "policy":{
            "raw_payload_published":False,
            "state_mutation_intended":False,
            "request_count":1,
        },
    }
    print(json.dumps(out,indent=2,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
