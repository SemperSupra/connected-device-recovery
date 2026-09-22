#!/usr/bin/env python3
"""One-shot anonymous JOYHUB video-list probe for catalog-derived J-MowgliII.

Contract recovered from JOYHUB Android 2.14.2:
POST api/video/list
{"product_code":"3333","page":"1","per_size":6}

Uses only non-auth common app context. Publishes structural response metadata and
hashes, never raw response content.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
import uuid

BASE="https://appapi.joyhub.net/"
ENDPOINT="api/video/list"
BODY={"product_code":"3333","page":"1","per_size":6}
SYNTHETIC_DEVICE_ID="cdr-video-probe-20260922"


def headers():
    return {
        "Accept":"application/json",
        "Content-Type":"application/json",
        "User-Agent":"okhttp/3.12.13",
        "JH-Device":"Android",
        "JH-FromApp":"Joyhub",
        "JH-DeviceId":SYNTHETIC_DEVICE_ID,
        "X-Request-ID":str(uuid.uuid4()),
        "JH-AppVersion":"2.14.2",
        "JH-SystemVersion":"0",
        "JH-DeviceModel":"CDR",
        "JH-Screen":"0x0",
        "JH-Lang":"en",
        "Content-Language":"en",
        "JH-clientTime":str(int(time.time())),
        "JH-NetworkType":"unknown",
        "Time-Zone":"UTC",
        "Utc-Offset":"+00:00",
    }


def summarize(value, depth=0):
    if depth>2:
        return {"type":type(value).__name__}
    if isinstance(value,dict):
        out={"type":"dict","keys":sorted(value.keys())}
        for k in ("code","status","success","responseCode","responseMsg","msg","message"):
            if k in value and (value[k] is None or isinstance(value[k],(str,int,float,bool))):
                out[k]=value[k]
        for k in ("data","resultData","rows","list"):
            if k in value:
                out[k]=summarize(value[k],depth+1)
        return out
    if isinstance(value,list):
        out={"type":"list","length":len(value)}
        if value:
            if isinstance(value[0],dict):
                out["item_keys"]=sorted(value[0].keys())
                # Structural nested shapes only.
                for k,v in value[0].items():
                    if isinstance(v,(list,dict)):
                        out.setdefault("item_nested",{})[k]=summarize(v,depth+1)
        return out
    return {"type":type(value).__name__}


def main():
    raw_body=json.dumps(BODY,separators=(",",":")).encode()
    req=urllib.request.Request(
        BASE+ENDPOINT,
        data=raw_body,
        headers=headers(),
        method="POST",
    )
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
        result={
            "schema":"cdr-joyhub-video-list-probe/v1",
            "classification":"TRANSPORT_FAILURE",
            "error_type":type(exc).__name__,
            "error":str(exc)[:300],
        }
        print(json.dumps(result,indent=2,sort_keys=True))
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

    result={
        "schema":"cdr-joyhub-video-list-probe/v1",
        "endpoint":ENDPOINT,
        "http_status":status,
        "content_type":content_type,
        "response_bytes":len(raw),
        "sha256":hashlib.sha256(raw).hexdigest(),
        "classification":classification,
        "request":{
            "product_code_source":"qualified live catalog J-MowgliII",
            "product_code":"3333",
            "page":"1",
            "per_size":6,
            "authorization_sent":False,
            "cookie_sent":False,
            "account_identifier_sent":False,
            "device_id":"synthetic-non-user",
        },
        "json":summarize(parsed) if parsed is not None else None,
        "policy":{
            "raw_payload_published":False,
            "server_ids_guessed":False,
            "state_mutation_intended":False,
        },
    }
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
