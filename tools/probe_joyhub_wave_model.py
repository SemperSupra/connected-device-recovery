#!/usr/bin/env python3
"""One-shot anonymous JOYHUB recommendation-wave model probe for J-MowgliII.

Recovered Android 2.14.2 contract:
POST api/video/getRecommendModel
{"product_id":"320"}

320 is the server-issued J-MowgliII ProductBean.id from the qualified anonymous
live catalog. Uses the recovered logged-out interceptor header shape. Publishes
only structural metadata and response hash.
"""
from __future__ import annotations
import hashlib,json,time,urllib.error,urllib.request,uuid

URL="https://appapi.joyhub.net/api/video/getRecommendModel"
BODY={"product_id":"320"}
DEVICE="cdr-wave-model-20260922"

def headers():
    return {
        "Accept":"application/json","Content-Type":"application/json",
        "User-Agent":"okhttp/3.12.13","Authorization":"",
        "JH-Device":"Android","JH-FromApp":"Joyhub","JH-DeviceId":DEVICE,
        "X-Request-ID":str(uuid.uuid4()),"JH-AppVersion":"2.14.2",
        "JH-AppChannel":"","JH-SystemVersion":"android0","JH-DeviceModel":"CDR",
        "JH-Screen":"","JH-Latitude":"","JH-Longitude":"","JH-SimCountry":"",
        "JH-Lang":"en","Content-Language":"en","JH-userId":"",
        "JH-clientTime":str(int(time.time())),"JH-IP":"","JH-NetworkType":"unknown",
        "Time-Zone":"UTC","Utc-Offset":"+00:00",
    }

def shape(v,depth=0):
    if depth>3:return {"type":type(v).__name__}
    if isinstance(v,dict):
        o={"type":"dict","keys":sorted(v.keys())}
        for k in ("code","status","success","responseCode","responseMsg","msg","message"):
            if k in v and (v[k] is None or isinstance(v[k],(str,int,float,bool))):o[k]=v[k]
        for k in ("data","resultData","rows","list"):
            if k in v:o[k]=shape(v[k],depth+1)
        return o
    if isinstance(v,list):
        o={"type":"list","length":len(v)}
        if v and isinstance(v[0],dict):
            o["item_keys"]=sorted(v[0].keys())
            o["item_value_types"]={k:type(val).__name__ for k,val in sorted(v[0].items())}
        return o
    return {"type":type(v).__name__}

def main():
    data=json.dumps(BODY,separators=(",",":")).encode()
    req=urllib.request.Request(URL,data=data,headers=headers(),method="POST")
    try:
        with urllib.request.urlopen(req,timeout=30) as r:
            raw=r.read(); status=r.status; ct=r.headers.get("Content-Type")
    except urllib.error.HTTPError as e:
        raw=e.read(); status=e.code; ct=e.headers.get("Content-Type")
    except Exception as e:
        print(json.dumps({"schema":"cdr-joyhub-wave-model-probe/v1","classification":"TRANSPORT_FAILURE","error_type":type(e).__name__,"error":str(e)[:300]},indent=2,sort_keys=True));return 0
    try: parsed=json.loads(raw.decode())
    except Exception: parsed=None
    code=parsed.get("code") if isinstance(parsed,dict) else None
    st=parsed.get("status") if isinstance(parsed,dict) else None
    if status in (401,403):cl="AUTH_BOUNDARY"
    elif 200<=status<300 and isinstance(parsed,dict) and (code==0 or st=="success"):cl="ANONYMOUS_READ_OK"
    elif 200<=status<300:cl="APPLICATION_BOUNDARY"
    else:cl="CONTRACT_OR_SERVER_BOUNDARY"
    print(json.dumps({
      "schema":"cdr-joyhub-wave-model-probe/v1","endpoint":"api/video/getRecommendModel",
      "classification":cl,"http_status":status,"content_type":ct,
      "response_bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),
      "request":{"product_id":"320","product_id_source":"qualified live catalog J-MowgliII","authorization_value":"empty","jh_user_id_value":"empty","cookie_sent":False,"account_identifier_sent":False},
      "json":shape(parsed) if parsed is not None else None,
      "policy":{"request_count":1,"raw_payload_published":False,"server_ids_guessed":False,"state_mutation_intended":False}
    },indent=2,sort_keys=True))
    return 0

if __name__=="__main__":raise SystemExit(main())
