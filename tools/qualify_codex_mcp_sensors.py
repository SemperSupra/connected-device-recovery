#!/usr/bin/env python3
"""Bounded source-backed Codex protocol evidence ladder: synthetic contracts only.

Tagged oracle: openai/codex rust-v0.167.0 app-server v2 protocol.
No original ChatGPT process, credentials, MCP tool calls, or user data are used.
Raw event traces are input only; public output contains no event payloads.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

SOURCE_TAG = "rust-v0.167.0"
SOURCE_BLOBS = {
    "computer_use_config": "27399954f9d3148814534f07b11973257ea14bd7",
    "browser_use_config": "0045f7b22ae41a63b278dcf11c7fa183e49e7c6d",
    "mcp_status": "824d770f503a934351318d51dd0efbbd8594ced1",
    "apps": "1993c27b759e9e402ba200b89dc1f67984bfd55b",
}
MAX_SOURCE = 32_768
MAX_EVENTS = 64
MCP_STATES = frozenset({"NotStarted", "Starting", "Connected",
                        "AuthenticationRequired", "Failed", "Cancelled", "Disabled"})
POLICY = frozenset({"allow", "deny", "unknown"})
FIELDS = {
    "bundle": {"present"},
    "installed": {"enabled", "callable"},
    "permission": {"app", "origin", "downloads", "uploads", "full_cdp_access"},
    "thread_start": {"ok"},
    "session_configured": {"arrived"},
    "mcp_state": {"state"},
    "mcp_initialized": {"success"},
    "mcp_catalog": {"tool_count", "error"},
    "tool_call": {"ok", "mutating"},
    "state_readback": {"before", "after", "changed", "independent"},
    "cleanup": {"ok"},
}
BOOLEAN_FIELDS = frozenset({"present","enabled","callable","ok","arrived","success",
                             "error","mutating","before","after","changed","independent"})


def _strict_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key] = value
    return out


def validate(document: dict) -> list[dict]:
    if not isinstance(document,dict) or set(document)!={"schema","observation_class","events"}:
        raise ValueError("invalid source oracle envelope")
    if document["schema"] != "cdr-codex-source-backed-trace/v1" or document["observation_class"] != "SYNTHETIC":
        raise ValueError("unsupported or unqualified observer class")
    events=document["events"]
    if not isinstance(events,list) or len(events)>MAX_EVENTS:
        raise ValueError("event count outside approved envelope")
    for event in events:
        if not isinstance(event,dict) or not isinstance(event.get("kind"),str):
            raise ValueError("invalid event envelope")
        kind=event["kind"]
        if kind not in FIELDS or set(event)!=(FIELDS[kind]|{"kind"}):
            raise ValueError("unreviewed event kind or fields")
        for field in BOOLEAN_FIELDS & FIELDS[kind]:
            if type(event[field]) is not bool:
                raise ValueError("boolean sensor field has invalid type")
        if kind=="permission" and any(event[p] not in POLICY for p in FIELDS[kind]):
            raise ValueError("unreviewed permission status")
        if kind=="mcp_state" and event["state"] not in MCP_STATES:
            raise ValueError("unreviewed MCP runtime status")
        if kind=="mcp_catalog" and (type(event["tool_count"]) is not int
                                   or not 0<=event["tool_count"]<=256):
            raise ValueError("invalid bounded tool count")
    return events


def evaluate(document: dict) -> dict:
    events=validate(document)
    first={}
    last={}
    for idx,event in enumerate(events):
        kind=event["kind"]
        if kind not in first:
            first[kind]=idx
        last[kind]=event
    # One source-known synthetic action per receipt. Preserve the time at
    # which authority and MCP state were actually observed; a later allow or
    # Connected notification cannot authorize an earlier invocation.
    def ordered(earlier,later):
        return earlier in first and later in first and first[earlier]<first[later]

    n_calls=sum(event["kind"]=="tool_call" for event in events)
    n_readbacks=sum(event["kind"]=="state_readback" for event in events)
    n_cleanups=sum(event["kind"]=="cleanup" for event in events)
    n_catalogs=sum(event["kind"]=="mcp_catalog" for event in events)
    call_limit=first.get("tool_call",len(events))

    def before_index(kind,limit):
        for event in reversed(events[:limit]):
            if event["kind"]==kind:
                return event
        return {}

    def before_call(kind):
        return before_index(kind,call_limit)

    b=before_call("bundle")
    ins=before_call("installed")
    perm=before_call("permission")
    mcp=before_call("mcp_state")
    catalog=before_call("mcp_catalog")
    call=last.get("tool_call",{}) if n_calls==1 else {}
    initialized=before_call("mcp_initialized").get("success") is True
    catalog_at=first.get("mcp_catalog",call_limit)
    mcp_at_catalog=before_index("mcp_state",catalog_at)
    init_at_catalog=before_index("mcp_initialized",catalog_at)
    connected_epoch_intact=all(
        event["state"]=="Connected"
        for event in events[catalog_at+1:call_limit]
        if event["kind"]=="mcp_state")

    event_order_qualified = (
        n_calls<=1 and n_readbacks<=1 and n_cleanups<=1 and n_catalogs<=1
        and ("session_configured" not in first or ordered("thread_start","session_configured"))
        and ("mcp_catalog" not in first or (
            mcp_at_catalog.get("state")=="Connected"
            and init_at_catalog.get("success") is True
            and ordered("mcp_initialized","mcp_catalog")
            and connected_epoch_intact))
        and ("tool_call" not in first or all(
            ordered(kind,"tool_call") for kind in (
                "bundle","installed","permission","thread_start",
                "session_configured","mcp_catalog")))
        and ("state_readback" not in first or ordered("tool_call","state_readback"))
        and ("cleanup" not in first or ordered("state_readback","cleanup"))
    )
    state=last.get("state_readback",{})
    cleanup=last.get("cleanup",{})
    declared=b.get("present") is True
    enabled=ins.get("enabled") is True
    callable_=ins.get("callable") is True
    authorized=perm.get("app")=="allow" and perm.get("origin")=="allow"
    connected=mcp.get("state")=="Connected" and initialized and event_order_qualified
    cataloged=(connected and catalog.get("error") is False
               and type(catalog.get("tool_count")) is int)
    callable_verified=cataloged and enabled and callable_ and authorized and catalog["tool_count"]>0
    called=(callable_verified and call.get("ok") is True and event_order_qualified
            and before_call("thread_start").get("ok") is True
            and before_call("session_configured").get("arrived") is True)
    observed_change=(called and call.get("mutating") is True
                     and all(state.get(k) is True for k in ("before","after","changed","independent"))
                     and cleanup.get("ok") is True and event_order_qualified)
    grade=("SYNTHETIC_CRUD_READBACK_CONTRACT_PASS" if observed_change
           else "SYNTHETIC_INVOCATION_CONTRACT_PASS" if called
           else "SYNTHETIC_CALLABLE_CATALOG_CONTRACT_PASS" if callable_verified
           else "SYNTHETIC_CATALOG_CONTRACT_PASS" if cataloged
           else "SYNTHETIC_INSTALLED_ENABLED_ONLY" if enabled
           else "SYNTHETIC_BUNDLED_ONLY" if declared
           else "SYNTHETIC_UNOBSERVED")
    return {
        "schema":"cdr-codex-source-backed-evaluation/v1",
        "source_release":SOURCE_TAG,
        "pinned_source_blobs":SOURCE_BLOBS,
        "source_contract_class":"PUBLIC_TAGGED_SOURCE_ORACLE_NOT_TARGET_BINARY_IDENTITY",
        "observation_class":"SYNTHETIC",
        "event_count":len(events),
        "event_order_qualified":event_order_qualified,
        "bundled_descriptor_observed":declared,
        "installed_enabled_observed":enabled,
        "installed_callable_declared":callable_,
        "app_and_origin_policy_allow":authorized,
        "mcp_connected_and_initialized_observed":connected,
        "mcp_catalog_observed":cataloged,
        "effective_callability_contract":callable_verified,
        "synthetic_mutation_readback_with_cleanup":observed_change,
        "contract_grade":grade,
        "original_chatgpt_runtime_verified":False,
        "product_release_identity_verified":False,
        "permission_to_act_granted_by_this_tool":False,
        "claim_boundary":"Static Codex source-backed synthetic invariants only. Source types are not observed ChatGPT GUI, permissions, API, MCP state, or CRUD.",
    }


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source",type=Path)
    parser.add_argument("--out",required=True,type=Path)
    args=parser.parse_args()
    raw=args.source.read_bytes()
    if len(raw)>MAX_SOURCE:
        raise ValueError("observer JSON exceeds source limit")
    document=json.loads(raw.decode("utf-8"),object_pairs_hook=_strict_object)
    result=evaluate(document)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")


if __name__=="__main__":
    main()
