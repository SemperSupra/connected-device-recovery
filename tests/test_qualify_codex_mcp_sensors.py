"""Negative-source contracts for full capability/evidence chain."""
import json
import tempfile
import unittest
from pathlib import Path
from tools.qualify_codex_mcp_sensors import evaluate, validate, _strict_object

def e(kind,**kwargs):
    return {"kind":kind,**kwargs}

def env(events):
    return {"schema":"cdr-codex-source-backed-trace/v1",
            "observation_class":"SYNTHETIC","events":events}

def full():
    return [
      e("bundle",present=True),
      e("installed",enabled=True,callable=True),
      e("permission",app="allow",origin="allow",downloads="deny",
        uploads="deny",full_cdp_access="deny"),
      e("thread_start",ok=True),
      e("mcp_state",state="Starting"),
      e("mcp_initialized",success=True),
      e("mcp_state",state="Connected"),
      e("mcp_catalog",tool_count=1,error=False),
      e("session_configured",arrived=True),
      e("tool_call",ok=True,mutating=True),
      e("state_readback",before=True,after=True,changed=True,independent=True),
      e("cleanup",ok=True),
    ]

class CodexMcpOracleTests(unittest.TestCase):
    def test_full_source_oracle_never_promotes_target_runtime(self):
        r=evaluate(env(full()))
        self.assertEqual(r["contract_grade"],"SYNTHETIC_CRUD_READBACK_CONTRACT_PASS")
        self.assertTrue(r["event_order_qualified"])
        self.assertFalse(r["original_chatgpt_runtime_verified"])
        self.assertFalse(r["permission_to_act_granted_by_this_tool"])

    def test_installed_enabled_is_not_callable(self):
        events=full()
        events[1]["callable"]=False
        r=evaluate(env(events))
        self.assertTrue(r["installed_enabled_observed"])
        self.assertFalse(r["effective_callability_contract"])
        self.assertFalse(r["synthetic_mutation_readback_with_cleanup"])

    def test_disabled_or_failed_mcp_is_not_tool_catalog(self):
        for status in ("Disabled","Failed","AuthenticationRequired","Cancelled","NotStarted"):
            with self.subTest(status=status):
                events=full()
                events[6]["state"]=status
                self.assertFalse(evaluate(env(events))["mcp_catalog_observed"])

    def test_permissions_are_independent_of_bundled_or_catalog(self):
        for key in ("app","origin"):
            with self.subTest(key=key):
                events=full();events[2][key]="deny"
                r=evaluate(env(events))
                self.assertTrue(r["mcp_catalog_observed"])
                self.assertFalse(r["effective_callability_contract"])

    def test_missing_independent_readback_or_cleanup_cannot_promote(self):
        for key in ("before","after","changed","independent"):
            events=full();events[10][key]=False
            self.assertFalse(evaluate(env(events))["synthetic_mutation_readback_with_cleanup"])
        events=full();events[-1]["ok"]=False
        self.assertFalse(evaluate(env(events))["synthetic_mutation_readback_with_cleanup"])

    def test_async_order_and_mcp_init_order_are_explicit(self):
        events=full()
        events[3],events[8]=events[8],events[3]
        r=evaluate(env(events))
        self.assertFalse(r["event_order_qualified"])
        self.assertFalse(r["synthetic_mutation_readback_with_cleanup"])
        events=full()
        events[5],events[7]=events[7],events[5]
        r=evaluate(env(events))
        self.assertFalse(r["event_order_qualified"])
        self.assertFalse(r["mcp_catalog_observed"])

    def test_unknown_payload_and_boolean_count_injection_fail_closed(self):
        for event in (e("mcp_catalog",tool_count=True,error=False),
                      e("mcp_catalog",tool_count=999999,error=False),
                      e("bundle",present="secret"),
                      {"kind":"bundle","present":True,"token":"private"},
                      e("mcp_state",state="Unexpected"),
                      e("permission",app="allow",origin="secret",downloads="deny",uploads="deny",full_cdp_access="deny")):
            with self.subTest(event=event):
                with self.assertRaises(ValueError):
                    validate(env([event]))

    def test_unknown_observation_class_and_duplicate_json_keys_refused(self):
        d=env(full());d["observation_class"]="ORIGINAL_APP"
        with self.assertRaisesRegex(ValueError,"observer class"):
            evaluate(d)
        with self.assertRaisesRegex(ValueError,"duplicate"):
            json.loads('{"schema":"v1","schema":"sneaky"}',object_pairs_hook=_strict_object)

    def test_no_freeform_tool_names_or_conversation_content_in_output(self):
        r=evaluate(env(full()))
        s=json.dumps(r)
        self.assertNotIn("api_key",s)
        self.assertNotIn("message_body",s)
        self.assertIn("rust-v0.167.0",s)
        self.assertNotIn("http_origin",s)

    def test_temporal_cleanup_must_follow_independent_readback(self):
        events=full()
        events[-2],events[-1]=events[-1],events[-2]
        r=evaluate(env(events))
        self.assertFalse(r["event_order_qualified"])
        self.assertFalse(r["synthetic_mutation_readback_with_cleanup"])

    def test_late_permission_cannot_authorize_earlier_invocation(self):
        events=full()
        permission=events.pop(2)
        events.insert(-1,permission)
        r=evaluate(env(events))
        self.assertFalse(r["effective_callability_contract"])
        self.assertFalse(r["synthetic_mutation_readback_with_cleanup"])

    def test_late_permission_grant_cannot_override_pre_call_deny(self):
        events=full()
        events[2]["app"]="deny"
        events.insert(-1,e("permission",app="allow",origin="allow",
                           downloads="deny",uploads="deny",full_cdp_access="deny"))
        r=evaluate(env(events))
        self.assertFalse(r["effective_callability_contract"])
        self.assertFalse(r["synthetic_mutation_readback_with_cleanup"])

    def test_late_connected_notification_cannot_backdate_mcp_catalog(self):
        events=full()
        connected=events.pop(6)
        events.insert(-1,connected)
        r=evaluate(env(events))
        self.assertFalse(r["mcp_catalog_observed"])
        self.assertFalse(r["synthetic_mutation_readback_with_cleanup"])

    def test_duplicated_action_epoch_is_not_a_single_mutation_witness(self):
        events=full()
        events.insert(10,e("tool_call",ok=True,mutating=True))
        r=evaluate(env(events))
        self.assertFalse(r["event_order_qualified"])
        self.assertFalse(r["synthetic_mutation_readback_with_cleanup"])

    def test_disabled_installed_app_cannot_be_called(self):
        events=full()
        events[1]["enabled"]=False
        r=evaluate(env(events))
        self.assertFalse(r["installed_enabled_observed"])
        self.assertFalse(r["effective_callability_contract"])
        self.assertFalse(r["synthetic_mutation_readback_with_cleanup"])

    def test_mcp_catalog_requires_same_connected_epoch(self):
        for case in ("failed_at_catalog","lost_connection_after_catalog"):
            with self.subTest(case=case):
                events=full()
                if case=="failed_at_catalog":
                    events.insert(7,e("mcp_state",state="Failed"))
                    events.insert(9,e("mcp_state",state="Connected"))
                else:
                    events.insert(8,e("mcp_state",state="Failed"))
                    events.insert(9,e("mcp_state",state="Connected"))
                r=evaluate(env(events))
                self.assertFalse(r["mcp_catalog_observed"])
                self.assertFalse(r["synthetic_mutation_readback_with_cleanup"])

    def test_late_mcp_init_failure_cannot_reuse_earlier_success(self):
        events=full()
        events.insert(9,e("mcp_initialized",success=False))
        r=evaluate(env(events))
        self.assertFalse(r["mcp_connected_and_initialized_observed"])
        self.assertFalse(r["synthetic_mutation_readback_with_cleanup"])

    def test_failed_thread_or_late_session_config_is_not_valid_invocation(self):
        for index,key in ((3,"ok"),(8,"arrived")):
            with self.subTest(index=index):
                events=full()
                events[index][key]=False
                r=evaluate(env(events))
                self.assertFalse(r["synthetic_mutation_readback_with_cleanup"])

if __name__=="__main__":
    unittest.main()
