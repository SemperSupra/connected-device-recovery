"""Source-owned four-platform differential/negative controls, no donor downloads."""
import json
import tempfile
import unittest
from pathlib import Path

from tools.compare_chatgpt_platform_receipts import compare, read_json, read_ndjson


def windows(arch):
    return ({
        "schema": "cdr-chatgpt-windows-derived-package/v2",
        "identity": {"version": "26.1103.3517.0", "processor_architecture": arch},
        "package": {"sha256": "b" * 64, "signature_status": "Valid"},
    }, "a" * 64)


def fixture():
    linux = ([
        {"package_kind": "rpm", "architecture": "x86_64", "version": "1.0",
         "sha256": "c" * 64, "package_signature_status": "RPM_SIGNATURE_KEY_UNAVAILABLE"},
        {"package_kind": "deb", "architecture": "amd64", "version": "1.0",
         "sha256": "d" * 64, "package_signature_status": "DEB_PACKAGE_AUTHENTICITY_NOT_VERIFIED"},
    ], "e" * 64)
    mac = ([{"bundle": {"CFBundleVersion": "26.1103.3517.0"},
             "dmg_sha256": "f" * 64,
             "codesign_summary": "any freeform string never emitted"}], "1" * 64)
    android = ({
        "schema": "aar-chatgpt-public-recovery-receipt/v1",
        "package_id": "com.openai.chatgpt",
        "selected_source": "apkpure",
        "official_signer_verified": True,
        "native_abi_qualification": {"status": "NATIVE_ABI_MISMATCH"},
        "decompiler_qualification": {"status": "PARTIAL"},
    }, "2" * 64)
    return [windows("x64"), windows("arm64")], linux, mac, android


class CrossPlatformReceiptsTests(unittest.TestCase):
    def test_realistic_signed_static_receipts_not_runtime_parity(self):
        r = compare(*fixture())
        self.assertEqual(r["schema"], "cdr-chatgpt-cross-platform-derived-diff/v1")
        self.assertTrue(r["windows"]["same_version_across_architectures"])
        self.assertEqual(r["android"]["native_abi_status"], "NATIVE_ABI_MISMATCH")
        self.assertEqual(r["android"]["play_provenance_verified"], False)
        self.assertEqual(r["linux"]["packages"][0]["authenticity"], "RPM_SIGNATURE_KEY_UNAVAILABLE")
        self.assertFalse(r["original_runtime_verified"])
        self.assertFalse(r["promotion_authorized"])
        self.assertEqual(r["cross_platform_state_crud_parity"], "NOT_VERIFIED")
        self.assertNotIn("any freeform string", json.dumps(r))

    def test_windows_architecture_mismatch_refused(self):
        w, l, m, a = fixture()
        with self.assertRaisesRegex(ValueError, "duplicate or missing"):
            compare([windows("x64"), windows("x64")], l, m, a)

    def test_bad_schema_fails_closed(self):
        w, l, m, a = fixture()
        a[0]["schema"] = "unknown"
        with self.assertRaises(ValueError):
            compare(w, l, m, a)

    def test_unknown_linux_signature_does_not_promote(self):
        w, l, m, a = fixture()
        l[0][0]["package_signature_status"] = "VERIFIED_BY_VIBES"
        r = compare(w, l, m, a)
        self.assertEqual(r["linux"]["packages"][0]["authenticity"], "NOT_VERIFIED")

    def test_no_arbitrary_metadata_leak(self):
        w, l, m, a = fixture()
        l[0][0]["version"] = "secret.example.com/?token=123"
        a[0]["selected_source"] = "private-file:///secret"
        r = compare(w, l, m, a)
        self.assertIsNone(r["linux"]["packages"][0]["version"])
        self.assertEqual(r["android"]["source_channel"], "UNKNOWN")
        self.assertNotIn("secret", json.dumps(r))

    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "receipt.json"
            p.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                read_json(p)

    def test_ndjson_bound_and_records(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "rows.ndjson"
            p.write_text('{"package_kind":"rpm"}' + chr(10), encoding="utf-8")
            records, sha = read_ndjson(p)
            self.assertEqual(len(records), 1)
            self.assertEqual(len(sha), 64)
            p.write_text("{}" + chr(10) * 0 if False else ("{}" + chr(10)) * 33)
            with self.assertRaisesRegex(ValueError, "excessive"):
                read_ndjson(p)


if __name__ == "__main__":
    unittest.main()
