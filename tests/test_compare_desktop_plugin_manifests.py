"""No proprietary donors: plugin descriptor semantic and safety counterexamples."""
import json
from pathlib import Path
import tempfile
import unittest

from tools.compare_desktop_plugin_manifests import (
    read_plugin_inventory,
    compare,
)


def row(name, digest):
    return {"metadata": {"name": name, "version": "1.0"}, "sha256": digest}


class DerivedPluginDiffTests(unittest.TestCase):
    def test_shared_and_extra_plugins_do_not_infer_enablement(self):
        left = ({"browser": ("a"*64,), "unified-computer-use": tuple(sorted(("b"*64, "c"*64)))}, "0"*64)
        right = ({"browser": ("a"*64,), "unified-computer-use": tuple(sorted(("b"*64, "c"*64))),
                  "record-and-replay": ("d"*64,)}, "1"*64)
        r=compare(left,right)
        self.assertEqual(r["only_right"], ["record-and-replay"])
        self.assertEqual(len(r["shared_names_with_identical_descriptor_multiset"]), 2)
        self.assertEqual(r["runtime_enabled"], "NOT_VERIFIED")
        self.assertEqual(r["behavioral_parity"], "NOT_VERIFIED")

    def test_duplicate_name_distinct_descriptors_are_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"plugins.json"
            p.write_text(json.dumps([row("unified-computer-use","b"*64),row("unified-computer-use","c"*64)]))
            v, digest=read_plugin_inventory(p)
            self.assertEqual(v["unified-computer-use"], ("b"*64,"c"*64))
            self.assertEqual(len(digest),64)

    def test_same_name_different_hash_is_not_identical(self):
        a=({"browser": ("a"*64,)}, "0"*64)
        b=({"browser": ("b"*64,)}, "1"*64)
        r=compare(a,b)
        self.assertEqual(r["shared_names_with_different_descriptor_multiset"],["browser"])

    def test_unknown_or_freeform_names_cannot_leak(self):
        for name in ("name https://private.example/token", "../escape", "", "x"*100):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as d:
                p=Path(d)/"bad.json";p.write_text(json.dumps([row(name, "a"*64)]))
                with self.assertRaises(ValueError):
                    read_plugin_inventory(p)

    def test_bad_hash_and_duplicate_json_key_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"bad.json"
            p.write_text(json.dumps([row("browser", "invalid")]))
            with self.assertRaisesRegex(ValueError, "SHA256"):
                read_plugin_inventory(p)
            p.write_text('[{"metadata":{"name":"browser","name":"spoof"},"sha256":"' + "a"*64 + '"}]')
            with self.assertRaisesRegex(ValueError, "duplicate"):
                read_plugin_inventory(p)

    def test_bounded_input_and_row_count(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"bad.json"
            p.write_text(json.dumps([row("browser","a"*64)]*251))
            with self.assertRaisesRegex(ValueError, "bounded list"):
                read_plugin_inventory(p)
            p.write_bytes(b" "*(1_000_001))
            with self.assertRaisesRegex(ValueError, "oversize"):
                read_plugin_inventory(p)


if __name__ == "__main__":
    unittest.main()
