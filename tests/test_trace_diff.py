import unittest

from harness.diff.compare import canonical_event, compare


def event(kind, value=None, *, ts="2026-09-21T00:00:00Z", source="oracle"):
    return {
        "ts": ts,
        "source": source,
        "kind": kind,
        "specimen": "s",
        "experiment": "e",
        "device_identity": "J-Test",
        "service": "0000FFA0-0000-1000-8000-00805F9B34FB",
        "characteristic": "0000FFA1-0000-1000-8000-00805F9B34FB",
        "value_hex": value,
        "semantic": {"intent": "test"} if kind == "control-intent" else None,
        "provenance": {"run": "volatile"},
    }


class TraceDiffTests(unittest.TestCase):
    def test_ignores_only_declared_noise_and_hex_case(self):
        left = event("ble-write", "A00301000000AA", ts="2026-09-21T00:00:00Z")
        right = event("ble-write", "a00301000000aa", ts="2026-09-21T01:00:00Z")
        right["provenance"] = {"run": "different"}
        self.assertEqual(canonical_event(left), canonical_event(right))

    def test_detects_payload_change(self):
        report = compare(
            [event("ble-write", "a00301000000aa")],
            [event("ble-write", "a00302000000aa")],
            kinds={"ble-write"},
        )
        self.assertFalse(report["equal"])
        self.assertEqual(report["delta_count"], 1)
        self.assertEqual(report["deltas"][0]["op"], "replace")

    def test_default_scope_can_exclude_markers(self):
        left = [event("marker"), event("ble-write", "aa")]
        right = [event("ble-write", "aa")]
        report = compare(left, right, kinds={"ble-write"})
        self.assertTrue(report["equal"])

    def test_order_change_is_not_hidden(self):
        a = event("ble-write", "01")
        b = event("ble-write", "02")
        report = compare([a, b], [b, a], kinds={"ble-write"})
        self.assertFalse(report["equal"])
        self.assertGreater(report["delta_count"], 0)

    def test_all_fields_other_than_declared_noise_survive(self):
        x = event("ble-write", "AA")
        x["semantic"] = {"nested": {"v": 1}}
        c = canonical_event(x)
        self.assertNotIn("ts", c)
        self.assertNotIn("provenance", c)
        self.assertEqual(c["semantic"]["nested"]["v"], 1)
        self.assertEqual(c["value_hex"], "aa")


if __name__ == "__main__":
    unittest.main()
