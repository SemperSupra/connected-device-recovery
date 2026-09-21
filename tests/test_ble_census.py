import json
import unittest
from types import SimpleNamespace

from harness.ble.census import (
    advertisement_event,
    characteristic_event,
    select_target,
    service_event,
)


class CensusTests(unittest.TestCase):
    def test_advertisement_normalization(self):
        device = SimpleNamespace(name="fallback", address="AA:BB")
        adv = SimpleNamespace(
            local_name="J-Test",
            rssi=-55,
            tx_power=4,
            service_uuids=["b", "a"],
            manufacturer_data={2: b"\x01\x02"},
            service_data={"x": b"\xaa"},
        )
        event = advertisement_event(
            device, adv, specimen="specimen-x", experiment="EXP-X"
        )
        self.assertEqual(event["kind"], "advertisement")
        self.assertEqual(event["device_identity"], "J-Test")
        self.assertEqual(event["semantic"]["service_uuids"], ["a", "b"])
        self.assertEqual(event["semantic"]["manufacturer_data_hex"]["2"], "0102")
        json.dumps(event)

    def test_target_selection_requires_uniqueness(self):
        d1 = SimpleNamespace(name="J-X", address="1")
        d2 = SimpleNamespace(name="J-X", address="2")
        a1 = SimpleNamespace(local_name="J-X")
        a2 = SimpleNamespace(local_name="J-X")
        with self.assertRaises(RuntimeError):
            select_target(
                [(d1, a1), (d2, a2)], target_name="J-X", target_address=None
            )
        chosen = select_target(
            [(d1, a1), (d2, a2)], target_name=None, target_address="2"
        )
        self.assertIs(chosen[0], d2)

    def test_gatt_events_are_metadata_only(self):
        service = SimpleNamespace(uuid="0000ffa0", handle=1, description="svc")
        char = SimpleNamespace(
            uuid="0000ffa1",
            handle=2,
            description="char",
            properties=["write", "notify"],
        )
        se = service_event(
            service, specimen="s", experiment="e", identity="J-Test"
        )
        ce = characteristic_event(
            service, char, specimen="s", experiment="e", identity="J-Test"
        )
        self.assertEqual(se["kind"], "gatt-service")
        self.assertEqual(ce["kind"], "gatt-characteristic")
        self.assertEqual(ce["semantic"]["properties"], ["notify", "write"])
        self.assertIsNone(ce["value_hex"])


if __name__ == "__main__":
    unittest.main()
