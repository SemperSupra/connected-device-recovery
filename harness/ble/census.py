#!/usr/bin/env python3
"""Read-only BLE advertisement/GATT census -> CDR normalized JSONL trace.

This utility deliberately exposes no GATT read, write, notify, pair, or firmware path.
It scans advertisements and, when an exact target is supplied, connects only long
enough for the OS/Bleak service discovery performed during connection.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

TOOL = "cdr-ble-census"
TOOL_VERSION = "0.1.0"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _hex(value: bytes | bytearray | None) -> str | None:
    return None if value is None else bytes(value).hex()


def base_event(
    kind: str,
    *,
    specimen: str | None,
    experiment: str | None,
    device_identity: str | None = None,
    service: str | None = None,
    characteristic: str | None = None,
    semantic: Any = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "ts": now_iso(),
        "source": "instrumentation",
        "kind": kind,
        "specimen": specimen,
        "experiment": experiment,
        "device_identity": device_identity,
        "service": service,
        "characteristic": characteristic,
        "value_hex": None,
        "semantic": semantic,
        "provenance": {
            "tool": TOOL,
            "tool_version": TOOL_VERSION,
            "platform": platform.platform(),
            **(provenance or {}),
        },
    }


def advertisement_event(
    device: Any,
    adv: Any,
    *,
    specimen: str | None,
    experiment: str | None,
) -> dict[str, Any]:
    local_name = getattr(adv, "local_name", None) or getattr(device, "name", None)
    manufacturer = {
        str(k): _hex(v)
        for k, v in sorted((getattr(adv, "manufacturer_data", {}) or {}).items())
    }
    service_data = {
        str(k): _hex(v)
        for k, v in sorted((getattr(adv, "service_data", {}) or {}).items())
    }
    return base_event(
        "advertisement",
        specimen=specimen,
        experiment=experiment,
        device_identity=local_name,
        semantic={
            "address_or_platform_id": getattr(device, "address", None),
            "local_name": local_name,
            "rssi": getattr(adv, "rssi", None),
            "tx_power": getattr(adv, "tx_power", None),
            "service_uuids": sorted(getattr(adv, "service_uuids", []) or []),
            "manufacturer_data_hex": manufacturer,
            "service_data_hex": service_data,
        },
    )


def service_event(
    service: Any,
    *,
    specimen: str | None,
    experiment: str | None,
    identity: str | None,
) -> dict[str, Any]:
    return base_event(
        "gatt-service",
        specimen=specimen,
        experiment=experiment,
        device_identity=identity,
        service=str(service.uuid),
        semantic={
            "handle": getattr(service, "handle", None),
            "description": getattr(service, "description", None),
        },
    )


def characteristic_event(
    service: Any,
    characteristic: Any,
    *,
    specimen: str | None,
    experiment: str | None,
    identity: str | None,
) -> dict[str, Any]:
    return base_event(
        "gatt-characteristic",
        specimen=specimen,
        experiment=experiment,
        device_identity=identity,
        service=str(service.uuid),
        characteristic=str(characteristic.uuid),
        semantic={
            "handle": getattr(characteristic, "handle", None),
            "description": getattr(characteristic, "description", None),
            "properties": sorted(getattr(characteristic, "properties", []) or []),
        },
    )


def select_target(
    discovered: Iterable[tuple[Any, Any]],
    *,
    target_name: str | None,
    target_address: str | None,
) -> tuple[Any, Any] | None:
    if not target_name and not target_address:
        return None

    matches = []
    for device, adv in discovered:
        name = getattr(adv, "local_name", None) or getattr(device, "name", None)
        address = getattr(device, "address", None)
        if target_address and address == target_address:
            matches.append((device, adv))
        elif target_name and name == target_name:
            matches.append((device, adv))

    if not matches:
        raise RuntimeError("target not found during scan")
    if len(matches) > 1:
        raise RuntimeError(
            "target selector matched multiple devices; rerun with --target-address "
            "or the platform-specific identifier shown in the advertisement trace"
        )
    return matches[0]


def write_jsonl(events: Iterable[dict[str, Any]], path: str | None) -> None:
    lines = [json.dumps(e, sort_keys=True, separators=(",", ":")) for e in events]
    text = "\n".join(lines) + ("\n" if lines else "")
    if path:
        Path(path).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


async def census(args: argparse.Namespace) -> list[dict[str, Any]]:
    # Import only for real hardware execution so unit tests do not require BLE.
    from bleak import BleakClient, BleakScanner, __version__ as bleak_version

    scan_kwargs: dict[str, Any] = {}
    if args.passive:
        scan_kwargs["scanning_mode"] = "passive"

    discovered_map = await BleakScanner.discover(
        timeout=args.scan_seconds,
        return_adv=True,
        **scan_kwargs,
    )
    discovered = list(discovered_map.values())
    events = [
        advertisement_event(
            device,
            adv,
            specimen=args.specimen,
            experiment=args.experiment,
        )
        for device, adv in discovered
    ]

    target = select_target(
        discovered,
        target_name=args.target_name,
        target_address=args.target_address,
    )
    if target is None:
        return events

    device, adv = target
    identity = getattr(adv, "local_name", None) or getattr(device, "name", None)
    provenance = {"bleak_version": bleak_version}

    events.append(
        base_event(
            "marker",
            specimen=args.specimen,
            experiment=args.experiment,
            device_identity=identity,
            semantic={"phase": "connect_for_service_enumeration"},
            provenance=provenance,
        )
    )

    # pair=False and no read/write/notify methods are exposed or called.
    async with BleakClient(device, pair=False, timeout=args.connect_timeout) as client:
        for service in client.services:
            events.append(
                service_event(
                    service,
                    specimen=args.specimen,
                    experiment=args.experiment,
                    identity=identity,
                )
            )
            for characteristic in service.characteristics:
                events.append(
                    characteristic_event(
                        service,
                        characteristic,
                        specimen=args.specimen,
                        experiment=args.experiment,
                        identity=identity,
                    )
                )

    events.append(
        base_event(
            "marker",
            specimen=args.specimen,
            experiment=args.experiment,
            device_identity=identity,
            semantic={"phase": "disconnected"},
            provenance=provenance,
        )
    )
    return events


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Read-only BLE advertisement/GATT census emitting CDR JSONL traces."
    )
    p.add_argument("--scan-seconds", type=float, default=8.0)
    p.add_argument("--connect-timeout", type=float, default=30.0)
    p.add_argument("--target-name", help="Exact advertised local name to connect/enumerate.")
    p.add_argument(
        "--target-address",
        help="Exact BLE address or platform identifier from the scan trace.",
    )
    p.add_argument(
        "--passive",
        action="store_true",
        help=(
            "Request passive scanning when the platform supports it. "
            "Bleak/CoreBluetooth does not support passive scanning on macOS."
        ),
    )
    p.add_argument("--specimen")
    p.add_argument("--experiment")
    p.add_argument("--output", help="JSONL output path; stdout when omitted.")
    return p


def main() -> int:
    args = parser().parse_args()
    if args.target_name and args.target_address:
        raise SystemExit("use only one target selector")
    events = asyncio.run(census(args))
    write_jsonl(events, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
