"""Bounded comparison of sanitized desktop plugin descriptor inventories.

Inputs are derived plugins.json receipts from the existing static CDR census.
Repeated names represent multiple distinguishable descriptor instances; they
must not be silently overwritten. Never infer runtime feature enablement.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re

MAX_INPUT = 1_000_000
MAX_ROWS = 250
NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$")
SHA = re.compile(r"^[0-9a-f]{64}$")


def _no_duplicate_keys(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError("duplicate JSON key")
        data[key] = value
    return data


def read_plugin_inventory(path: Path) -> tuple[dict[str, tuple[str, ...]], str]:
    raw = path.read_bytes()
    if len(raw) > MAX_INPUT:
        raise ValueError("oversize derived plugin inventory")
    rows = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise ValueError("derived plugin inventory must be bounded list")
    descriptors = defaultdict(list)
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("metadata"), dict):
            raise ValueError("invalid derived plugin row")
        name = row["metadata"].get("name")
        digest = row.get("sha256")
        if name is None:
            continue  # benign manifest without declared plugin name; no claim
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise ValueError("unreviewed plugin name")
        if not isinstance(digest, str) or not SHA.fullmatch(digest):
            raise ValueError("unverified plugin descriptor SHA256")
        descriptors[name].append(digest)
    result = {k: tuple(sorted(v)) for k, v in sorted(descriptors.items())}
    return result, hashlib.sha256(raw).hexdigest()


def compare(left, right):
    l, lsha = left
    r, rsha = right
    overlap = sorted(set(l) & set(r))
    identical = [k for k in overlap if l[k] == r[k]]
    changed = [k for k in overlap if l[k] != r[k]]
    return {
        "schema": "cdr-derived-desktop-plugin-diff/v1",
        "evidence_grade": "STATIC_DESCRIPTOR_PRESENCE_NOT_RUNTIME_ENABLEMENT",
        "source_inventory_hashes": {"left": lsha, "right": rsha},
        "left_distinct_name_count": len(l),
        "right_distinct_name_count": len(r),
        "left_descriptor_instance_count": sum(map(len, l.values())),
        "right_descriptor_instance_count": sum(map(len, r.values())),
        "shared_names_with_identical_descriptor_multiset": identical,
        "shared_names_with_different_descriptor_multiset": changed,
        "only_left": sorted(set(l) - set(r)),
        "only_right": sorted(set(r) - set(l)),
        "runtime_enabled": "NOT_VERIFIED",
        "behavioral_parity": "NOT_VERIFIED",
        "claim_boundary": "Identical SHA256 of plugin.json declares identical file bytes, not runtime activation or service-side API behavior.",
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("left", type=Path)
    p.add_argument("right", type=Path)
    p.add_argument("--out", required=True, type=Path)
    a = p.parse_args()
    result = compare(read_plugin_inventory(a.left), read_plugin_inventory(a.right))
    a.out.write_text(json.dumps(result, indent=2, sort_keys=True) + chr(10), encoding="utf-8")


if __name__ == "__main__":
    main()
