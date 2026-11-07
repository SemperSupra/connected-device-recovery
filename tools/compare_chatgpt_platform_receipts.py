"""Read-only four-platform comparison of sanitized ChatGPT donor receipts.

Consumes ONLY derived JSON/NDJSON produced by existing CDR/AAR workcells.
Does not download, unpack, execute or publish proprietary target files.
A package match or feature declaration is never proof of behavioral parity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

MAX_INPUT = 2_000_000
MAX_ROWS = 32
SHA = re.compile(r"^[a-f0-9]{64}$")
VERSION = re.compile(r"^[a-zA-Z0-9._+~:-]{1,90}$")
ALLOWED_LINUX_TRUST = frozenset({
    "RPM_SIGNATURE_KEY_UNAVAILABLE", "RPM_SIGNATURE_VERIFIED",
    "RPM_SIGNATURE_INVALID", "DEB_PACKAGE_AUTHENTICITY_NOT_VERIFIED",
    "PACKAGE_AUTHENTICITY_NOT_VERIFIED",
})
ALLOWED_ABI_STATUS = frozenset({
    "NATIVE_ABI_MATCH", "NATIVE_ABI_MISMATCH", "NATIVE_ABI_NOT_ESTABLISHED",
})


def _unique_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key in derived evidence")
        out[key] = value
    return out


def read_json(path: Path) -> tuple[dict, str]:
    data = path.read_bytes()
    if len(data) > MAX_INPUT:
        raise ValueError("derived evidence exceeds input bound")
    obj = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_pairs)
    if not isinstance(obj, dict):
        raise ValueError("expected derived JSON object")
    return obj, hashlib.sha256(data).hexdigest()


def read_ndjson(path: Path) -> tuple[list[dict], str]:
    data = path.read_bytes()
    if len(data) > MAX_INPUT:
        raise ValueError("derived evidence exceeds input bound")
    lines = [l for l in data.decode("utf-8").splitlines() if l.strip()]
    if not lines or len(lines) > MAX_ROWS:
        raise ValueError("missing or excessive derived records")
    objs = [json.loads(line, object_pairs_hook=_unique_pairs) for line in lines]
    if not all(isinstance(o, dict) for o in objs):
        raise ValueError("derived records must be objects")
    return objs, hashlib.sha256(data).hexdigest()


def value(value):
    """Allowlist short release identifiers; never echo free-form original data."""
    return value if isinstance(value, str) and VERSION.fullmatch(value) else None


def sha(value):
    return value if isinstance(value, str) and SHA.fullmatch(value.lower()) else None


def compare(windows: list[tuple[dict, str]], linux: tuple[list[dict], str],
            macos: tuple[list[dict], str], android: tuple[dict, str]) -> dict:
    if len(windows) != 2:
        raise ValueError("Windows requires independent x64 and ARM64 receipts")
    win = []
    for obj, receipt_sha in windows:
        if obj.get("schema") != "cdr-chatgpt-windows-derived-package/v2":
            raise ValueError("unsupported Windows schema")
        ident, pkg = obj.get("identity") or {}, obj.get("package") or {}
        arch = value(ident.get("processor_architecture"))
        if arch not in {"x64", "arm64"}:
            raise ValueError("missing verified Windows architecture field")
        win.append({
            "architecture": arch, "version": value(ident.get("version")),
            "package_sha256": sha(pkg.get("sha256")),
            "reported_authenticode": "VALID_REPORTED" if pkg.get("signature_status") == "Valid" else "NOT_VERIFIED",
            "source_receipt_sha256": receipt_sha,
        })
    if {w["architecture"] for w in win} != {"x64", "arm64"}:
        raise ValueError("duplicate or missing Windows architecture")
    win.sort(key=lambda x: x["architecture"])
    same_version = all(x["version"] for x in win) and win[0]["version"] == win[1]["version"]

    linux_rows, linux_sha = linux
    lin = []
    for row in linux_rows:
        if row.get("package_kind") not in {"deb", "rpm"}:
            raise ValueError("unexpected Linux package kind")
        trust = row.get("package_signature_status")
        lin.append({
            "kind": row["package_kind"], "architecture": value(row.get("architecture")),
            "version": value(row.get("version")), "package_sha256": sha(row.get("sha256")),
            "authenticity": trust if trust in ALLOWED_LINUX_TRUST else "NOT_VERIFIED",
        })
    mac_rows, mac_sha = macos
    mac = []
    for row in mac_rows:
        b = row.get("bundle")
        if not isinstance(b, dict):
            raise ValueError("missing macOS bundle metadata")
        mac.append({
            "bundle_version": value(b.get("CFBundleVersion")),
            "short_version": value(b.get("CFBundleShortVersionString")),
            "dmg_sha256": sha(row.get("dmg_sha256")),
            # Signature is qualified in original workcell; do not promote raw
            # codesign/spctl free text into a new trust claim here.
            "signature": "SEE_ORIGINAL_MACOS_SIGNATURE_GATE",
        })
    android_obj, android_sha = android
    if (android_obj.get("schema") != "aar-chatgpt-public-recovery-receipt/v1"
            or android_obj.get("package_id") != "com.openai.chatgpt"):
        raise ValueError("unexpected Android receipt identity")
    abi = android_obj.get("native_abi_qualification") or {}
    abi_status = abi.get("status")
    if abi_status not in ALLOWED_ABI_STATUS:
        raise ValueError("unsupported Android ABI classification")
    signed = android_obj.get("official_signer_verified") is True
    source = android_obj.get("selected_source")
    source = source if source in {"apkpure", "uptodown", "google_play"} else "UNKNOWN"
    result = {
        "schema": "cdr-chatgpt-cross-platform-derived-diff/v1",
        "evidence_grade": "DERIVED_STATIC_METADATA_ONLY",
        "windows": {"receipts": win, "same_version_across_architectures": bool(same_version)},
        "linux": {"receipts_sha256": linux_sha, "packages": lin},
        "macos": {"receipts_sha256": mac_sha, "bundles": mac},
        "android": {
            "receipts_sha256": android_sha,
            "source_channel": source,
            "publisher_signer_claim_reported": signed,
            "native_abi_status": abi_status,
            "decompiler_status": value((android_obj.get("decompiler_qualification") or {}).get("status")),
            "play_provenance_verified": False if source != "google_play" else None,
        },
        "cross_platform_feature_parity": "NOT_VERIFIED",
        "cross_platform_state_crud_parity": "NOT_VERIFIED",
        "cross_platform_protocol_parity": "NOT_VERIFIED",
        "original_runtime_verified": False,
        "promotion_authorized": False,
        "claim_boundary": "Static donor receipts can expose package/ABI/version differences, not equivalence of functions, APIs, server state or runtime behavior.",
    }
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("windows_x64", "windows_arm64", "linux", "macos", "android"):
        p.add_argument("--" + name.replace("_", "-"), required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    a = p.parse_args()
    output = compare(
        [read_json(a.windows_x64), read_json(a.windows_arm64)],
        read_ndjson(a.linux), read_ndjson(a.macos), read_json(a.android),
    )
    a.out.write_text(json.dumps(output, indent=2, sort_keys=True) + chr(10), encoding="utf-8")


if __name__ == "__main__":
    main()
