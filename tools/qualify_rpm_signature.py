"""Classify RPM signature verification output without claiming owner key trust.

This is derived metadata only. A signature verified against a locally present key
cannot prove that the key is owned/trusted by the software publisher.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_FAILURE = re.compile(r"\b(?:BAD|NOTTRUSTED|NOT[ -]?OK|FAILED|FAILURE|INVALID)\b", re.I)
_SIG_OK = re.compile(r"\b(?:signature|sig)\b[^\n]*:\s*OK\b", re.I)
_DIGEST_OK = re.compile(r"\b(?:digest|sha\d+)\b[^\n]*:\s*OK\b", re.I)


def qualify(log_text: str, exit_code: int) -> dict:
    """Produce a bounded, fail-closed classification without raw log leakage."""
    if not isinstance(log_text, str) or type(exit_code) is not int or exit_code < 0:
        raise ValueError("Invalid rpm verifier input")
    if _FAILURE.search(log_text):
        status = "RPM_SIGNATURE_BAD_OR_UNTRUSTED"
    elif re.search(r"\bNOKEY\b", log_text, re.I):
        status = "RPM_SIGNATURE_KEY_UNAVAILABLE"
    elif exit_code != 0:
        status = "RPM_VERIFIER_RETURNED_NONZERO"
    elif _SIG_OK.search(log_text):
        status = "RPM_SIGNATURE_CHECK_OK_OWNER_KEY_UNATTESTED"
    elif _DIGEST_OK.search(log_text):
        status = "RPM_DIGEST_OK_SIGNATURE_UNVERIFIED"
    else:
        status = "RPM_SIGNATURE_EVIDENCE_MISSING"
    return {
        "schema": "cdr-rpm-signature-qualification/v1",
        "status": status,
        "rpm_verify_exit_code": exit_code,
        "official_publisher_key_attested": False,
        "original_package_signature_accepted": False,
        "claim_boundary": "Untrusted or absent signer key is not an authenticity pass; detached first-party key trust must be independently established.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--exit-code", type=int, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    doc = qualify(args.log.read_text(encoding="utf-8", errors="replace"), args.exit_code)
    args.out.write_text(json.dumps(doc, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
