#!/usr/bin/env python3
"""Canonical differential comparator for CDR normalized JSONL traces."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Iterable

DEFAULT_KINDS = (
    "control-intent",
    "ble-read",
    "ble-write",
    "ble-notification",
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{number}: invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{number}: trace event must be a JSON object")
        events.append(value)
    return events


def validate_events(
    events: Iterable[dict[str, Any]],
    schema: dict[str, Any],
    *,
    source: str,
) -> None:
    import jsonschema

    validator = jsonschema.Draft202012Validator(schema)
    for index, event in enumerate(events, 1):
        errors = sorted(validator.iter_errors(event), key=lambda e: list(e.path))
        if errors:
            err = errors[0]
            location = ".".join(str(x) for x in err.path) or "<root>"
            raise ValueError(
                f"{source}:{index}: schema error at {location}: {err.message}"
            )


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _normalize(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return [_normalize(x) for x in value]
    return value


def canonical_event(event: dict[str, Any]) -> dict[str, Any]:
    """Remove only declared non-semantic noise; preserve all other fields."""

    keep = {
        key: value
        for key, value in event.items()
        if key not in {"ts", "provenance"}
    }
    for key in ("service", "characteristic", "value_hex"):
        value = keep.get(key)
        if isinstance(value, str):
            keep[key] = value.lower()
    return _normalize(keep)


def select_events(
    events: Iterable[dict[str, Any]],
    kinds: set[str] | None,
) -> list[dict[str, Any]]:
    if kinds is None:
        return list(events)
    return [event for event in events if event.get("kind") in kinds]


def fingerprint(event: dict[str, Any]) -> str:
    return json.dumps(
        canonical_event(event),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compare(
    left: list[dict[str, Any]],
    right: list[dict[str, Any]],
    *,
    kinds: set[str] | None,
) -> dict[str, Any]:
    left_selected = select_events(left, kinds)
    right_selected = select_events(right, kinds)
    left_canon = [canonical_event(x) for x in left_selected]
    right_canon = [canonical_event(x) for x in right_selected]
    left_fp = [fingerprint(x) for x in left_selected]
    right_fp = [fingerprint(x) for x in right_selected]

    matcher = SequenceMatcher(a=left_fp, b=right_fp, autojunk=False)
    deltas = []
    equal_events = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            equal_events += i2 - i1
            continue
        deltas.append(
            {
                "op": tag,
                "left_range": [i1, i2],
                "right_range": [j1, j2],
                "left": left_canon[i1:i2],
                "right": right_canon[j1:j2],
            }
        )

    return {
        "equal": not deltas,
        "selected_kinds": sorted(kinds) if kinds is not None else "all",
        "left_event_count": len(left_selected),
        "right_event_count": len(right_selected),
        "equal_event_count": equal_events,
        "left_kind_counts": dict(sorted(Counter(
            str(x.get("kind")) for x in left_selected
        ).items())),
        "right_kind_counts": dict(sorted(Counter(
            str(x.get("kind")) for x in right_selected
        ).items())),
        "delta_count": len(deltas),
        "deltas": deltas,
        "canonicalization": {
            "ignored_top_level_fields": ["ts", "provenance"],
            "case_normalized_fields": ["service", "characteristic", "value_hex"],
            "other_fields_preserved": True,
        },
    }


def parse_kinds(value: str) -> set[str] | None:
    if value.strip().lower() == "all":
        return None
    kinds = {x.strip() for x in value.split(",") if x.strip()}
    if not kinds:
        raise argparse.ArgumentTypeError("kinds must be 'all' or a comma-separated list")
    return kinds


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Compare two normalized CDR JSONL traces without hiding semantic deltas."
    )
    p.add_argument("left", type=Path)
    p.add_argument("right", type=Path)
    p.add_argument(
        "--kinds",
        type=parse_kinds,
        default=set(DEFAULT_KINDS),
        help=(
            "comma-separated event kinds; default: "
            + ",".join(DEFAULT_KINDS)
            + "; use 'all' for all events"
        ),
    )
    p.add_argument(
        "--schema",
        type=Path,
        default=Path("schemas/trace.schema.json"),
        help="JSON schema used to validate both traces",
    )
    p.add_argument("--output", type=Path, help="write JSON report; stdout when omitted")
    p.add_argument(
        "--require-equal",
        action="store_true",
        help="exit 1 when semantic deltas are present",
    )
    return p


def main() -> int:
    args = parser().parse_args()
    left = load_jsonl(args.left)
    right = load_jsonl(args.right)
    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    validate_events(left, schema, source=str(args.left))
    validate_events(right, schema, source=str(args.right))
    report = compare(left, right, kinds=args.kinds)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 1 if args.require_equal and not report["equal"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
