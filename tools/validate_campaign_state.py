#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import sys

import jsonschema
import yaml


def load(path: pathlib.Path):
    with path.open("r", encoding="utf-8") as fh:
        if path.suffix == ".json":
            return json.load(fh)
        return yaml.safe_load(fh)


def validate_documents(campaign_root: pathlib.Path, workset_root: pathlib.Path,
                       campaign_schema: pathlib.Path, workset_schema: pathlib.Path) -> list[str]:
    errors: list[str] = []
    cs = load(campaign_schema)
    ws = load(workset_schema)

    campaigns: dict[str, pathlib.Path] = {}
    for path in sorted(campaign_root.glob("*/campaign.yaml")):
        try:
            doc = load(path)
            jsonschema.validate(doc, cs)
            cid = doc["id"]
            if cid in campaigns:
                errors.append(f"duplicate campaign id {cid}: {campaigns[cid]} and {path}")
            else:
                campaigns[cid] = path
        except Exception as exc:
            errors.append(f"{path}: {exc}")

    if not campaigns:
        errors.append(f"no campaign manifests found under {campaign_root}")

    for path in sorted([*workset_root.glob("*.yaml"), *workset_root.glob("*.yml")]):
        try:
            doc = load(path)
            jsonschema.validate(doc, ws)
            campaign = doc["campaign"]
            if campaign not in campaigns:
                errors.append(f"{path}: unknown campaign {campaign!r}")

            ids = [item["id"] for item in doc["work"]]
            if len(ids) != len(set(ids)):
                errors.append(f"{path}: duplicate work item id")
            known = set(ids)
            for item in doc["work"]:
                for dep in item.get("blocked_by", []) or []:
                    if dep not in known:
                        errors.append(f"{path}: {item['id']} blocked_by unknown item {dep}")
        except Exception as exc:
            errors.append(f"{path}: {exc}")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaign-root", required=True)
    ap.add_argument("--workset-root", required=True)
    ap.add_argument("--campaign-schema", default="schemas/campaign.schema.json")
    ap.add_argument("--workset-schema", default="schemas/workset.schema.json")
    args = ap.parse_args()

    errors = validate_documents(
        pathlib.Path(args.campaign_root),
        pathlib.Path(args.workset_root),
        pathlib.Path(args.campaign_schema),
        pathlib.Path(args.workset_schema),
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("campaign-state-validation=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
