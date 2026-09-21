# Normalized Trace Differential

`compare.py` compares two CDR JSONL traces after schema validation.

By default it compares:

- `control-intent`
- `ble-read`
- `ble-write`
- `ble-notification`

Canonicalization is intentionally conservative:

- top-level `ts` and `provenance` are ignored;
- UUID and hex-value casing is normalized;
- every other field is preserved;
- event order is preserved.

No similarity threshold or heuristic equivalence can turn an unexplained difference into a match.

## Example

```sh
python harness/diff/compare.py official.jsonl oracle.jsonl \
  --output differential.json
```

For the narrowest JOYHUB local-command comparison:

```sh
python harness/diff/compare.py official.jsonl oracle.jsonl \
  --kinds ble-write \
  --require-equal
```

Exit status is zero unless `--require-equal` is supplied and semantic deltas remain.
