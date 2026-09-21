# BLE Census Harness

`census.py` performs the minimum non-mutating census needed by Connected Device Recovery:

1. scan BLE advertisements;
2. optionally select one exact device;
3. connect without pairing;
4. enumerate services and characteristic metadata;
5. disconnect;
6. emit normalized JSONL trace events.

It contains **no characteristic read/write, notification subscription, pairing, actuator, or firmware path**.

## Install

```sh
python -m pip install "bleak>=3.0,<4"
```

## Scan only

```sh
python harness/ble/census.py \
  --scan-seconds 8 \
  --specimen specimen-001 \
  --experiment EXP-JH-001 \
  --output census.jsonl
```

Review the advertisement trace and then rerun with exactly one target selector.

## Enumerate an exact target

```sh
python harness/ble/census.py \
  --target-name J-MowgliII \
  --specimen specimen-002 \
  --experiment EXP-JH-002 \
  --output mowgli-census.jsonl
```

Use `--target-address` instead when multiple devices advertise the same name. On macOS the identifier shown by CoreBluetooth is platform-specific rather than a hardware MAC address.

`--passive` requests passive scanning where Bleak supports it; macOS/CoreBluetooth does not support passive mode. Active advertisement scanning may therefore be required there, but the harness still performs no GATT reads or writes.

The output shape follows `schemas/trace.schema.json`.
