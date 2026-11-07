#!/usr/bin/env python3
"""Select an original native Mach-O Codex executable without launching it.

macOS bundles also ship a shell launcher named 'codex' (~328 bytes); choosing
first find(1) match misclassifies launcher as bundled binary. This selector
inspects only fixed-size Mach-O header bytes and refuses ambiguous candidates.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import struct

CPU_X86_64 = 0x01000007
CPU_ARM64 = 0x0100000C
THIN_MAGICS = {
    bytes.fromhex("cffaedfe"): "<",  # little-endian 64-bit Mach-O
    bytes.fromhex("feedfacf"): ">",  # big-endian 64-bit Mach-O
    bytes.fromhex("cefaedfe"): "<",  # little-endian 32-bit Mach-O
    bytes.fromhex("feedface"): ">",  # big-endian 32-bit Mach-O
}
FAT_MAGICS = {
    bytes.fromhex("cafebabe"): (">", 20),
    bytes.fromhex("bebafeca"): ("<", 20),
    bytes.fromhex("cafebabf"): (">", 32),
    bytes.fromhex("bfbafeca"): ("<", 32),
}
MAX_CANDIDATES = 64
MAX_FAT_ARCHES = 16


def _arch(code: int) -> str:
    return {CPU_X86_64: "x86_64", CPU_ARM64: "arm64"}.get(code, "OTHER")


def read_macho_architecture(path: pathlib.Path) -> str | None:
    if path.is_symlink() or not path.is_file():
        return None
    with path.open("rb") as file:
        header = file.read(8)
        if len(header) != 8:
            return None
        if header[:4] in THIN_MAGICS:
            order = THIN_MAGICS[header[:4]]
            return _arch(struct.unpack(order + "I", header[4:8])[0])
        fat = FAT_MAGICS.get(header[:4])
        if fat is None:
            return None
        order, stride = fat
        count = struct.unpack(order + "I", header[4:8])[0]
        if not 1 <= count <= MAX_FAT_ARCHES:
            return None
        archs = set()
        for _ in range(count):
            entry = file.read(stride)
            if len(entry) != stride:
                return None
            archs.add(_arch(struct.unpack(order + "I", entry[:4])[0]))
        if archs == {"arm64", "x86_64"}:
            return "universal"
        return next(iter(archs)) if len(archs) == 1 else "mixed_other"


def select_codex(root: pathlib.Path) -> dict:
    if not root.is_dir():
        return {"status": "NO_RESOURCES_DIRECTORY", "selected_path": None, "arch": None, "native_candidates": 0}
    files = []
    for path in root.rglob("codex"):
        if path.is_symlink() or not path.is_file():
            continue
        files.append(path)
        if len(files) > MAX_CANDIDATES:
            return {"status": "CANDIDATE_LIMIT_EXCEEDED", "selected_path": None, "arch": None, "native_candidates": None}
    native = [(p, read_macho_architecture(p)) for p in files]
    native = [(p, a) for p, a in native if a in {"x86_64", "arm64", "universal"}]
    if not native:
        return {"status": "NO_NATIVE_MACHO_CODEX", "selected_path": None, "arch": None, "native_candidates": 0}
    if len(native) != 1:
        return {"status": "AMBIGUOUS_NATIVE_CODEX", "selected_path": None, "arch": None, "native_candidates": len(native)}
    path, architecture = native[0]
    return {"status": "NATIVE_MACHO_CODEX_SELECTED", "selected_path": str(path), "arch": architecture, "native_candidates": 1}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("resource_root", type=pathlib.Path)
    parser.add_argument("--receipt", required=True, type=pathlib.Path)
    args = parser.parse_args()
    result = select_codex(args.resource_root)
    public = {
        "schema": "cdr-macos-native-codex-selection/v1",
        "status": result["status"],
        "detected_architecture": result["arch"],
        "native_candidates": result["native_candidates"],
        "donor_executed": False,
        "claim_boundary": "Mach-O header-only static selection; no native/runtime/CLI version or public release identity qualification.",
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(public, indent=2, sort_keys=True) + chr(10), encoding="utf-8")
    if result["selected_path"]:
        print(result["selected_path"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
