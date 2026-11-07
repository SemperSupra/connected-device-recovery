"""Independent synthetic Mach-O selector oracle: never execute original donors."""
import pathlib
import struct
import tempfile
import unittest

from tools.select_static_macho_codex import (
    CPU_ARM64, CPU_X86_64,
    read_macho_architecture, select_codex,
)


def macho(code: int):
    return bytes.fromhex("cffaedfe") + struct.pack("<I", code) + bytes(24)


class MachOCodexSelectorTests(unittest.TestCase):
    def test_native_selected_not_shell_launcher(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            wrapper = root / "codex-cli/bin/codex"
            native = root / "codex-cli/CodexCLI.app/Contents/MacOS/codex"
            wrapper.parent.mkdir(parents=True)
            native.parent.mkdir(parents=True)
            trap = root / "WRAPPER_EXECUTED"
            wrapper.write_text("#!/bin/sh\ntouch " + str(trap) + "\n")
            wrapper.chmod(0o755)
            native.write_bytes(macho(CPU_ARM64))
            native.chmod(0o755)
            result = select_codex(root)
            self.assertEqual(result["status"], "NATIVE_MACHO_CODEX_SELECTED")
            self.assertEqual(result["arch"], "arm64")
            self.assertEqual(result["selected_path"], str(native))
            self.assertFalse(trap.exists(), "source-known launcher must never run")

    def test_x64_thin_classification(self):
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "codex"
            path.write_bytes(macho(CPU_X86_64))
            self.assertEqual(read_macho_architecture(path), "x86_64")

    def test_universal_fat_classification(self):
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "codex"
            data = bytes.fromhex("cafebabe") + struct.pack(">I", 2)
            data += struct.pack(">I", CPU_ARM64) + bytes(16)
            data += struct.pack(">I", CPU_X86_64) + bytes(16)
            path.write_bytes(data)
            self.assertEqual(read_macho_architecture(path), "universal")

    def test_shell_only_abstains(self):
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "codex"
            path.write_text("#!/bin/sh\necho wrong candidate\n")
            result = select_codex(path.parent)
            self.assertEqual(result["status"], "NO_NATIVE_MACHO_CODEX")
            self.assertIsNone(result["selected_path"])

    def test_ambiguous_native_candidates_abstains(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            for d in ("a", "b"):
                parent = root / d
                parent.mkdir()
                (parent / "codex").write_bytes(macho(CPU_ARM64))
            result = select_codex(root)
            self.assertEqual(result["status"], "AMBIGUOUS_NATIVE_CODEX")
            self.assertIsNone(result["selected_path"])

    def test_malformed_or_truncated_macho_is_not_selected(self):
        for data in (b"", b"codex", bytes.fromhex("cafebabe") + struct.pack(">I", 99),
                     bytes.fromhex("cafebabe") + struct.pack(">I", 1) + bytes(4)):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as td:
                root=pathlib.Path(td);(root / "codex").write_bytes(data)
                self.assertIsNone(read_macho_architecture(root / "codex"))

    def test_missing_root_abstains(self):
        with tempfile.TemporaryDirectory() as td:
            r = select_codex(pathlib.Path(td) / "nonexistent")
            self.assertEqual(r["status"], "NO_RESOURCES_DIRECTORY")


if __name__ == "__main__":
    unittest.main()
