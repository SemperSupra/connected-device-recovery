"""Ensure package characterization never runs an extracted donor executable.

The regression fixture deliberately creates an executable named codex and a
stub ldd that leave sentinel files if invoked. Running the Python scanner is
permitted; running the bundled donor or ldd on untrusted modules is not.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "characterize_desktop_bundle.py"


class StaticDonorCensusTests(unittest.TestCase):
    def test_no_donor_execution_or_ldd(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            donor = root / "donor"
            output = root / "out"
            fakebin = root / "bin"
            fakebin.mkdir()
            codex = donor / "resources" / "codex"
            codex.parent.mkdir(parents=True)
            donor_sentinel = root / "donor-executed"
            codex.write_text(f"#!/bin/sh\ntouch '{donor_sentinel}'\n", encoding="utf-8")
            codex.chmod(0o755)
            native = donor / "resources" / "native" / "synthetic.node"
            native.parent.mkdir(parents=True)
            native.write_text(f"#!/bin/sh\ntouch '{donor_sentinel}'\n", encoding="utf-8")
            native.chmod(0o755)
            ldd_sentinel = root / "ldd-invoked"
            stub = fakebin / "ldd"
            stub.write_text(f"#!/bin/sh\ntouch '{ldd_sentinel}'\n", encoding="utf-8")
            stub.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = str(fakebin) + os.pathsep + env.get("PATH", "")
            subprocess.run(
                [sys.executable, str(SCRIPT), str(donor), str(output),
                 "--platform", "linux", "--label", "source-owned-negative"],
                check=True, timeout=20, env=env, capture_output=True, text=True,
            )
            self.assertFalse(donor_sentinel.exists(), "extracted donor ran")
            self.assertFalse(ldd_sentinel.exists(), "unsafe ldd executed")
            records = json.loads((output / "executables.json").read_text(encoding="utf-8"))
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["version_probe"], {"status": "NOT_EXECUTED_STATIC_ONLY"})


if __name__ == "__main__":
    unittest.main()
