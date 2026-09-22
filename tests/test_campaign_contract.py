from __future__ import annotations

import pathlib
import subprocess
import sys
import unittest


class CampaignContractTest(unittest.TestCase):
    def test_valid_fixture(self):
        cp = subprocess.run(
            [
                sys.executable,
                "tools/validate_campaign_state.py",
                "--campaign-root", "fixtures/campaign-contract/campaigns",
                "--workset-root", "fixtures/campaign-contract/worksets",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("campaign-state-validation=PASS", cp.stdout)


if __name__ == "__main__":
    unittest.main()
