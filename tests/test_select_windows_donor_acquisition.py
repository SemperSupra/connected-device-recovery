import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.select_windows_donor_acquisition import needs_acquisition, select, main


EVENT = {"action": "synchronize", "before": "a" * 40, "after": "b" * 40}


class SourceOnlyAcquisitionSelectorTests(unittest.TestCase):
    def test_initial_or_manual_events_always_run(self):
        self.assertEqual(select("workflow_dispatch", {})[0], True)
        self.assertEqual(select("pull_request", {"action": "opened"})[0], True)

    def test_cumulative_pr_diff_does_not_force_download(self):
        with patch("tools.select_windows_donor_acquisition.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 0, "tools/characterize_windows_msix.py\n", "")):
            allowed, reason = select("pull_request", EVENT)
        self.assertFalse(allowed)
        self.assertEqual(reason, "SOURCE_ONLY_CHANGE_SKIP_ACQUISITION")

    def test_exact_acquisition_tool_change_admitted(self):
        with patch("tools.select_windows_donor_acquisition.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 0, "tools/characterize_asar_header.cjs\n", "")):
            self.assertTrue(select("pull_request", EVENT)[0])

    def test_workflow_change_admitted(self):
        self.assertTrue(needs_acquisition(EVENT, [".github/workflows/chatgpt-windows-oracle.yml"]))
        self.assertFalse(needs_acquisition(EVENT, ["tests/test_characterize_windows_msix.py"]))
        self.assertTrue(needs_acquisition(EVENT, None))

    def test_missing_or_malformed_ancestry_fails_open_to_run(self):
        for evt in ({"action": "synchronize"}, {"action": "synchronize", "before": "not-sha", "after": "b" * 40}):
            with self.subTest(evt=evt):
                allowed, reason = select("pull_request", evt)
                self.assertTrue(allowed)
                self.assertEqual(reason, "UNVERIFIABLE_ANCESTRY_RUN_CONSERVATIVELY")

    def test_failed_git_comparison_fails_open_to_run(self):
        with patch("tools.select_windows_donor_acquisition.subprocess.run",
                   side_effect=subprocess.CalledProcessError(128, ["git", "diff"])):
            allowed, reason = select("pull_request", EVENT)
        self.assertTrue(allowed)
        self.assertEqual(reason, "UNVERIFIABLE_DIFF_RUN_CONSERVATIVELY")

    def test_bounded_output_is_newline_delimited(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            event_path = root / "event.json"
            out = root / "output.txt"
            event_path.write_text(json.dumps(EVENT))
            with patch.dict("os.environ", {
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_EVENT_PATH": str(event_path),
                "GITHUB_OUTPUT": str(out),
            }), patch("tools.select_windows_donor_acquisition.subprocess.run",
                      return_value=subprocess.CompletedProcess([], 0, "tests/only.py\n", "")):
                self.assertEqual(main(), 0)
            self.assertEqual(out.read_text().splitlines(), [
                "acquire=false", "reason=SOURCE_ONLY_CHANGE_SKIP_ACQUISITION"
            ])


if __name__ == "__main__":
    unittest.main()
