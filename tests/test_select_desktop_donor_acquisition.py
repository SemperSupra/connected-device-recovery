"""Hostile zero-donor synchronization admission and GITHUB_OUTPUT controls."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.select_desktop_donor_acquisition import select,main

SYNC={"action":"synchronize","before":"a"*40,"after":"b"*40}

class DesktopAdmissionTests(unittest.TestCase):
    def test_manual_and_initial_run_full(self):
        for profile in ("linux","macos"):
            self.assertTrue(select("workflow_dispatch",{},profile)[0])
            self.assertTrue(select("pull_request",{"action":"opened"},profile)[0])
            self.assertTrue(select("pull_request",{"action":"ready_for_review"},profile)[0])

    def test_docs_and_test_only_changes_skip_original(self):
        for profile in ("linux","macos"):
            for path in ("docs/README.md","tests/test_characterize_desktop_noexec.py",
                         "tools/select_desktop_donor_acquisition.py",
                         "tests/test_select_desktop_donor_acquisition.py"):
                with self.subTest(profile=profile,path=path),patch(
                    "tools.select_desktop_donor_acquisition.subprocess.run",
                    return_value=subprocess.CompletedProcess([],0,path+"\n","")
                ):
                    self.assertEqual(select("pull_request",SYNC,profile),
                                     (False,"SOURCE_ONLY_CHANGE_SKIP_ORIGINAL_DONOR"))

    def test_package_or_producer_changes_run(self):
        paths={"linux":["tools/characterize_desktop_bundle.py",
                        "tools/qualify_rpm_signature.py",".github/workflows/chatgpt-linux-oracle.yml"],
               "macos":["tools/characterize_desktop_bundle.py",
                        "tools/select_static_macho_codex.py",".github/workflows/chatgpt-macos-oracle.yml"]}
        for profile,names in paths.items():
            for path in names:
                with self.subTest(profile=profile,path=path),patch(
                    "tools.select_desktop_donor_acquisition.subprocess.run",
                    return_value=subprocess.CompletedProcess([],0,path+"\n","")
                ):
                    self.assertEqual(select("pull_request",SYNC,profile),
                                     (True,"ORIGINAL_DONOR_PRODUCER_CHANGED"))

    def test_git_failure_or_missing_heads_fail_open(self):
        self.assertTrue(select("pull_request",{"action":"synchronize"},"linux")[0])
        self.assertTrue(select("pull_request",SYNC,"unknown")[0])
        with patch("tools.select_desktop_donor_acquisition.subprocess.run",
                   side_effect=subprocess.CalledProcessError(128,["git","diff"])):
            self.assertEqual(select("pull_request",SYNC,"macos"),
                             (True,"UNVERIFIABLE_DIFF_RUN_CONSERVATIVELY"))

    def test_provider_output_is_two_line_boolean_contract(self):
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td);event=folder/"event.json";out=folder/"gha.out"
            event.write_text(json.dumps(SYNC))
            with patch.dict("os.environ",{"GITHUB_EVENT_NAME":"pull_request",
                    "GITHUB_EVENT_PATH":str(event),"DONOR_PROFILE":"linux",
                    "GITHUB_OUTPUT":str(out)}),patch(
                    "tools.select_desktop_donor_acquisition.subprocess.run",
                    return_value=subprocess.CompletedProcess([],0,"docs/only.md\n","")):
                self.assertEqual(main(),0)
            self.assertEqual(out.read_text().splitlines(),[
                "acquire=false","reason=SOURCE_ONLY_CHANGE_SKIP_ORIGINAL_DONOR"])

if __name__=="__main__":
    unittest.main()
