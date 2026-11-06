import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.characterize_windows_msix import characterize


MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Identity Name="OpenAI.Codex" Publisher="CN=Example" Version="1.2.3.4" ProcessorArchitecture="x64"/>
  <Properties><DisplayName>ChatGPT</DisplayName><PublisherDisplayName>OpenAI</PublisherDisplayName></Properties>
  <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" MaxVersionTested="10.0.26100.0"/></Dependencies>
  <Capabilities><Capability Name="internetClient"/></Capabilities>
  <Applications>
    <Application Id="App" Executable="app\\ChatGPT.exe" EntryPoint="Windows.FullTrustApplication">
      <Extensions><uap:Extension Category="windows.protocol"><uap:Protocol Name="chatgpt"/></uap:Extension></Extensions>
    </Application>
  </Applications>
</Package>
"""


class CharacterizeWindowsMsixTests(unittest.TestCase):
    def test_minimal_msix(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.msix"
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("AppxManifest.xml", MANIFEST)
                zf.writestr("app/ChatGPT.exe", b"MZtest")
                zf.writestr("app/resources.pak", b"pak")
                zf.writestr("app/resources/app.asar", b"asar-payload")
                zf.writestr("app/resources/app.asar.unpacked/node_modules/@scope/native/native.node", b"native")
                zf.writestr("app/resources/plugins/openai-bundled/plugins/chrome/plugin.json", b"{}")
                zf.writestr("AppxSignature.p7x", b"signature")

            result = characterize(path, "https://example.invalid/sample.msix", "x64")
            self.assertEqual(result["schema"], "cdr-derived-windows-msix-surface/v2")
            self.assertEqual(result["package"]["identity"]["Name"], "OpenAI.Codex")
            self.assertEqual(result["package"]["properties"]["DisplayName"], "ChatGPT")
            self.assertEqual(result["files"]["executable_count"], 1)
            self.assertTrue(result["files"]["selected_markers"]["chatgpt_executable"])
            self.assertTrue(result["files"]["selected_markers"]["chromium_or_electron"])
            self.assertTrue(result["package"]["signature"]["present"])
            self.assertEqual(len(result["package"]["sha256"]), 64)
            self.assertEqual(len(result["runtime_topology"]["asar_archives"]), 1)
            self.assertIn("@scope/native", result["runtime_topology"]["asar_unpacked_node_modules"])
            self.assertIn("chrome", result["runtime_topology"]["bundled_plugin_ids"])


class MsixAdversarialArchiveTests(unittest.TestCase):
    def test_malformed_names_and_duplicate_members_fail_closed(self):
        cases = [
            ["app/../escape.txt"],
            ["/absolute.txt"],
            ["C:/drive.txt"],
            ["app\\\\backslash.txt"],
            ["folder//double.txt"],
            ["folder/./dot.txt"],
            ["AppxManifest.xml"],
            ["data.txt", "DATA.TXT"],
        ]
        for extras in cases:
            with self.subTest(extras=extras), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "bad.msix"
                with zipfile.ZipFile(path, "w") as zf:
                    zf.writestr("AppxManifest.xml", MANIFEST)
                    for extra in extras:
                        zf.writestr(extra, b"x")
                with self.assertRaises(ValueError):
                    characterize(path, "https://example.invalid/synthetic.msix", "x64")

    def test_oversize_manifest_header_is_rejected_before_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oversize.msix"
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("AppxManifest.xml", b"x" * (4 * 1024 * 1024 + 1))
            with self.assertRaisesRegex(ValueError, "manifest exceeds"):
                characterize(path, "https://example.invalid/synthetic.msix", "x64")

    def test_architecture_hint_does_not_override_observed_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "arch.msix"
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("AppxManifest.xml", MANIFEST)
            r = characterize(path, "https://example.invalid/synthetic.msix", "arm64")
            self.assertEqual(r["package"]["architecture_verdict"], "MISMATCH")
            self.assertEqual(r["source"]["source_class"], "CALLER_SUPPLIED_URL_NOT_PROVEN_BY_PARSER")
            self.assertEqual(r["package"]["signature"]["verification"], "not-performed-by-linux-static-rep")


if __name__ == "__main__":
    unittest.main()
