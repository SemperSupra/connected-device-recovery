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


if __name__ == "__main__":
    unittest.main()
