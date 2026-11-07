"""No browser credentials, synthetic public-host and leakage counterexamples."""
import unittest
from tools.chatgpt_webui_guest_safety import (
    allowed_asset_url, error_kind, MAX_ASSETS, MAX_ASSET_BYTES,
)


class GuestSensorControls(unittest.TestCase):
    def test_first_party_https_assets_only(self):
        for url in ("https://chatgpt.com/assets/a.js",
                    "https://cdn.oaistatic.com/c/one.js",
                    "https://foo.chatgpt.com/style.css"):
            with self.subTest(url=url):self.assertTrue(allowed_asset_url(url))
        for url in ("http://chatgpt.com/asset.js", "https://evilchatgpt.com/a",
                    "https://fakeoaistatic.com/x", "https://chatgpt.com.evil.net/a",
                    "https://user:secret@chatgpt.com/a", "https://chatgpt.com:8443/x",
                    "https://127.0.0.1/x", "file:///etc/passwd", "//chatgpt.com/x"):
            with self.subTest(url=url):self.assertFalse(allowed_asset_url(url))

    def test_bad_ports_and_long_urls_are_rejected(self):
        self.assertFalse(allowed_asset_url("https://chatgpt.com:badport/x"))
        self.assertFalse(allowed_asset_url("https://chatgpt.com/" + "a"*5000))

    def test_error_details_are_never_emitted(self):
        exc=ValueError("secret token abc from upstream login redirect")
        self.assertEqual(error_kind(exc), "ValueError")
        self.assertNotIn("secret", error_kind(exc).lower())

    def test_bounded_free_ci_budget(self):
        self.assertGreater(MAX_ASSETS,0)
        self.assertLessEqual(MAX_ASSETS,32)
        self.assertLessEqual(MAX_ASSET_BYTES,1_000_000)


if __name__ == "__main__":
    unittest.main()
