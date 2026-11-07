"""Synthetic guest DOM parser privacy and no-auth process controls."""
import json
from pathlib import Path
import stat
import tempfile
import unittest

from tools.chatgpt_guest_dom_sensor import observe, SafeDOMShape


class GuestDOMTests(unittest.TestCase):
    def test_allowlisted_structure_never_emits_private_content(self):
        html='<html><body><button aria-label="private key">do not log this</button>' \
             '<input type="password" value="secret-token">' \
             '<div role="dialog" data-secret="nope"></div>' \
             '<div role="malicious://token"></div></body></html>'
        parser=SafeDOMShape()
        parser.feed(html)
        data=json.dumps(parser.report())
        self.assertEqual(parser.tags["button"],1)
        self.assertEqual(parser.inputs["password"],1)
        self.assertEqual(parser.roles["dialog"],1)
        self.assertEqual(parser.unknown_roles,1)
        self.assertNotIn("secret",data)
        self.assertNotIn("private",data)
        self.assertNotIn("malicious",data)

    def test_missing_browser_abstains(self):
        with tempfile.TemporaryDirectory() as td:
            receipt=observe(Path(td)/"nonexistent",seconds=1)
            self.assertEqual(receipt["status"],"BROWSER_UNAVAILABLE")
            self.assertFalse(receipt["authenticated"])

    def test_synthetic_headless_client_emits_only_dom_shape(self):
        with tempfile.TemporaryDirectory() as td:
            temp=Path(td)
            chrome=temp/"fake-chrome"
            chrome.write_text(
              "#!/usr/bin/env python3\n"
              "print('<html><body><button aria-label=\"secret text\">private</button><input type=\"text\" value=\"token\" /></body></html>')\n")
            chrome.chmod(chrome.stat().st_mode | stat.S_IXUSR)
            result=observe(chrome,seconds=5)
            self.assertEqual(result["status"],"DOM_SHAPE_OBSERVED_NOT_AUTHENTICATED_APP")
            self.assertEqual(result["dom_shape"]["allowlisted_tag_counts"]["button"],1)
            body=json.dumps(result)
            self.assertNotIn("private",body)
            self.assertNotIn("secret",body)
            self.assertFalse(result["raw_dom_or_screenshot_published"])

    def test_timeout_bound(self):
        with self.assertRaisesRegex(ValueError,"invalid browser"):
            observe(seconds=0)


if __name__ == "__main__":
    unittest.main()
