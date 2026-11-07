"""Offline negative controls for untrusted RPM signature evidence."""
import unittest
from tools.qualify_rpm_signature import qualify


class RPMVerifierControls(unittest.TestCase):
    def verify(self, raw, rc, status):
        d = qualify(raw, rc)
        self.assertEqual(d["status"], status)
        self.assertFalse(d["original_package_signature_accepted"])
        self.assertFalse(d["official_publisher_key_attested"])
        self.assertNotIn("NOKEY", str(d))

    def test_rpm_actual_nokey_even_on_zero(self):
        self.verify("/tmp/chatgpt.x86_64.rpm: Header V4 RSA/SHA512 Signature, key ID 6c4660e4: NOKEY", 0, "RPM_SIGNATURE_KEY_UNAVAILABLE")

    def test_bad_signature_overrides_nokey(self):
        self.verify("Header RSA Signature: NOKEY; payload digest: BAD", 1, "RPM_SIGNATURE_BAD_OR_UNTRUSTED")

    def test_nottrusted(self):
        self.verify("Header RSA Signature: NOTTRUSTED", 1, "RPM_SIGNATURE_BAD_OR_UNTRUSTED")

    def test_nonzero_without_trust_signal(self):
        self.verify("rpm command could not load package", 2, "RPM_VERIFIER_RETURNED_NONZERO")

    def test_empty_success_is_not_verified(self):
        self.verify("", 0, "RPM_SIGNATURE_EVIDENCE_MISSING")

    def test_digest_not_signature(self):
        self.verify("Header SHA256 digest: OK", 0, "RPM_DIGEST_OK_SIGNATURE_UNVERIFIED")

    def test_crypto_ok_still_not_owner_key_trust(self):
        self.verify("Header V4 RSA/SHA512 Signature, key ID 6c4660e4: OK", 0, "RPM_SIGNATURE_CHECK_OK_OWNER_KEY_UNATTESTED")

    def test_verifier_rc_is_higher_priority_than_ok(self):
        self.verify("Header RSA Signature: OK\nerror: cannot parse payload", 4, "RPM_VERIFIER_RETURNED_NONZERO")

    def test_invalid_rc(self):
        with self.assertRaises(ValueError):
            qualify("NOKEY", -1)
        with self.assertRaises(ValueError):
            qualify("NOKEY", True)


if __name__ == "__main__":
    unittest.main()
