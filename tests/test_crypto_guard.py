"""Hermetic tests for Crypto Authentication and Session Token Auditor."""

import base64
import hashlib
import hmac
import json
import time
import unittest
from sentinel_shield.core.crypto_guard import audit_session_token_security


def create_mock_token(payload: dict, secret: str) -> str:
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode("ascii").rstrip("=")
    sig = hmac.new(secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
    return f"{payload_b64}.{sig_b64}"


class TestCryptoGuard(unittest.TestCase):
    """Test suite for cryptographic session token auditing."""

    def setUp(self):
        self.secret = "super_secure_server_secret_key_12345"

    def test_valid_token_passes(self):
        """Validly signed, unexpired token with sub claim must pass with 0 findings."""
        token = create_mock_token(
            {"sub": "0x2821d6003ceE245C4997Ff908029aa0116177b69", "exp": int(time.time()) + 3600, "iat": int(time.time())},
            self.secret,
        )
        result = audit_session_token_security(token, self.secret)
        self.assertTrue(result.passed)
        self.assertEqual(result.findings_count, 0)

    def test_tampered_signature_detected(self):
        """Tampered token signature must trigger CRITICAL CWE-347 finding."""
        token = create_mock_token(
            {"sub": "0x2821d6003ceE245C4997Ff908029aa0116177b69", "exp": int(time.time()) + 3600},
            self.secret,
        )
        corrupted = token[:-3] + "xyz"
        result = audit_session_token_security(corrupted, self.secret)
        self.assertFalse(result.passed)
        cwe_347 = [f for f in result.findings if f.cwe_id == "CWE-347"]
        self.assertEqual(len(cwe_347), 1)

    def test_expired_token_detected(self):
        """Expired session token must trigger HIGH CWE-613 finding."""
        token = create_mock_token(
            {"sub": "0x2821d6003ceE245C4997Ff908029aa0116177b69", "exp": int(time.time()) - 100},
            self.secret,
        )
        result = audit_session_token_security(token, self.secret)
        self.assertFalse(result.passed)
        cwe_613 = [f for f in result.findings if f.cwe_id == "CWE-613"]
        self.assertEqual(len(cwe_613), 1)

    def test_missing_expiration_detected(self):
        """Token lacking exp claim must trigger CWE-613 permanent replay finding."""
        token = create_mock_token(
            {"sub": "0x2821d6003ceE245C4997Ff908029aa0116177b69"},
            self.secret,
        )
        result = audit_session_token_security(token, self.secret)
        self.assertFalse(result.passed)
        self.assertTrue(any(f.cwe_id == "CWE-613" for f in result.findings))


if __name__ == "__main__":
    unittest.main()
