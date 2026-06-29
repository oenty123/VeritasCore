"""Tests for secrets_scan.py — precision over recall (Principle Zero)."""
import unittest
import veritas_secrets as ss


class KnownFormats(unittest.TestCase):
    def _types(self, text):
        return {f["type"] for f in ss.scan_text(text)}

    def test_aws_access_key(self):
        self.assertIn("AWS Access Key ID",
                      self._types("key = 'AKIA3MN7PQR2STU9VWX1'"))

    def test_github_token(self):
        self.assertIn("GitHub token",
                      self._types("t = 'ghp_" + "a1B2c3D4e5F6g7H8i9J0kL1mN2oP3qR4sT5u" + "'"))

    def test_google_api_key(self):
        self.assertIn("Google API key",
                      self._types("k = 'AIza" + "SyD3mN7pQr2StU9vWx1YzAbCdEf4GhIjKlM" + "'"))

    def test_private_key_block(self):
        self.assertIn("Private key block",
                      self._types("-----BEGIN RSA PRIVATE KEY-----"))

    def test_jwt(self):
        jwt = "eyJ" + "hbGciOiJIUzI1" + ".eyJ" + "zdWIiOiIxMjM0" + "." + "SflKxwRJSMeKKF2"
        self.assertIn("JWT", self._types(f"auth = '{jwt}'"))


class HardcodedAssignments(unittest.TestCase):
    def _findings(self, text):
        return ss.scan_text(text)

    def test_real_password_flagged(self):
        f = self._findings("password = 'Tr0ub4dor&3xpl0it'")
        self.assertTrue(any("hardcoded password" in x["type"] for x in f))

    def test_api_key_assignment_flagged(self):
        f = self._findings("api_key = 'sk9f8a7s6d5f4g3h2j1k0l9p8o7i6u5y'")
        self.assertTrue(f)


class NoFalsePositives(unittest.TestCase):
    """The whole point: do not cry wolf on placeholders / examples / templates."""

    def _has(self, text):
        return bool(ss.scan_text(text))

    def test_placeholder_your_key(self):
        self.assertFalse(self._has("api_key = 'your_api_key_here'"))

    def test_placeholder_xxx(self):
        self.assertFalse(self._has("password = 'xxxxxxxx'"))

    def test_env_var_template(self):
        self.assertFalse(self._has("token = '${GITHUB_TOKEN}'"))

    def test_example_value(self):
        self.assertFalse(self._has("secret = 'example'"))

    def test_format_placeholder(self):
        self.assertFalse(self._has("password = '%(db_pass)s'"))

    def test_jinja_placeholder(self):
        self.assertFalse(self._has("token = '{{ secret_token }}'"))

    def test_changeme(self):
        self.assertFalse(self._has("password = 'changeme'"))


class Masking(unittest.TestCase):
    def test_secret_is_masked_in_output(self):
        # the full secret must never appear verbatim in our findings
        secret = "AKIA3MN7PQR2STU9VWX1"
        f = ss.scan_text(f"k = '{secret}'")
        self.assertTrue(f)
        self.assertNotIn(secret, f[0]["preview"])


class NoiseReduction(unittest.TestCase):
    """Documented examples, synthetic values, and test fixtures are not noise."""

    def test_aws_documented_example_skipped(self):
        self.assertFalse(ss.scan_text("k = 'AKIAIOSFODNN7EXAMPLE'"))

    def test_repeated_char_token_skipped(self):
        self.assertFalse(ss.scan_text("t = 'ghp_" + "a" * 36 + "'"))

    def test_test_file_findings_demoted(self):
        # a real-looking key in a test file is reported but demoted to low
        f = ss.scan_text("k = 'AKIA3MN7PQR2STU9VWX1'", "tests/test_x.py")
        self.assertTrue(f)
        self.assertEqual(f[0]["confidence"], "low")
        self.assertIn("fixture", f[0]["type"])

    def test_non_test_file_stays_high(self):
        f = ss.scan_text("k = 'AKIA3MN7PQR2STU9VWX1'", "app/config.py")
        self.assertTrue(f)
        self.assertEqual(f[0]["confidence"], "high")

class ReDoSResilience(unittest.TestCase):
    def test_pathological_input_is_fast(self):
        import time
        evil = "AKIA" + "A" * 100000 + "'" * 50000
        t = time.time()
        ss.scan_text("k='" + evil + "'")
        self.assertLess(time.time() - t, 1.0)   # no catastrophic backtracking

    def test_huge_line_skipped(self):
        # a 4097+ char line is skipped (bounds regex work), shorter is scanned
        self.assertFalse(ss.scan_text("x = '" + "A" * 5000 + "'"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
