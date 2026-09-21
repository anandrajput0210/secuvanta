import unittest

from core.detectors import detect_secrets, mask_secret


class TestDetectors(unittest.TestCase):

    def test_aws_key_detection(self):

        text = "AWS_KEY = AKIAIOSFODNN7EXAMPLE"

        findings = detect_secrets(text, "config.py")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_type, "AWS Access Key")
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_jwt_detection(self):

        text = (
            "token = "
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJ1c2VyIjoiYWRtaW4ifQ."
            "signature123456"
        )

        findings = detect_secrets(text, "auth.py")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_type, "JWT Token")

    def test_private_key_detection(self):

        text = "-----BEGIN PRIVATE KEY-----"

        findings = detect_secrets(text, "private.pem")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_variable_name_password_detection(self):

        text = 'API_PASSWORD = "supersecret123"'

        findings = detect_secrets(text, "config.py")

        self.assertEqual(len(findings), 1)
        self.assertEqual(
        findings[0].finding_type,
        "Hardcoded Password"
    )
    def test_high_entropy_credential_detection(self):

        text = (
        'API_TOKEN = '
        '"aK9xP2mQr7VzN4wYt8LbF3cHs6Dj1GeR"'
    )

        findings = detect_secrets(
        text,
        "config.py"
    )

        entropy_findings = [
        finding
        for finding in findings
        if finding.finding_type == "High-Entropy Secret"
    ]

        self.assertEqual(
        len(entropy_findings),
        1
    )

        self.assertEqual(
        entropy_findings[0].severity,
        "MEDIUM"
    )
    def test_normal_value_is_not_high_entropy_secret(self):

        text = 'API_TOKEN = "this-is-a-simple-test-token"'

        findings = detect_secrets(
        text,
        "config.py"
    )

        entropy_findings = [
        finding
        for finding in findings
        if finding.finding_type == "High-Entropy Secret"
    ]

        self.assertEqual(
        len(entropy_findings),
        0
    )

    def test_password_detection(self):

        text = 'password = "supersecret123"'

        findings = detect_secrets(text, "settings.py")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_type, "Hardcoded Password")

    def test_mask_secret(self):

        secret = "abcdefghijklmnop"

        masked = mask_secret(secret)

        self.assertEqual(masked, "abcd********mnop")


if __name__ == "__main__":
    unittest.main()