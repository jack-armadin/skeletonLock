import unittest

from recon.redaction import build_redacted_http_message, redact_headers, redact_structure, redact_text, redact_url


class RedactionTests(unittest.TestCase):
    def test_redacts_sensitive_headers_and_query_values(self):
        headers = redact_headers({
            "Authorization": "Bearer abc.def.ghi",
            "Cookie": "sid=secret",
            "Accept": "application/json",
        })
        self.assertEqual(headers["Authorization"], "[REDACTED]")
        self.assertEqual(headers["Cookie"], "[REDACTED]")
        self.assertEqual(headers["Accept"], "application/json")
        clean_url = redact_url("https://app.example/callback?code=secret&page=2")
        self.assertIn("code=%5BREDACTED%5D", clean_url)
        self.assertIn("page=2", clean_url)

    def test_http_message_does_not_persist_cookie(self):
        message = build_redacted_http_message(
            "GET /api/users HTTP/1.1",
            {"Cookie": "session=super-secret", "Accept": "application/json"},
        ).decode()
        self.assertNotIn("super-secret", message)
        self.assertIn("Cookie: [REDACTED]", message)

    def test_redacts_inline_html_or_form_secrets(self):
        clean = redact_text('<input name="SAMLResponse" value="very-secret-value"> access_token=abc12345')
        self.assertNotIn("very-secret-value", clean)
        self.assertNotIn("abc12345", clean)

    def test_structure_keeps_coverage_keys_but_redacts_urls(self):
        clean = redact_structure({
            "state_transitions": [{"from_url": "https://app.example/callback?code=secret"}],
        })
        self.assertIn("state_transitions", clean)
        self.assertNotIn("secret", clean["state_transitions"][0]["from_url"])


if __name__ == "__main__":
    unittest.main()
