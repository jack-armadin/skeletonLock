import json
import tempfile
import unittest
from pathlib import Path

from recon.importers import load_recon_import


class ImporterTests(unittest.TestCase):
    def test_imports_har_requests_with_body_schema(self):
        payload = {
            "log": {"entries": [{
                "request": {
                    "method": "POST",
                    "url": "https://app.example/api/users/search",
                    "postData": {"text": '{"page":1,"query":"alice"}'},
                },
                "response": {"status": 200, "content": {"mimeType": "application/json"}},
            }]}
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.har"
            path.write_text(json.dumps(payload))
            inventory = load_recon_import(str(path))
        self.assertEqual(len(inventory.candidates), 1)
        item = inventory.candidates[0]
        self.assertEqual(item.method, "POST")
        self.assertEqual(item.request_body_schema, {"page": "integer", "query": "string"})
        self.assertTrue(item.observed)


if __name__ == "__main__":
    unittest.main()
