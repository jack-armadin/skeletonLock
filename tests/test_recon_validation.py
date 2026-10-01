import unittest

from recon.models import EndpointCandidate, ReconInventory
from recon.validation import validate_safe_get_candidates


class FakeResponse:
    status = 200
    headers = {"content-type": "application/json"}


class FakeRequest:
    def __init__(self):
        self.urls = []

    async def fetch(self, url, **_kwargs):
        self.urls.append(url)
        return FakeResponse()


class ValidationTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_validates_read_like_opt_in_candidates(self):
        inventory = ReconInventory(role="admin")
        read = EndpointCandidate.build(
            method="GET", raw_url="https://app.example/api/users",
            source="js_bundle", evidence="bundle",
        )
        mutation = EndpointCandidate.build(
            method="GET", raw_url="https://app.example/api/users/delete/1",
            source="js_bundle", evidence="bundle",
        )
        inventory.extend([read, mutation])
        request = FakeRequest()
        count = await validate_safe_get_candidates(
            request, inventory, allowed_hosts={"app.example"},
        )
        self.assertEqual(count, 1)
        self.assertEqual(request.urls, ["https://app.example/api/users"])
        self.assertTrue(read.validated)
        self.assertFalse(mutation.validated)


if __name__ == "__main__":
    unittest.main()
