import unittest

from recon.models import EndpointCandidate, ReconInventory, canonicalize_endpoint


class ReconModelTests(unittest.TestCase):
    def test_canonicalizes_ids_and_query_values(self):
        value = canonicalize_endpoint(
            "/api/users/12345/550e8400-e29b-41d4-a716-446655440000?tenantId=9988&page=2"
        )
        self.assertEqual(
            value,
            "/api/users/{int}/{id}?page={int}&tenantId={int}",
        )

    def test_inventory_preserves_provenance(self):
        inventory = ReconInventory(role="admin")
        network = EndpointCandidate.build(
            method="GET", raw_url="https://app.example/api/users/42",
            source="network", evidence="observed", role="admin", observed=True,
        )
        static = EndpointCandidate.build(
            method="GET", raw_url="https://app.example/api/users/42",
            source="js_bundle", evidence="bundle", role="admin",
        )
        inventory.add(network)
        inventory.add(static)
        self.assertEqual(len(inventory.candidates), 2)
        self.assertEqual(inventory.coverage()["by_source"], {"js_bundle": 1, "network": 1})


if __name__ == "__main__":
    unittest.main()
