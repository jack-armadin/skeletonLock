import unittest

from recon.javascript import (
    expand_and_analyze_assets,
    extract_endpoint_candidates,
    extract_webpack_chunks,
)
from recon.js_static_resolver import MAX_SOURCE_BYTES, resolve_static_endpoints


class FakeResponse:
    def __init__(self, body, status=200):
        self._body = body.encode()
        self.status = status
        self.ok = 200 <= status < 300

    async def body(self):
        return self._body


class FakeRequestContext:
    def __init__(self, responses):
        self.responses = responses
        self.requested = []

    async def get(self, url, **_kwargs):
        self.requested.append(url)
        if url not in self.responses:
            return FakeResponse("", 404)
        return FakeResponse(self.responses[url])

    async def fetch(self, url, **_kwargs):
        return await self.get(url)


class JavaScriptReconTests(unittest.TestCase):
    def test_extracts_methods_and_string_candidates(self):
        source = """
            svc.http.get('/api/Person/GetAllUsers');
            fetch('/api/Person/GetExternalUsers', {method: 'GET'});
            const hidden = '/api/Questionnaire/GetMigerateQuaterlyInfoMaster';
        """
        items = extract_endpoint_candidates(source, "https://app.example/main.js")
        paths = {(item.method, item.canonical_path) for item in items}
        self.assertIn(("GET", "/api/Person/GetAllUsers"), paths)
        self.assertIn(("GET", "/api/Person/GetExternalUsers"), paths)
        self.assertIn((None, "/api/Questionnaire/GetMigerateQuaterlyInfoMaster"), paths)

    def test_extracts_webpack_manifest(self):
        runtime = 'a.u=e=>(592===e?"common":e)+"."+{21:"abc123def",592:"feedface"}[e]+".js"'
        chunks = extract_webpack_chunks(runtime, "https://app.example/runtime.1.js")
        self.assertIn("https://app.example/21.abc123def.js", chunks)
        self.assertIn("https://app.example/common.feedface.js", chunks)

    def test_honors_webpack_public_path(self):
        runtime = 'a.p="/assets/";a.u=e=>e+"."+{21:"abc123def"}[e]+".js"'
        chunks = extract_webpack_chunks(runtime, "https://app.example/static/runtime.js")
        self.assertIn("https://app.example/assets/21.abc123def.js", chunks)

    def test_extracts_relative_api_literal(self):
        items = extract_endpoint_candidates(
            "const endpoint='api/Person/GetExternalUsers'",
            "https://app.example/main.js",
        )
        self.assertTrue(any(item.canonical_path == "/api/Person/GetExternalUsers" for item in items))

    def test_recovers_relative_angular_call_expression(self):
        items = extract_endpoint_candidates(
            'return this.http.get(this.apiBase + "Person/GetAllUsers")',
            "https://app.example/main.js",
        )
        self.assertTrue(any(
            item.method == "GET" and item.canonical_path == "/Person/GetAllUsers"
            for item in items
        ))

    def test_resolves_webpack_environment_and_template_constant_map(self):
        source = r'''({
            2340:(module,exports,webpackRequire)=>{
                webpackRequire.d(exports,{N:()=>environment});
                const environment={production:true,apiUrl:"https://app.example/api"};
            },
            909:(module,exports,webpackRequire)=>{
                const base=webpackRequire(2340).N.apiUrl;
                const endpoints={users:`${base}/Person/GetAllUsers`};
                return this.http.get(endpoints.users);
            }
        })'''
        items = extract_endpoint_candidates(source, "https://app.example/main.js")
        matches = [
            item for item in items
            if item.method == "GET" and item.canonical_path == "/api/Person/GetAllUsers"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].resolution, "template_resolved")
        self.assertEqual(matches[0].method_source, "request_call")
        self.assertEqual(matches[0].classification, "application_api")
        self.assertFalse(matches[0].observed)
        self.assertFalse(matches[0].validated)

    def test_infers_method_from_cross_module_constant_property(self):
        source = r'''({
            10:(m,e,w)=>{
                const env={apiUrl:"https://app.example/api"};
                const base=env.apiUrl;
                const routes={externalUsers:`${base}/Person/GetExternalUsers`};
            },
            20:(m,e,w)=>{
                return this.http.get(imported.routes.externalUsers);
            }
        })'''
        items = extract_endpoint_candidates(source, "https://app.example/main.js")
        self.assertTrue(any(
            item.method == "GET"
            and item.canonical_path == "/api/Person/GetExternalUsers"
            and item.method_source == "request_call"
            for item in items
        ))

    def test_keeps_unresolved_template_passive_and_explicit(self):
        source = "return http.get(`${runtimeBase}/api/users/${userId}`)"
        items = extract_endpoint_candidates(source, "https://app.example/main.js")
        match = next(item for item in items if item.canonical_path == "/api/users/{param}")
        self.assertEqual(match.resolution, "template_partial")
        self.assertIn("runtimeBase", match.unresolved_expressions)
        self.assertIn("userId", match.unresolved_expressions)
        self.assertFalse(match.observed)
        self.assertFalse(match.validated)

    def test_template_resolution_can_be_disabled(self):
        source = 'const base="/api"; const endpoint=`${base}/Person/GetAllUsers`'
        items = extract_endpoint_candidates(
            source,
            "https://app.example/main.js",
            resolve_templates=False,
        )
        self.assertFalse(any(item.canonical_path == "/api/Person/GetAllUsers" for item in items))

    def test_duplicate_candidate_keeps_richer_resolution_metadata(self):
        source = 'const base="/api"; const endpoint=`${base}/users`; const literal="/api/users"'
        items = extract_endpoint_candidates(source, "https://app.example/main.js")
        match = next(item for item in items if item.method is None and item.canonical_path == "/api/users")
        self.assertEqual(match.resolution, "template_resolved")
        self.assertEqual(match.method_source, "constant_map")

    def test_does_not_resolve_sensitive_constant_properties(self):
        source = 'const config={token:"/api/Admin/GetSecret"}; const endpoint=`${config.token}/users`'
        facts = resolve_static_endpoints(source)
        self.assertFalse(any("GetSecret" in item.value for item in facts))

    def test_function_calls_are_not_executed_or_guessed(self):
        facts = resolve_static_endpoints('const endpoint=`${danger()}/api/users`')
        match = next(item for item in facts if item.value == "/api/users")
        self.assertEqual(match.resolution, "template_partial")
        self.assertIn("danger()", match.unresolved)

    def test_rejects_cross_origin_reconstructed_candidate(self):
        items = extract_endpoint_candidates(
            'const endpoint=`https://other.example/api/users`',
            "https://app.example/main.js",
        )
        self.assertFalse(any("other.example" in item.raw_url for item in items))

    def test_static_resolver_enforces_source_size_budget(self):
        source = "x" * (MAX_SOURCE_BYTES + 1)
        self.assertEqual(resolve_static_endpoints(source), [])


class AsyncJavaScriptReconTests(unittest.IsolatedAsyncioTestCase):
    async def test_fetches_advertised_chunk_and_finds_endpoint(self):
        runtime_url = "https://app.example/runtime.1.js"
        chunk_url = "https://app.example/21.abc123def.js"
        runtime = 'a.u=e=>e+"."+{21:"abc123def"}[e]+".js"'
        request = FakeRequestContext({
            chunk_url: 'client.get("/api/Person/GetAllUsers")',
        })
        inventory = await expand_and_analyze_assets(
            request,
            {runtime_url: runtime},
            role="admin",
            allowed_hosts={"app.example"},
        )
        self.assertIn(chunk_url, request.requested)
        self.assertTrue(any(
            item.canonical_path == "/api/Person/GetAllUsers"
            for item in inventory.candidates
        ))

    async def test_parses_referenced_openapi_document(self):
        main_url = "https://app.example/main.js"
        schema_url = "https://app.example/openapi.json"
        request = FakeRequestContext({
            schema_url: '{"openapi":"3.0.0","paths":{"/api/users":{"get":{"operationId":"listUsers"}}}}',
        })
        inventory = await expand_and_analyze_assets(
            request,
            {main_url: "const spec='/openapi.json'"},
            role="admin",
            allowed_hosts={"app.example"},
        )
        self.assertTrue(any(
            item.source == "openapi" and item.canonical_path == "/api/users"
            for item in inventory.candidates
        ))


if __name__ == "__main__":
    unittest.main()
