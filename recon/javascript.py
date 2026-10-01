"""Safe, passive endpoint discovery from first-party JavaScript assets."""

from __future__ import annotations

import json
import re
from typing import Iterable, Optional
from urllib.parse import urljoin, urlparse

from .models import EndpointCandidate, ReconInventory
from .schemas import extract_openapi_candidates, extract_referenced_schema_urls
from .js_static_resolver import resolve_static_endpoints


HTTP_METHOD_RE = re.compile(
    r"(?:\bfetch\s*\(|\.(get|post|put|patch|delete|head|options)\s*\()\s*"
    r"([\"'`])([^\"'`]{1,1000})\2",
    re.IGNORECASE,
)
XHR_OPEN_RE = re.compile(
    r"\.open\s*\(\s*([\"'])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\1\s*,\s*"
    r"([\"'`])([^\"'`]{1,1000})\3",
    re.IGNORECASE,
)
METHOD_CALL_RE = re.compile(
    r"\.(get|post|put|patch|delete|head|options)\s*\((.{1,600}?)\)",
    re.IGNORECASE | re.DOTALL,
)
SOURCE_MAP_RE = re.compile(r"[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)")
WEBPACK_PAIR_RE = re.compile(r"(?<![A-Za-z0-9_$])(\d{1,7})\s*:\s*[\"']([a-f0-9]{6,64})[\"']", re.IGNORECASE)
LINKED_JS_RE = re.compile(r"[\"']([^\"']+\.(?:m?js))(?:\?[^\"']*)?[\"']", re.IGNORECASE)
CONCAT_RE = re.compile(
    r"([\"'])(/[^\"']{1,300})\1\s*\+\s*([\"'])([^\"']{1,300})\3"
)

API_HINT_RE = re.compile(
    r"(?:^|/)(?:api|rest|graphql|service|services|odata|v\d+)(?:/|$)",
    re.IGNORECASE,
)
ACTION_HINT_RE = re.compile(
    r"(?:get|list|search|find|create|add|update|edit|delete|remove|export|import|"
    r"report|user|account|admin|questionnaire|migrate|quaterly|quarterly|master)",
    re.IGNORECASE,
)
STATIC_SUFFIXES = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map", ".html",
)

IDENTITY_HINT_RE = re.compile(
    r"(?:^|/)(?:oauth2?|authorize|token|revoke|userinfo|authn|idp|saml|sessions?)(?:/|$)",
    re.IGNORECASE,
)
EMBEDDED_VENDOR_RE = re.compile(r"(?:^|/)(?:report|reports)(?:/|$)", re.IGNORECASE)


def classify_endpoint(url: str) -> str:
    path = urlparse(url).path or "/"
    if IDENTITY_HINT_RE.search(path):
        return "identity"
    if EMBEDDED_VENDOR_RE.search(path):
        return "embedded_vendor"
    if API_HINT_RE.search(path) or ACTION_HINT_RE.search(path):
        return "application_api"
    if re.search(r"/(?:hub|hubs|signalr)(?:/|$)", path, re.IGNORECASE):
        return "realtime"
    return "route"


def strip_http_envelope(text: str) -> str:
    if text.startswith("HTTP/"):
        marker = "\r\n\r\n"
        if marker in text:
            return text.split(marker, 1)[1]
        marker = "\n\n"
        if marker in text:
            return text.split(marker, 1)[1]
    return text


def _decode_js_string(value: str) -> str:
    try:
        # json handles common JS escapes after quote normalization.
        return json.loads('"' + value.replace('"', '\\"') + '"')
    except Exception:
        return value.replace("\\/", "/")


def iter_js_strings(text: str, max_length: int = 2000):
    """Yield JavaScript string contents with a bounded linear-time scanner."""
    index = 0
    length = len(text)
    while index < length:
        quote_char = text[index]
        if quote_char not in ("'", '"', "`"):
            index += 1
            continue
        start = index
        index += 1
        value_start = index
        escaped = False
        too_long = False
        while index < length:
            char = text[index]
            if escaped:
                escaped = False
                index += 1
                continue
            if char == "\\":
                escaped = True
                index += 1
                continue
            if char == quote_char:
                if not too_long and index > value_start:
                    yield text[value_start:index], start, index + 1
                index += 1
                break
            if quote_char != "`" and char in ("\n", "\r"):
                index += 1
                break
            if index - value_start > max_length:
                too_long = True
            index += 1


def _candidate_url(value: str, base_url: str, allow_relative: bool = False) -> Optional[str]:
    raw = _decode_js_string(value).strip()
    if not raw or len(raw) > 1500:
        return None
    if raw.startswith(("data:", "blob:", "javascript:", "mailto:", "#")):
        return None
    if any(ch in raw for ch in ("<", ">", "{", "}")):
        # Unresolved templates are retained only when their static prefix is API-like.
        if not API_HINT_RE.search(raw) and not ACTION_HINT_RE.search(raw):
            return None
    parsed = urlparse(raw)
    path = parsed.path if parsed.scheme or parsed.netloc else raw.split("?", 1)[0]
    if path.lower().endswith(STATIC_SUFFIXES):
        return None
    if re.match(r"^(?:api|rest|graphql|odata|services?|v\d+)/", raw, re.IGNORECASE):
        raw = "/" + raw
    if allow_relative and not raw.startswith(("/", "http://", "https://", "ws://", "wss://", "./", "../")):
        if "/" in raw and ACTION_HINT_RE.search(raw):
            raw = "/" + raw
    if not raw.startswith(("/", "http://", "https://", "ws://", "wss://", "./", "../")):
        return None
    if not API_HINT_RE.search(path) and not ACTION_HINT_RE.search(path) and not re.search(r"/(?:hub|hubs|signalr)(?:/|$)", path, re.IGNORECASE):
        return None
    return urljoin(base_url, raw)


def extract_endpoint_candidates(
    text: str,
    asset_url: str,
    role: Optional[str] = None,
    source: str = "js_bundle",
    *,
    resolve_templates: bool = True,
) -> list[EndpointCandidate]:
    body = strip_http_envelope(text)
    candidates: list[EndpointCandidate] = []
    seen: dict[tuple[Optional[str], str], EndpointCandidate] = {}

    def remember(
        method: Optional[str],
        raw: str,
        evidence: str,
        confidence: str,
        allow_relative: bool = False,
        *,
        resolution: Optional[str] = "literal",
        method_source: Optional[str] = None,
        unresolved_expressions: Iterable[str] = (),
    ) -> None:
        url = _candidate_url(raw, asset_url, allow_relative=allow_relative)
        if not url:
            return
        parsed_asset = urlparse(asset_url)
        parsed_url = urlparse(url)
        if parsed_url.netloc and parsed_asset.netloc and parsed_url.netloc != parsed_asset.netloc:
            return
        candidate = EndpointCandidate.build(
            method=method,
            raw_url=url,
            source=source,
            evidence=evidence[:500],
            role=role,
            discovered_from=asset_url,
            observed=False,
            validated=False,
            confidence=confidence,
            resolution=resolution,
            method_source=method_source or ("request_call" if method else "unknown"),
            unresolved_expressions=unresolved_expressions,
            classification=classify_endpoint(url),
        )
        key = (candidate.method, candidate.canonical_path)
        existing = seen.get(key)
        if existing is not None:
            resolution_rank = {
                None: 0,
                "literal": 1,
                "concatenated": 2,
                "template_partial": 3,
                "template_resolved": 4,
            }
            if resolution_rank.get(candidate.resolution, 0) > resolution_rank.get(existing.resolution, 0):
                existing.resolution = candidate.resolution
                existing.evidence = candidate.evidence or existing.evidence
            if existing.method_source in {None, "unknown", "constant_map"} and candidate.method_source:
                existing.method_source = candidate.method_source
            if candidate.confidence == "HIGH":
                existing.confidence = "HIGH"
            for expression in candidate.unresolved_expressions:
                if expression not in existing.unresolved_expressions:
                    existing.unresolved_expressions.append(expression)
            return
        seen[key] = candidate
        candidates.append(candidate)

    for match in HTTP_METHOD_RE.finditer(body):
        method = match.group(1).upper() if match.group(1) else "GET"
        if not match.group(1):
            fetch_tail = body[match.end():match.end() + 350]
            method_match = re.search(r"\bmethod\s*:\s*[\"'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"']", fetch_tail, re.IGNORECASE)
            if method_match:
                method = method_match.group(1).upper()
        if "${" not in match.group(3):
            remember(method, match.group(3), match.group(0), "HIGH", method_source="request_call")

    for match in XHR_OPEN_RE.finditer(body):
        remember(match.group(2).upper(), match.group(4), match.group(0), "HIGH", method_source="request_call")

    # Recover simple concatenated Angular/axios call expressions such as
    # http.get(environment.apiUrl + "Person/GetAllUsers").
    for match in METHOD_CALL_RE.finditer(body):
        method = match.group(1).upper()
        literals = [
            value for value, _start, _end in iter_js_strings(match.group(2), max_length=600)
            if "${" not in value
        ]
        if literals:
            remember(method, "".join(literals), match.group(0), "MEDIUM", allow_relative=True, resolution="concatenated", method_source="request_call")
            remember(method, literals[0], match.group(0), "MEDIUM", allow_relative=True, method_source="request_call")

    # Handle the common minified form "/api/" + "Controller/Action".
    for match in CONCAT_RE.finditer(body):
        remember(None, match.group(2) + match.group(4), match.group(0), "MEDIUM")

    for value, start, end in iter_js_strings(body):
        if body[start:start + 1] == "`" and "${" in value:
            continue
        remember(None, value, body[start:end], "MEDIUM")

    if resolve_templates:
        for fact in resolve_static_endpoints(body):
            remember(
                fact.method,
                fact.value,
                fact.evidence,
                "HIGH" if fact.method and not fact.unresolved else "MEDIUM",
                allow_relative=True,
                resolution=fact.resolution,
                method_source=fact.method_source,
                unresolved_expressions=fact.unresolved,
            )

    return candidates


def extract_source_map_urls(text: str, asset_url: str) -> set[str]:
    return {urljoin(asset_url, match.group(1).strip()) for match in SOURCE_MAP_RE.finditer(strip_http_envelope(text))}


def extract_linked_js_urls(text: str, asset_url: str) -> set[str]:
    urls = set()
    for value in LINKED_JS_RE.findall(strip_http_envelope(text)):
        url = urljoin(asset_url, value)
        if urlparse(url).netloc == urlparse(asset_url).netloc:
            urls.add(url)
    return urls


def extract_source_map_candidates(text: str, map_url: str, role: Optional[str]) -> list[EndpointCandidate]:
    try:
        payload = json.loads(strip_http_envelope(text))
    except Exception:
        return extract_endpoint_candidates(text, map_url, role=role, source="source_map")
    candidates: list[EndpointCandidate] = []
    contents = payload.get("sourcesContent") if isinstance(payload, dict) else None
    sources = payload.get("sources") if isinstance(payload, dict) else None
    if isinstance(contents, list):
        for index, source_text in enumerate(contents):
            if not isinstance(source_text, str):
                continue
            source_name = sources[index] if isinstance(sources, list) and index < len(sources) else f"source-{index}"
            virtual_url = f"{map_url}#{source_name}"
            candidates.extend(extract_endpoint_candidates(source_text, virtual_url, role=role, source="source_map"))
    return candidates


def extract_webpack_chunks(text: str, runtime_url: str) -> set[str]:
    """Extract conventional Webpack numeric chunk URLs from a runtime bundle."""
    body = strip_http_envelope(text)
    chunks: set[str] = set()
    public_path = ""
    public_match = re.search(r"(?:\b\w+|__webpack_require__)\.p\s*=\s*[\"']([^\"']*)[\"']", body)
    if public_match:
        public_path = public_match.group(1)
    chunk_base = urljoin(runtime_url, public_path or "./")
    for chunk_id, digest in WEBPACK_PAIR_RE.findall(body):
        basename = "common" if re.search(rf"{re.escape(chunk_id)}\s*===?\s*\w+\s*\?\s*[\"']common", body) else chunk_id
        chunks.add(urljoin(chunk_base, f"{basename}.{digest}.js"))
    return chunks


async def expand_and_analyze_assets(
    request_context,
    initial_assets: dict[str, str],
    *,
    role: Optional[str],
    allowed_hosts: Iterable[str],
    max_assets: int = 150,
    max_total_bytes: int = 50 * 1024 * 1024,
    fetch_source_maps: bool = True,
    browser_page=None,
    resolve_templates: bool = True,
) -> ReconInventory:
    """Enumerate advertised chunks, fetch bounded first-party assets, and analyze them."""
    inventory = ReconInventory(role=role)
    allowed = {str(host).lower() for host in allowed_hosts if host}
    assets = {url: strip_http_envelope(text) for url, text in initial_assets.items()}
    asset_kinds = {url: "javascript" for url in assets}
    inventory.assets_downloaded.update(assets)
    queue: list[tuple[str, str]] = []

    for url, text in list(assets.items()):
        for chunk_url in extract_webpack_chunks(text, url):
            inventory.assets_advertised.add(chunk_url)
            if chunk_url not in assets:
                queue.append((chunk_url, "webpack_chunk"))
        if fetch_source_maps:
            for map_url in extract_source_map_urls(text, url):
                inventory.assets_advertised.add(map_url)
                inventory.source_maps_found.add(map_url)
                if map_url not in assets:
                    queue.append((map_url, "source_map"))
        for linked_url in extract_linked_js_urls(text, url):
            inventory.assets_advertised.add(linked_url)
            if linked_url not in assets:
                queue.append((linked_url, "linked_script"))
        for schema_url in extract_referenced_schema_urls(text, url):
            inventory.assets_advertised.add(schema_url)
            if schema_url not in assets:
                queue.append((schema_url, "api_schema"))

    total_bytes = sum(len(text.encode("utf-8", errors="replace")) for text in assets.values())
    fetched = 0
    seen_urls = set(assets)
    while queue and fetched < max_assets and total_bytes < max_total_bytes:
        url, kind = queue.pop(0)
        if url in seen_urls:
            continue
        seen_urls.add(url)
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or parsed.hostname not in allowed:
            inventory.skipped_assets.append({"url": url, "reason": "outside first-party scope"})
            continue
        try:
            raw = None
            status = None
            # Same-origin browser fetch preserves the exact browser/TLS/WAF session
            # while downloading text without executing the script.
            if browser_page is not None and urlparse(getattr(browser_page, "url", "")).netloc == parsed.netloc:
                try:
                    browser_result = await browser_page.evaluate("""async (assetUrl) => {
                        const response = await fetch(assetUrl, {credentials: 'include', cache: 'no-store'});
                        const text = await response.text();
                        return {ok: response.ok, status: response.status, text};
                    }""", url)
                    status = int(browser_result.get("status", 0))
                    if browser_result.get("ok"):
                        raw = str(browser_result.get("text", "")).encode("utf-8", errors="replace")
                except Exception:
                    raw = None
            if raw is None:
                response = await request_context.get(url, timeout=15000, fail_on_status_code=False)
                status = response.status
                if response.ok:
                    raw = await response.body()
            if raw is None:
                inventory.skipped_assets.append({"url": url, "reason": f"HTTP {status or 'error'}"})
                continue
            if total_bytes + len(raw) > max_total_bytes:
                inventory.skipped_assets.append({"url": url, "reason": "byte budget exceeded"})
                break
            text = raw.decode("utf-8", errors="replace")
            assets[url] = text
            asset_kinds[url] = kind
            total_bytes += len(raw)
            fetched += 1
            inventory.assets_downloaded.add(url)
            inventory.assets_fetched_by_scanner.add(url)
            if kind != "source_map":
                for nested in extract_webpack_chunks(text, url):
                    inventory.assets_advertised.add(nested)
                    if nested not in seen_urls:
                        queue.append((nested, "webpack_chunk"))
                for linked_url in extract_linked_js_urls(text, url):
                    inventory.assets_advertised.add(linked_url)
                    if linked_url not in seen_urls:
                        queue.append((linked_url, "linked_script"))
                for schema_url in extract_referenced_schema_urls(text, url):
                    inventory.assets_advertised.add(schema_url)
                    if schema_url not in seen_urls:
                        queue.append((schema_url, "api_schema"))
                if fetch_source_maps:
                    for map_url in extract_source_map_urls(text, url):
                        inventory.assets_advertised.add(map_url)
                        inventory.source_maps_found.add(map_url)
                        if map_url not in seen_urls:
                            queue.append((map_url, "source_map"))
        except Exception as exc:
            inventory.skipped_assets.append({"url": url, "reason": type(exc).__name__})

    if queue:
        for url, _kind in queue:
            inventory.skipped_assets.append({"url": url, "reason": "asset limit reached"})

    for url, text in assets.items():
        if asset_kinds.get(url) == "api_schema":
            inventory.extend(extract_openapi_candidates(text, url, role))
            inventory.assets_parsed.add(url)
            continue
        source = "source_map" if url.lower().endswith(".map") else "js_bundle"
        if source == "source_map":
            inventory.extend(extract_source_map_candidates(text, url, role))
        else:
            inventory.extend(extract_endpoint_candidates(
                text,
                url,
                role=role,
                source=source,
                resolve_templates=resolve_templates,
            ))
        inventory.assets_parsed.add(url)

    return inventory
