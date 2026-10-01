"""Discovery from application-referenced API descriptions."""

from __future__ import annotations

import json
import re
from typing import Optional
from urllib.parse import urljoin, urlparse

from .models import EndpointCandidate


SCHEMA_URL_RE = re.compile(
    r"[\"']([^\"']*(?:openapi(?:\.json|\.ya?ml)|swagger(?:\.json|\.ya?ml)|"
    r"swagger/v\d+/swagger\.json|v\d+/api-docs)[^\"']*)[\"']",
    re.IGNORECASE,
)
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


def extract_referenced_schema_urls(text: str, base_url: str) -> set[str]:
    result = set()
    for value in SCHEMA_URL_RE.findall(text or ""):
        url = urljoin(base_url, value)
        if urlparse(url).netloc == urlparse(base_url).netloc:
            result.add(url)
    return result


def extract_openapi_candidates(text: str, schema_url: str, role: Optional[str]) -> list[EndpointCandidate]:
    try:
        document = json.loads(text)
    except Exception:
        # YAML support intentionally stays optional; JSON is the dominant browser-linked format.
        return []
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        return []
    base = schema_url
    servers = document.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict) and servers[0].get("url"):
        base = urljoin(schema_url, str(servers[0]["url"]))
    items = []
    for path, path_item in document["paths"].items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if str(method).lower() not in HTTP_METHODS:
                continue
            operation_id = operation.get("operationId") if isinstance(operation, dict) else None
            items.append(EndpointCandidate.build(
                method=str(method).upper(),
                raw_url=urljoin(base, str(path)),
                source="openapi",
                evidence=f"OpenAPI operation{': ' + str(operation_id) if operation_id else ''}",
                role=role,
                discovered_from=schema_url,
                observed=False,
                validated=False,
                confidence="HIGH",
            ))
    return items
