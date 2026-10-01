"""Read-only endpoint imports from HAR, SkeletonLock traffic, Burp XML, or text."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
import xml.etree.ElementTree as ET

from .models import EndpointCandidate, ReconInventory, infer_body_schema


REQUEST_LINE_RE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)", re.IGNORECASE)


def _candidate(method, url, source, evidence, role, body=None, status=None, content_type=None):
    return EndpointCandidate.build(
        method=method,
        raw_url=url,
        source=source,
        evidence=evidence,
        role=role,
        discovered_from=source,
        observed=True,
        validated=status is not None,
        confidence="HIGH",
        status=status,
        content_type=content_type,
        request_body_schema=infer_body_schema(body),
    )


def _load_json(payload, role, inventory):
    if isinstance(payload, dict) and isinstance(payload.get("log"), dict):
        entries = payload["log"].get("entries", [])
        for entry in entries:
            request = entry.get("request", {}) if isinstance(entry, dict) else {}
            response = entry.get("response", {}) if isinstance(entry, dict) else {}
            post_data = request.get("postData", {}) if isinstance(request, dict) else {}
            inventory.add(_candidate(
                request.get("method"), request.get("url", ""), "imported_har",
                "Observed in imported HAR", role,
                body=post_data.get("text") if isinstance(post_data, dict) else None,
                status=response.get("status") if isinstance(response, dict) else None,
                content_type=(response.get("content", {}) or {}).get("mimeType") if isinstance(response, dict) else None,
            ))
        return

    if isinstance(payload, list):
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            url = entry.get("url")
            if not url:
                continue
            body = None
            raw_request = entry.get("request")
            if isinstance(raw_request, str):
                try:
                    decoded = base64.b64decode(raw_request).decode("utf-8", errors="replace")
                    body = decoded.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in decoded else None
                except Exception:
                    pass
            inventory.add(_candidate(
                entry.get("method"), url, "imported_traffic",
                "Observed in imported SkeletonLock traffic", role,
                body=body,
                status=entry.get("responseCode"),
                content_type=entry.get("mimeType"),
            ))


def _load_burp_xml(text, role, inventory):
    root = ET.fromstring(text)
    for item in root.findall(".//item"):
        url = item.findtext("url") or ""
        method = item.findtext("method") or None
        body = None
        request_node = item.find("request")
        if request_node is not None and request_node.text:
            try:
                raw = base64.b64decode(request_node.text) if request_node.get("base64") == "true" else request_node.text.encode()
                decoded = raw.decode("utf-8", errors="replace")
                if not method:
                    match = REQUEST_LINE_RE.match(decoded)
                    method = match.group(1) if match else None
                body = decoded.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in decoded else None
            except Exception:
                pass
        status_text = item.findtext("status")
        status = int(status_text) if status_text and status_text.isdigit() else None
        inventory.add(_candidate(
            method, url, "imported_burp", "Observed in imported Burp XML", role,
            body=body, status=status, content_type=item.findtext("mimetype"),
        ))


def _load_text(text, role, inventory):
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        match = REQUEST_LINE_RE.match(value)
        if match:
            method, url = match.group(1).upper(), match.group(2)
        else:
            method, url = None, value
        inventory.add(_candidate(method, url, "seed_file", "Imported endpoint seed", role))


def load_recon_import(path: str, role: str = "Imported") -> ReconInventory:
    inventory = ReconInventory(role=role)
    source_path = Path(path)
    text = source_path.read_text(encoding="utf-8", errors="replace")
    suffix = source_path.suffix.lower()
    if suffix in {".har", ".json"}:
        _load_json(json.loads(text), role, inventory)
    elif suffix == ".xml":
        _load_burp_xml(text, role, inventory)
    else:
        _load_text(text, role, inventory)
    return inventory
