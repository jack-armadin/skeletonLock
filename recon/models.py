"""Typed, provenance-aware recon results.

The crawler used to keep page routes and API calls in unrelated sets.  That
made a string found in a bundle indistinguishable from a request observed on
the wire.  These models deliberately preserve that distinction.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import re
from typing import Any, Iterable, Optional
from urllib.parse import parse_qsl, quote, urlencode, urlparse


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
# Opaque application identifiers usually mix letters and digits.  Do not turn
# long alphabetic controller/action names (for example GetExternalUsers) into
# {id} placeholders.
_LONG_TOKEN_RE = re.compile(r"^(?=[A-Za-z0-9_-]{20,}$)(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_-]+$")
_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
_INT_RE = re.compile(r"^-?\d+$")
_FLOAT_RE = re.compile(r"^-?\d+\.\d+$")


def _canonical_value(value: str) -> str:
    value = str(value or "")
    if not value:
        return ""
    if _UUID_RE.match(value) or _HEX_RE.match(value) or _LONG_TOKEN_RE.match(value):
        return "{id}"
    if _INT_RE.match(value):
        return "{int}"
    if _FLOAT_RE.match(value):
        return "{number}"
    return value


def canonicalize_endpoint(value: str) -> str:
    """Return a stable path+query template while retaining parameter names."""
    raw = str(value or "").strip()
    if not raw:
        return "/"
    parsed = urlparse(raw)
    path = parsed.path or "/"
    path = "/".join(_canonical_value(part) if part else "" for part in path.split("/"))
    query = ""
    if parsed.query:
        pairs = [(key, _canonical_value(val)) for key, val in parse_qsl(parsed.query, keep_blank_values=True)]
        # Keep braces readable instead of percent-encoding candidate templates.
        query = urlencode(sorted(pairs), doseq=True, quote_via=quote, safe="{}[]")
    return path + (("?" + query) if query else "")


def _schema_for_value(value: Any, depth: int = 0) -> Any:
    if depth > 6:
        return "unknown"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        samples = [_schema_for_value(item, depth + 1) for item in value[:3]]
        unique = []
        for item in samples:
            if item not in unique:
                unique.append(item)
        return {"type": "array", "items": unique or ["unknown"]}
    if isinstance(value, dict):
        return {str(key): _schema_for_value(item, depth + 1) for key, item in value.items()}
    return type(value).__name__


def infer_body_schema(body: Any) -> Optional[dict[str, Any]]:
    """Infer field names and primitive types without retaining sensitive values."""
    if body is None or body == "":
        return None
    if isinstance(body, (dict, list)):
        schema = _schema_for_value(body)
        return schema if isinstance(schema, dict) else {"body": schema}
    text = str(body).strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
        schema = _schema_for_value(parsed)
        return schema if isinstance(schema, dict) else {"body": schema}
    except Exception:
        pass
    try:
        pairs = parse_qsl(text, keep_blank_values=True)
        if pairs and any("=" in piece for piece in text.split("&")):
            return {key: "string" for key, _value in pairs}
    except Exception:
        pass
    return {"body": "opaque"}


@dataclass
class EndpointCandidate:
    method: Optional[str]
    raw_url: str
    canonical_path: str
    source: str
    evidence: str
    role: Optional[str] = None
    discovered_from: Optional[str] = None
    observed: bool = False
    validated: bool = False
    confidence: str = "MEDIUM"
    status: Optional[int] = None
    content_type: Optional[str] = None
    request_body_schema: Optional[dict[str, Any]] = None
    resolution: Optional[str] = None
    method_source: Optional[str] = None
    unresolved_expressions: list[str] = field(default_factory=list)
    classification: Optional[str] = None

    @classmethod
    def build(
        cls,
        *,
        method: Optional[str],
        raw_url: str,
        source: str,
        evidence: str,
        role: Optional[str] = None,
        discovered_from: Optional[str] = None,
        observed: bool = False,
        validated: bool = False,
        confidence: str = "MEDIUM",
        status: Optional[int] = None,
        content_type: Optional[str] = None,
        request_body_schema: Optional[dict[str, Any]] = None,
        resolution: Optional[str] = None,
        method_source: Optional[str] = None,
        unresolved_expressions: Optional[Iterable[str]] = None,
        classification: Optional[str] = None,
    ) -> "EndpointCandidate":
        return cls(
            method=(method or None).upper() if method else None,
            raw_url=raw_url,
            canonical_path=canonicalize_endpoint(raw_url),
            source=source,
            evidence=evidence,
            role=role,
            discovered_from=discovered_from,
            observed=bool(observed),
            validated=bool(validated),
            confidence=str(confidence or "MEDIUM").upper(),
            status=status,
            content_type=content_type,
            request_body_schema=request_body_schema,
            resolution=resolution,
            method_source=method_source,
            unresolved_expressions=list(unresolved_expressions or []),
            classification=classification,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReconInventory:
    """Deduplicated candidates plus transparent coverage accounting."""

    role: Optional[str] = None
    candidates: list[EndpointCandidate] = field(default_factory=list)
    assets_advertised: set[str] = field(default_factory=set)
    assets_downloaded: set[str] = field(default_factory=set)
    assets_fetched_by_scanner: set[str] = field(default_factory=set)
    assets_parsed: set[str] = field(default_factory=set)
    source_maps_found: set[str] = field(default_factory=set)
    skipped_assets: list[dict[str, str]] = field(default_factory=list)
    ui_metrics: dict[str, int] = field(default_factory=dict)
    state_transitions: list[dict[str, Any]] = field(default_factory=list)
    _keys: set[tuple[Any, ...]] = field(default_factory=set, repr=False)

    def add(self, candidate: EndpointCandidate) -> bool:
        key = (
            candidate.method or "UNKNOWN",
            candidate.canonical_path,
            candidate.source,
            candidate.role or "",
            candidate.discovered_from or "",
        )
        if key in self._keys:
            # Upgrade the existing item if later evidence is stronger.
            for item in self.candidates:
                item_key = (
                    item.method or "UNKNOWN",
                    item.canonical_path,
                    item.source,
                    item.role or "",
                    item.discovered_from or "",
                )
                if item_key == key:
                    item.observed = item.observed or candidate.observed
                    item.validated = item.validated or candidate.validated
                    item.status = candidate.status if candidate.status is not None else item.status
                    item.content_type = candidate.content_type or item.content_type
                    item.resolution = candidate.resolution or item.resolution
                    item.method_source = candidate.method_source or item.method_source
                    item.classification = candidate.classification or item.classification
                    for expression in candidate.unresolved_expressions:
                        if expression not in item.unresolved_expressions:
                            item.unresolved_expressions.append(expression)
                    if len(candidate.evidence or "") > len(item.evidence or ""):
                        item.evidence = candidate.evidence
                    break
            return False
        self._keys.add(key)
        self.candidates.append(candidate)
        return True

    def extend(self, candidates: Iterable[EndpointCandidate]) -> None:
        for candidate in candidates:
            self.add(candidate)

    def merge(self, other: "ReconInventory") -> None:
        self.extend(other.candidates)
        self.assets_advertised.update(other.assets_advertised)
        self.assets_downloaded.update(other.assets_downloaded)
        self.assets_fetched_by_scanner.update(other.assets_fetched_by_scanner)
        self.assets_parsed.update(other.assets_parsed)
        self.source_maps_found.update(other.source_maps_found)
        self.skipped_assets.extend(other.skipped_assets)
        self.state_transitions.extend(other.state_transitions)
        for key, value in other.ui_metrics.items():
            self.ui_metrics[key] = self.ui_metrics.get(key, 0) + int(value)

    def coverage(self) -> dict[str, Any]:
        by_source: dict[str, int] = {}
        observed = validated = 0
        for candidate in self.candidates:
            by_source[candidate.source] = by_source.get(candidate.source, 0) + 1
            observed += int(candidate.observed)
            validated += int(candidate.validated)
        return {
            "role": self.role,
            "assets_advertised": len(self.assets_advertised),
            "assets_downloaded": len(self.assets_downloaded),
            "assets_fetched_by_scanner": len(self.assets_fetched_by_scanner),
            "assets_parsed": len(self.assets_parsed),
            "source_maps_found": len(self.source_maps_found),
            "assets_skipped": len(self.skipped_assets),
            "endpoint_candidates": len(self.candidates),
            "observed_candidates": observed,
            "validated_candidates": validated,
            "by_source": dict(sorted(by_source.items())),
            "ui": dict(sorted(self.ui_metrics.items())),
            "state_transitions": len(self.state_transitions),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "coverage": self.coverage(),
            "assets": {
                "advertised": sorted(self.assets_advertised),
                "downloaded": sorted(self.assets_downloaded),
                "fetched_by_scanner": sorted(self.assets_fetched_by_scanner),
                "parsed": sorted(self.assets_parsed),
                "source_maps": sorted(self.source_maps_found),
                "skipped": self.skipped_assets,
            },
            "state_transitions": self.state_transitions,
            "candidates": [item.to_dict() for item in sorted(
                self.candidates,
                key=lambda c: (c.canonical_path.lower(), c.method or "", c.source, c.discovered_from or ""),
            )],
        }
