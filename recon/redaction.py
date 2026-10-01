"""Redaction helpers for persisted recon evidence."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SENSITIVE_NAME_RE = re.compile(
    r"(?:authorization|proxy-authorization|cookie|set-cookie|csrf|xsrf|"
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|saml|assertion|"
    r"password|passwd|secret|client_secret|code|state|nonce|session)",
    re.IGNORECASE,
)
SENSITIVE_FIELD_RE = re.compile(
    r"^(?:authorization|proxy-authorization|cookie|set-cookie|csrf|xsrf|"
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|samlresponse|assertion|"
    r"password|passwd|secret|client_secret|code|state|nonce|session)$",
    re.IGNORECASE,
)
BEARER_RE = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b")
INLINE_SECRET_RE = re.compile(
    r"(?P<prefix>[\"']?(?:access[_-]?token|refresh[_-]?token|id[_-]?token|csrf|xsrf|"
    r"samlresponse|assertion|password|client_secret|authorization|session)[\"']?\s*[:=]\s*[\"']?)"
    r"(?P<value>[^\"'&\s<>]{4,})",
    re.IGNORECASE,
)
HTML_INPUT_SECRET_RE = re.compile(
    r"(?P<prefix><input\b[^>]*\bname\s*=\s*[\"'](?:samlresponse|assertion|csrf|xsrf|"
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|password)[\"'][^>]*\bvalue\s*=\s*[\"'])"
    r"(?P<value>[^\"']*)",
    re.IGNORECASE,
)


def redact_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        pairs = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            pairs.append((key, "[REDACTED]" if SENSITIVE_NAME_RE.search(key) else value))
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs, doseq=True), parsed.fragment))
    except Exception:
        return url


def redact_headers(headers: dict[str, Any]) -> dict[str, str]:
    clean: dict[str, str] = {}
    for key, value in (headers or {}).items():
        text = str(value)
        clean[str(key)] = "[REDACTED]" if SENSITIVE_NAME_RE.search(str(key)) else redact_text(text)
    return clean


def redact_text(value: str) -> str:
    text = str(value or "")
    text = BEARER_RE.sub(lambda m: f"{m.group(1)} [REDACTED]", text)
    text = JWT_RE.sub("[REDACTED_JWT]", text)
    text = HTML_INPUT_SECRET_RE.sub(lambda match: match.group("prefix") + "[REDACTED]", text)
    return INLINE_SECRET_RE.sub(lambda match: match.group("prefix") + "[REDACTED]", text)
    

def redact_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if SENSITIVE_NAME_RE.search(str(key)) else redact_json(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_json(item) for item in value]
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except Exception:
            return redact_text(value)
        return json.dumps(redact_json(decoded), separators=(",", ":"))
    return value


def redact_structure(value: Any, key_hint: str = "") -> Any:
    """Recursively redact serialized evidence, including URLs in arbitrary lists."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            key_text = str(key)
            if SENSITIVE_FIELD_RE.match(key_text):
                result[key_text] = "[REDACTED]"
            else:
                result[key_text] = redact_structure(item, key_text)
        return result
    if isinstance(value, list):
        return [redact_structure(item, key_hint) for item in value]
    if isinstance(value, str):
        if value.startswith(("http://", "https://", "ws://", "wss://", "/")) and "?" in value:
            return redact_url(value)
        return redact_text(value)
    return value


def build_redacted_http_message(start_line: str, headers: dict[str, Any], body: bytes | str = b"") -> bytes:
    clean_headers = redact_headers(headers)
    body_text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body or "")
    content_type = str(clean_headers.get("content-type", "")).lower()
    if "json" in content_type or "x-www-form-urlencoded" in content_type:
        body_text = str(redact_json(body_text))
    else:
        body_text = redact_text(body_text)
    message = start_line + "\r\n" + "\r\n".join(f"{k}: {v}" for k, v in clean_headers.items())
    return (message + "\r\n\r\n" + body_text).encode("utf-8", errors="replace")
