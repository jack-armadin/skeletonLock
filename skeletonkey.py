import argparse
import asyncio
import base64
import csv
import hashlib
from datetime import datetime
import json
import logging
import sys
import os
import random
import re
from typing import NamedTuple, Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from recon.javascript import expand_and_analyze_assets
from recon.importers import load_recon_import
from recon.models import EndpointCandidate, ReconInventory, infer_body_schema
from recon.redaction import build_redacted_http_message, redact_structure, redact_text, redact_url
from recon.validation import validate_safe_get_candidates

try:
    import openpyxl
    from openpyxl.styles import PatternFill, Border, Side, Font
except ImportError:
    openpyxl = None

try:
    from playwright.async_api import async_playwright, Page
except ImportError:
    print("Error: 'playwright' module not found. Please install it using:")
    print("  pip install playwright")
    print("  playwright install")
    sys.exit(1)

try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None

try:
    import requests
except ImportError:
    requests = None

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Playwright timeout constants (milliseconds)
TIMEOUT_LONG   = 3000
TIMEOUT_MEDIUM = 2000
TIMEOUT_SHORT  = 1000
TIMEOUT_BRIEF  =  500
ADAPTIVE_SPA_CLICK_CAP = 45
CRAWL_DOM_TIMEOUT_SEC = 10.0
CRAWL_FAST_TIMEOUT_SEC = 5.0
CRAWL_CLOSE_TIMEOUT_SEC = 5.0


async def _bounded_crawl_await(awaitable, timeout_sec, default=None, role_name="", action="crawl operation"):
    """Run a crawl sub-step with a local timeout so one stuck DOM op does not stall a role."""
    try:
        return await asyncio.wait_for(awaitable, timeout=timeout_sec)
    except asyncio.TimeoutError:
        prefix = f"[{role_name}] " if role_name else ""
        logger.warning(f"{prefix}Timed out while {action}; continuing.")
        return default
    except Exception as e:
        prefix = f"[{role_name}] " if role_name else ""
        logger.debug(f"{prefix}Failed while {action}: {e}")
        return default


class ApiCall(NamedTuple):
    method: str           # GET, POST, PUT, DELETE, PATCH, …
    url: str              # absolute URL as captured
    path: str             # path+query, normalised (same format as discovered_endpoints)
    body: Optional[str]   # request body (JSON string or form data), None if absent
    headers: dict         # request headers captured from JS (no cookies — added at replay time)


# Extensions to ignore
IGNORED_EXTENSIONS = {
    '.css', '.less', '.sass', '.scss', '.js', '.map',
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.bmp', '.webp',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp3', '.mp4', '.avi', '.mov', '.webm',
    '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z',
    '.xml', '.webmanifest'
}

# Like IGNORED_EXTENSIONS but keeps .js (and HTML/JSON/API by default) for --mockingbird traffic log.
_TRAFFIC_SKIP_EXTENSIONS = {
    '.css', '.map',
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.bmp', '.webp',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp3', '.mp4', '.avi', '.mov',
    '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z',
}

# ── Two-tier SPA click safety system ──────────────────────────────────────────
# Tier 1: HARD_SKIP — always skip, no AI review needed.
# These are unambiguously destructive or session-ending terms.
HARD_SKIP_TERMS = {
    # Session-ending
    "logout", "log out", "sign out", "signout", "log off", "logoff", "sign-out",
    # Deletion
    "delete", "bulk delete", "force delete", "permanent delete", "delete all",
    "remove all", "destroy", "drop", "truncate", "wipe", "purge", "erase", "shred",
    # Account termination
    "terminate account", "close account", "deactivate account",
    "factory reset", "hard reset",
    # Blanket revocation
    "revoke all", "revoke all tokens", "revoke all sessions",
    # Re-render loops — clicking these re-mounts entire lists, minting new
    # DOM identities for logically-identical items and causing infinite
    # click loops. Not destructive; individual items are still enumerable.
    "expand all", "collapse all", "view all",
}

# Tier 2: RISKY_TERMS — route to Gemini for context-aware review.
# Gemini decides SAFE (proceed) or SKIP (don't click).
RISKY_TERMS = {
    # Sending / communicating
    "send", "send message", "send email", "send notification", "broadcast", "notify",
    # Publishing / deploying
    "publish", "deploy", "release", "go live", "push to production",
    # Submitting data
    "submit", "submit form",
    # User / access management
    "invite", "add user", "add member", "remove user", "remove member",
    "ban", "suspend", "reinstate", "kick", "expel",
    "grant access", "revoke", "revoke access",
    # Enable / disable
    "disable", "deactivate", "activate", "enable",
    # Credential operations
    "reset password", "change password", "set password",
    "rotate", "regenerate", "generate token", "generate key", "generate secret",
    # Financial / billing
    "pay", "purchase", "buy", "checkout", "charge", "refund",
    "upgrade plan", "downgrade plan", "cancel subscription", "unsubscribe",
    # Execution / automation
    "run", "execute", "trigger", "launch job", "run script",
    "run workflow", "start pipeline",
    # Bulk / irreversible data operations
    "migrate", "transfer", "move all", "merge",
    "bulk import", "bulk update", "bulk delete",
    "clear all", "clear data", "flush cache", "flush",
    # Approval / rejection workflows
    "approve", "reject", "deny",
    # Chatbot / live support (risk of creating tickets or engaging live agents)
    "start chat", "chat now", "chat with us", "live chat",
    "contact support", "open chat", "chat support",
    "submit ticket", "create ticket", "new ticket", "open ticket",
    # Ambiguous confirmations in a destructive context
    "yes, delete", "yes, remove", "yes, disable", "yes, reset",
    "confirm delete", "confirm removal",
}

# Cache for Gemini risk decisions — keyed by (text, aria-label, title, url-path)
_gemini_risk_cache: dict = {}

AUTH_COOKIE_RE = re.compile(
    r"(session|sess|sid|auth|token|jwt|access|refresh|id_token|idtoken|remember)",
    re.IGNORECASE,
)
AUTH_STORAGE_RE = re.compile(
    r"(access[_-]?token|refresh[_-]?token|id[_-]?token|jwt|session|auth|credential|user)",
    re.IGNORECASE,
)
CSRF_NAME_RE = re.compile(r"(csrf|xsrf|_token|requestverificationtoken)", re.IGNORECASE)
LOGIN_FAILURE_RE = re.compile(
    r"(invalid|incorrect|failed|try again|wrong password|bad credentials|"
    r"couldn't sign|could not sign|account disabled|locked|captcha)",
    re.IGNORECASE,
)
AUTH_ENTRY_CONTROL_RE = re.compile(r"\b(login again|log\s*in|sign\s*in|sign-in|signin)\b", re.IGNORECASE)
AUTH_WALL_TEXT_RE = re.compile(
    r"(session (?:timeout|timed out|expired)|login again|please log in|please login|"
    r"sign in to continue|log in to continue|reauthenticate|authenticate again)",
    re.IGNORECASE,
)
PUBLIC_LANDING_CTA_RE = re.compile(
    r"\b(sign up|contact us|learn more|get started|register|create account|request demo|book demo)\b",
    re.IGNORECASE,
)
AUTH_FIELD_POSITIVE_RE = re.compile(
    r"(username|user name|userid|user id|email|e-mail|login|identifier|current-password|password)",
    re.IGNORECASE,
)
AUTH_FIELD_NEGATIVE_RE = re.compile(
    r"(search|filter|lookup|find|query|criteria|keyword)",
    re.IGNORECASE,
)
NON_ROUTE_FRAGMENT_RE = re.compile(
    r"^(?:collapse|accordion|panel|tab|section|modal|drawer|tooltip|popover)[A-Za-z0-9_-]*$",
    re.IGNORECASE,
)


NON_ROUTE_FRAGMENTS = {
    "top", "bottom", "header", "footer", "content", "main", "nav", "navbar",
    "navigation", "menu", "skip", "skipcontent", "skipnavigation",
}


def spa_route_fragment(fragment: str) -> str:
    """Return a canonical SPA route fragment such as /Tools, or empty for page anchors."""
    frag = str(fragment or "").strip()
    if not frag:
        return ""
    if frag.startswith("!"):
        frag = frag[1:].strip()
    if not frag:
        return ""
    frag_body = frag.lstrip("/")
    if NON_ROUTE_FRAGMENT_RE.match(frag_body):
        return ""
    if frag.startswith("/"):
        return frag
    compact = frag.lower().replace("-", "").replace("_", "")
    if compact in NON_ROUTE_FRAGMENTS:
        return ""
    if "/" in frag:
        return "/" + frag.lstrip("/")
    # Angular ui-router apps often expose states as #Tools or #defaultHome.
    # Keep route-looking names, but drop short lowercase anchors like #crm.
    if re.match(r"^[A-Za-z][A-Za-z0-9_.~-]{2,}$", frag) and (
        any(ch.isupper() for ch in frag) or "." in frag or "-" in frag or "_" in frag
    ):
        return "/" + frag
    return ""


def endpoint_from_url(url: str) -> str:
    """Return the report/replay endpoint for a URL, preserving query IDs.

    Query-string object IDs are common in IDOR/BOLA targets, so the authorization
    map must keep them. Hash routes are only kept for SPA route fragments.
    """
    parsed = urlparse(url or "")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    route_fragment = spa_route_fragment(parsed.fragment)
    if route_fragment:
        path = path.rstrip('/') + "/#" + route_fragment
    return path


def build_api_call_id(call: "ApiCall") -> str:
    return f"{call.method} {call.path}"


def role_cookie_dict(role: dict) -> dict:
    """Extract a simple cookie jar from either supported role cookie format."""
    cookies = {}
    raw = role.get("cookies") or []
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list):
        for c in raw:
            if isinstance(c, dict) and c.get("name") is not None:
                cookies[str(c.get("name"))] = str(c.get("value", ""))
    return cookies


def replay_headers_for_call(role: dict, call: "ApiCall") -> dict:
    """Merge captured request headers with role headers and drop replay-unsafe ones."""
    captured_headers = dict(call.headers or {}) if isinstance(call.headers, dict) else {}
    captured_had_auth = any(str(k).lower() == "authorization" for k in captured_headers)
    headers = dict(captured_headers)
    for k, v in (role.get("headers") or {}).items():
        headers[k] = v

    blocked = {
        "cookie", "host", "content-length", "transfer-encoding", "connection",
        "accept-encoding", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
        "sec-fetch-user", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
        "authorization",
    }
    clean_headers = {
        str(k): str(v)
        for k, v in headers.items()
        if k and k.lower() not in blocked and not k.startswith(":")
    }

    role_auth = (role.get("headers") or {}).get("Authorization") or (role.get("headers") or {}).get("authorization")
    if role_auth:
        clean_headers["Authorization"] = str(role_auth)
    elif captured_had_auth:
        token = role_bearer_token(role)
        if token:
            clean_headers["Authorization"] = token if token.lower().startswith("bearer ") else f"Bearer {token}"

    token_candidates = role_token_candidates(role)
    for header_name in list(clean_headers.keys()):
        if CSRF_NAME_RE.search(header_name):
            replacement = best_token_candidate(token_candidates, header_name)
            if replacement:
                clean_headers[header_name] = replacement
    return clean_headers


def _walk_json_values(value, prefix=""):
    if isinstance(value, dict):
        for k, v in value.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            yield key, v
            yield from _walk_json_values(v, key)
    elif isinstance(value, list):
        for idx, item in enumerate(value[:20]):
            yield from _walk_json_values(item, f"{prefix}[{idx}]")


def _parse_storage_blob(raw_value):
    if isinstance(raw_value, dict):
        return raw_value
    if not isinstance(raw_value, str) or not raw_value:
        return {}
    try:
        parsed = json.loads(raw_value)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def role_token_candidates(role: dict) -> dict:
    """Find role-specific auth/CSRF tokens from cookies, headers, and storage."""
    candidates = {}
    for name, value in role_cookie_dict(role).items():
        if value and (AUTH_COOKIE_RE.search(name) or CSRF_NAME_RE.search(name)):
            candidates[name.lower()] = str(value)

    for k, v in (role.get("headers") or {}).items():
        if v and (AUTH_STORAGE_RE.search(str(k)) or CSRF_NAME_RE.search(str(k)) or str(k).lower() == "authorization"):
            token = str(v)
            if token.lower().startswith("bearer "):
                token = token.split(None, 1)[1]
            candidates[str(k).lower()] = token

    storage = role.get("storage") or {}
    for bucket in ("localStorage", "sessionStorage"):
        for key, value in _parse_storage_blob(storage.get(bucket, {})).items():
            if isinstance(value, str):
                stripped = value.strip()
                if (AUTH_STORAGE_RE.search(str(key)) or CSRF_NAME_RE.search(str(key))) and stripped:
                    candidates[str(key).lower()] = stripped
                if stripped.startswith(("{", "[")):
                    try:
                        nested = json.loads(stripped)
                    except Exception:
                        nested = None
                    for nested_key, nested_value in _walk_json_values(nested):
                        if isinstance(nested_value, str) and (
                            AUTH_STORAGE_RE.search(nested_key) or CSRF_NAME_RE.search(nested_key)
                        ):
                            candidates[nested_key.lower()] = nested_value
            elif isinstance(value, (dict, list)):
                for nested_key, nested_value in _walk_json_values(value):
                    if isinstance(nested_value, str) and (
                        AUTH_STORAGE_RE.search(nested_key) or CSRF_NAME_RE.search(nested_key)
                    ):
                        candidates[nested_key.lower()] = nested_value
    return candidates


def best_token_candidate(candidates: dict, token_name: str) -> Optional[str]:
    if not candidates:
        return None
    name = (token_name or "").lower()
    if "xsrf" in name:
        for k, v in candidates.items():
            if "xsrf" in k:
                return v
    if "csrf" in name:
        for k, v in candidates.items():
            if "csrf" in k:
                return v
    if "verificationtoken" in name:
        for k, v in candidates.items():
            if "verification" in k:
                return v
    for k, v in candidates.items():
        if "token" in k:
            return v
    return next(iter(candidates.values()), None)


def role_bearer_token(role: dict) -> Optional[str]:
    candidates = role_token_candidates(role)
    preferred = (
        "access_token", "access-token", "accesstoken", "jwt", "id_token", "id-token",
        "token", "authorization",
    )
    for key_name in preferred:
        for k, v in candidates.items():
            if key_name in k and v:
                return v
    return None


def replay_body_for_call(role: dict, body):
    """Replace baseline CSRF-like body fields with role-specific token values."""
    if not isinstance(body, str) or not body:
        return body
    candidates = role_token_candidates(role)
    if not candidates:
        return body

    stripped = body.strip()
    if stripped.startswith("{"):
        try:
            data = json.loads(body)
        except Exception:
            return body
        if not isinstance(data, dict):
            return body
        changed = False
        for key in list(data.keys()):
            if CSRF_NAME_RE.search(str(key)):
                replacement = best_token_candidate(candidates, str(key))
                if replacement:
                    data[key] = replacement
                    changed = True
        return json.dumps(data, separators=(",", ":")) if changed else body

    if "=" in body:
        pairs = parse_qsl(body, keep_blank_values=True)
        changed = False
        new_pairs = []
        for key, value in pairs:
            if CSRF_NAME_RE.search(key):
                replacement = best_token_candidate(candidates, key)
                if replacement:
                    value = replacement
                    changed = True
            new_pairs.append((key, value))
        return urlencode(new_pairs) if changed else body

    return body


def is_hard_skip(text: str, aria_label: str, title: str, el_id: str, el_name: str, terms=None) -> bool:
    """Returns True if element matches an always-skip destructive term."""
    combined = " ".join(filter(None, [text, aria_label, title, el_id, el_name])).lower()
    skip_terms = HARD_SKIP_TERMS if terms is None else terms
    return any(str(term).lower() in combined for term in skip_terms)


def is_auth_entry_control(text: str, aria_label: str, title: str, el_id: str, el_name: str) -> bool:
    combined = " ".join(filter(None, [text, aria_label, title, el_id, el_name]))
    return bool(AUTH_ENTRY_CONTROL_RE.search(combined or ""))


def is_risky_element(text: str, aria_label: str, title: str, el_id: str, el_name: str) -> bool:
    """Returns True if element matches a potentially risky term requiring Gemini review."""
    combined = " ".join(filter(None, [text, aria_label, title, el_id, el_name])).lower()
    return any(term in combined for term in RISKY_TERMS)


def is_modal_dismiss_identity(identity: str) -> bool:
    """Returns True if an identity string represents a close/dismiss button.

    Used by the SPA modal queue ordering to defer close buttons to the end
    so all explorable content inside a panel is visited before it is closed.
    Identity format: tag|role|id|aria_label|text|class
    """
    parts = identity.split('|')
    aria = parts[3].lower() if len(parts) > 3 else ""
    text = parts[4].lower() if len(parts) > 4 else ""
    return any(w in aria or w in text for w in ("close", "dismiss", "cancel"))


# Matches path segments that are opaque IDs: UUIDs, long hex strings, 4+ digit numbers,
# or long alphanumeric slugs (20+ chars). Used to normalize URLs for loop-prevention dedup.
_PARAM_SEG_RE = re.compile(
    r'^(?:'
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'  # UUID
    r'|[0-9a-f]{16,}'       # long hex (16+ chars)
    r'|\d{4,}'              # 4+ digit number
    r'|[A-Za-z0-9_\-]{20,}' # long opaque slug (20+ chars)
    r')$',
    re.IGNORECASE
)
_HASH_PARAM_SEG_RE = re.compile(
    r'^(?:'
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    r'|[0-9a-f]{16,}'
    r'|\d{4,}'
    r')$',
    re.IGNORECASE
)

def normalize_url_for_dedup(url):
    """Replace ID-like path/query values with {id} for crawl loop-prevention dedup."""
    parsed = urlparse(url)
    segs = parsed.path.split('/')
    norm_path = '/'.join('{id}' if _PARAM_SEG_RE.match(s) else s for s in segs)
    norm_query = ''
    if parsed.query:
        norm_pairs = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            key_lower = key.lower()
            if _PARAM_SEG_RE.match(value) or (key_lower in {"id", "uid", "user_id", "account_id", "tenant_id"} and value):
                value = "{id}"
            norm_pairs.append((key, value))
        norm_query = urlencode(sorted(norm_pairs))
    norm_fragment = ''
    route_fragment = spa_route_fragment(parsed.fragment)
    if route_fragment:
        norm_fragment = '/'.join(
            '{id}' if _HASH_PARAM_SEG_RE.match(s) else s
            for s in route_fragment.split('/')
        )
    return urlunparse(parsed._replace(path=norm_path, query=norm_query, fragment=norm_fragment))


def is_static_resource(url):
    parsed = urlparse(url)
    path = parsed.path.lower()
    return any(path.endswith(ext) for ext in IGNORED_EXTENSIONS)


def is_noise_navigation_url(url: str) -> bool:
    """Reject obvious UI-only routes that should not enter the crawl queue."""
    try:
        parsed = urlparse(url or "")
    except Exception:
        return False

    parts = [segment.lower() for segment in (parsed.path or "").split("/") if segment]
    if len(parts) >= 2 and (parts[-2], parts[-1]) in {("css", "customcss"), ("js", "customjs")}:
        return True

    route_fragment = spa_route_fragment(parsed.fragment)
    if route_fragment:
        frag_leaf = route_fragment.strip("/").split("/")[-1]
        if NON_ROUTE_FRAGMENT_RE.match(frag_leaf):
            return True
    return False


def normalize_crawl_link(link: str, base_url: str) -> Optional[str]:
    """Resolve a browser-discovered link and reject non-web schemes."""
    if not link:
        return None
    raw = str(link).strip()
    if not raw:
        return None
    raw_lower = raw.lower()
    if raw_lower.startswith((
        "javascript:", "mailto:", "tel:", "data:", "blob:",
        "sms:", "callto:", "skype:", "whatsapp:",
    )):
        return None
    if raw.startswith("#") and not spa_route_fragment(raw[1:]):
        return None
    try:
        full_url = urljoin(base_url, raw)
        parsed = urlparse(full_url)
    except Exception:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    if parsed.fragment:
        route_fragment = spa_route_fragment(parsed.fragment)
        if route_fragment:
            full_url = urlunparse(parsed._replace(fragment=route_fragment))
        else:
            full_url = urlunparse(parsed._replace(fragment=''))
    if is_noise_navigation_url(full_url):
        return None
    return full_url


AUTH_EXIT_ROUTE_SEGMENTS = {
    "login", "signin", "sign-in",
    "logout", "signout", "sign-out",
    "sessiontimeout", "session-timeout",
    "forgotusername", "forgot-username", "forgot_username",
    "forgotpassword", "forgot-password", "forgot_password",
    "resetpassword", "reset-password", "reset_password",
    "passwordreset", "password-reset", "password_reset",
    "ceklogin",
}


def is_auth_exit_url(url: str) -> bool:
    """True for login/logout/recovery routes that can kick an authenticated crawl out of the app."""
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    route_text = f"{parsed.path or ''}/{parsed.fragment or ''}".lower()
    for segment in re.split(r"[/#?&=]+", route_text):
        segment = segment.strip()
        if not segment:
            continue
        compact = segment.replace("-", "").replace("_", "")
        if segment in AUTH_EXIT_ROUTE_SEGMENTS or compact in AUTH_EXIT_ROUTE_SEGMENTS:
            return True
    return False


def is_crawlable_web_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.netloc) and not is_static_resource(url)


def role_has_authenticated_state(role: dict) -> bool:
    if not isinstance(role, dict):
        return False
    if str(role.get("name", "")).strip().lower() == "unauthenticated":
        return False
    return bool(role.get("_login") or role.get("cookies") or role.get("storage") or role.get("headers"))


def should_ignore(url, ignore_patterns):
    url_lower = url.lower()
    return any(p.lower() in url_lower for p in ignore_patterns)

def trunc(s, n=80):
    return s if len(s) <= n else s[:n] + '…'

def compact_ws(value: str, limit: int = 80) -> str:
    """Normalize whitespace in element labels used for crawler fingerprints."""
    text = re.sub(r'\s+', ' ', value or '').strip()
    return text[:limit]


def stable_dom_id(value: str) -> str:
    value = compact_ws(value, 80)
    if not value:
        return ""
    if _PARAM_SEG_RE.match(value):
        return ""
    digit_count = sum(1 for ch in value if ch.isdigit())
    if len(value) >= 16 and digit_count >= 4:
        return ""
    return value


def stable_class_tokens(class_value: str, limit: int = 6) -> str:
    """Keep useful framework classes while dropping CSS-in-JS/hash noise."""
    tokens = []
    for raw in re.split(r'\s+', class_value or ''):
        token = raw.strip()
        if not token:
            continue
        lower = token.lower()
        if lower.startswith((
            "css-", "jss", "makestyles", "emotion-", "styled-", "sc-", "_",
            "chakra-", "mantine-", "ant-", "ng-tns-", "ng-star-inserted",
        )):
            continue
        if len(token) > 36:
            continue
        if re.search(r'[a-f0-9]{8,}', lower):
            continue
        tokens.append(token)
        if len(tokens) >= limit:
            break
    return " ".join(tokens)[:120]


def build_click_identity(
    el_tag: str,
    el_role: str,
    el_id: str,
    aria_label: str,
    text: str,
    el_class: str,
    nav_target: str = "",
) -> str:
    """Stable semantic key for SPA click deduplication.

    Keep the original first six fields for existing modal/menu memory code:
    tag|role|id|aria|text|class|target
    """
    return "|".join([
        compact_ws(el_tag.lower(), 30),
        compact_ws(el_role, 40),
        stable_dom_id(el_id),
        compact_ws(aria_label, 80),
        compact_ws(text, 80),
        stable_class_tokens(el_class),
        compact_ws(nav_target, 120),
    ])


def click_identity_label(identity: str) -> str:
    parts = identity.split('|')
    for idx in (4, 3, 2, 6):
        if len(parts) > idx and parts[idx].strip():
            return parts[idx].strip()
    return identity[:80]


def click_identity_nav_target(identity: str) -> str:
    parts = identity.split('|')
    return parts[6].strip() if len(parts) > 6 else ""


def click_identity_global_key(identity: str) -> str:
    """Semantic key without route, used for persistent chrome controls across pages."""
    parts = identity.split('|')
    tag = parts[0].lower().strip() if len(parts) > 0 else ""
    role = parts[1].lower().strip() if len(parts) > 1 else ""
    el_id = parts[2].strip() if len(parts) > 2 else ""
    aria = parts[3].lower().strip() if len(parts) > 3 else ""
    text = parts[4].lower().strip() if len(parts) > 4 else ""
    el_class = parts[5].strip() if len(parts) > 5 else ""
    target = parts[6].lower().strip() if len(parts) > 6 else ""
    primary = target or aria or text
    generic_label_keys = {
        "close", "cancel", "dismiss", "ok", "moreinformation",
        "openpreferences", "closepreferences", "preferences",
    }
    context = ""
    if _alnum_lower(primary) in generic_label_keys:
        context = (stable_dom_id(el_id) or stable_class_tokens(el_class)).lower().strip()
    return f"{tag}|{role}|{primary}|{context}" if context else f"{tag}|{role}|{primary}"


def _alnum_lower(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())


def is_persistent_profile_identity(identity: str, role_name: str = "") -> bool:
    """True for account/profile controls that should be explored once per role."""
    parts = identity.split('|')
    combined = " ".join(parts[1:7]).lower()
    profile_terms = (
        "profile", "account", "avatar", "user menu", "my settings",
        "my account", "signed in", "logged in",
    )
    if any(term in combined for term in profile_terms):
        return True
    label_key = _alnum_lower(click_identity_label(identity))
    role_key = _alnum_lower(role_name)
    if not label_key or not role_key:
        return False
    if label_key == role_key:
        return True
    return len(role_key) >= 6 and (label_key in role_key or role_key in label_key)


def is_persistent_chrome_identity(identity: str, role_name: str = "") -> bool:
    """True for low-value site chrome that should not be re-explored on every page."""
    if is_persistent_profile_identity(identity, role_name):
        return True

    parts = identity.split('|')
    el_id = parts[2].lower().strip() if len(parts) > 2 else ""
    aria = parts[3].lower().strip() if len(parts) > 3 else ""
    text = parts[4].lower().strip() if len(parts) > 4 else ""
    el_class = parts[5].lower().strip() if len(parts) > 5 else ""
    target = parts[6].strip() if len(parts) > 6 else ""

    if target:
        return False

    combined = " ".join(filter(None, [el_id, aria, text, el_class]))
    chrome_terms = (
        "cookie", "consent", "privacy", "preference center", "cookie settings",
        "your privacy choices", "onetrust", "optanon", "trustarc",
    )
    if any(term in combined for term in chrome_terms):
        return True

    label_key = _alnum_lower(click_identity_label(identity))
    persistent_labels = {
        "openpreferences",
        "closepreferences",
        "cookiepreferences",
        "cookiesettings",
        "privacypreferences",
        "yourprivacychoices",
        "poweredbyonetrust",
        "poweredbyonetrustopensinanewtab",
    }
    return label_key in persistent_labels


LOW_VALUE_CODE_LABEL_RE = re.compile(
    r"^(?=.{3,48}$)(?=.*[A-Z])(?=.*\d)[A-Z0-9][A-Z0-9_.:-]*$"
)


def is_low_value_code_label(label: str) -> bool:
    """True for dense list-row codes like OPS1000 that rarely reveal new endpoints."""
    value = compact_ws(label, 80).strip()
    if not value or " " in value:
        return False
    return bool(LOW_VALUE_CODE_LABEL_RE.match(value))


def low_value_code_group(label: str) -> str:
    value = compact_ws(label, 80).upper()
    return re.sub(r"\d+", "#", value)


def click_identity_semantic_key(identity: str, page_url: str) -> str:
    parts = identity.split('|')
    route = normalize_url_for_dedup(page_url or "")
    tag = parts[0].lower().strip() if len(parts) > 0 else ""
    role = parts[1].lower().strip() if len(parts) > 1 else ""
    aria = parts[3].lower().strip() if len(parts) > 3 else ""
    text = parts[4].lower().strip() if len(parts) > 4 else ""
    target = parts[6].lower().strip() if len(parts) > 6 else ""
    primary = target or aria or text
    return f"{route}|{tag}|{role}|{primary}"


def is_nav_toggle_identity(identity: str) -> bool:
    parts = identity.split('|')
    combined = " ".join(parts[1:7]).lower()
    nav_terms = (
        "menu", "hamburger", "navigation", "navbar", "nav-", "sidenav",
        "side nav", "sidebar", "drawer", "account", "profile", "avatar",
        "user menu", "dropdown", "toggle", "collapse", "expand",
    )
    return any(term in combined for term in nav_terms)


async def page_state_signature(page: Page) -> str:
    """Small digest of route, visible controls, and text for click outcome scoring."""
    try:
        raw = await page.evaluate("""() => {
            const visible = (el) => {
                const r = el.getBoundingClientRect();
                const s = window.getComputedStyle(el);
                return r.width > 0 && r.height > 0 &&
                       r.right > 0 && r.left < window.innerWidth &&
                       r.bottom > 0 && r.top < window.innerHeight &&
                       s.display !== 'none' && s.visibility !== 'hidden' &&
                       parseFloat(s.opacity || '1') > 0.05;
            };
            const controls = [...document.querySelectorAll(
                'a[href], button, [role="button"], [role="link"], [role="menuitem"], ' +
                '[role="tab"], [onclick], [data-action], [routerlink], [ng-reflect-router-link], ' +
                '[ui-sref], [data-ui-sref], [data-route], [data-url], [data-href]'
            )].filter(visible).slice(0, 80).map((el) => [
                el.tagName,
                el.getAttribute('role') || '',
                el.getAttribute('aria-label') || '',
                el.getAttribute('href') || el.getAttribute('routerlink') ||
                    el.getAttribute('ng-reflect-router-link') ||
                    el.getAttribute('ui-sref') || el.getAttribute('data-ui-sref') ||
                    el.getAttribute('data-route') || el.getAttribute('data-url') ||
                    el.getAttribute('data-href') || '',
                (el.innerText || el.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 80)
            ].join(':')).join('|');
            const bodyText = (document.body ? document.body.innerText : '')
                .replace(/\\s+/g, ' ').trim().slice(0, 3000);
            return [location.href, document.title, controls, bodyText].join('\\n');
        }""")
        return hashlib.sha1((raw or "").encode("utf-8", errors="replace")).hexdigest()
    except Exception:
        return ""


async def assess_interaction_profile(page: Page, link_count: int = 0, api_call_count: int = 0) -> dict:
    """Decide whether a page needs SPA-style interaction without requiring --spa."""
    try:
        signals = await page.evaluate("""() => {
            const visible = (el) => {
                const r = el.getBoundingClientRect();
                const s = window.getComputedStyle(el);
                return r.width > 0 && r.height > 0 &&
                       r.right > 0 && r.left < window.innerWidth &&
                       r.bottom > 0 && r.top < window.innerHeight &&
                       s.display !== 'none' && s.visibility !== 'hidden' &&
                       parseFloat(s.opacity || '1') > 0.05;
            };
            const clickSel = 'button, [role="button"], [role="link"], [role="tab"], ' +
                '[role="menuitem"], [onclick], [data-action], [routerlink], ' +
                '[ng-reflect-router-link], [ui-sref], [data-ui-sref], [data-route], [data-url], [data-href], ' +
                'input[type="button"], input[type="submit"], .btn, .button';
            const clickables = [...document.querySelectorAll(clickSel)].filter(visible);
            const anchors = [...document.querySelectorAll('a[href]')].filter(visible);
            const routerAttrs = document.querySelectorAll(
                '[routerlink], [ng-reflect-router-link], [data-route], [data-url], ' +
                '[data-href], [ui-sref], [data-ui-sref], a[href^="#/"]'
            ).length;
            const noHrefClickables = clickables.filter((el) => {
                if (el.closest('a[href]')) return false;
                return !(el.getAttribute('href') || el.getAttribute('routerlink') ||
                         el.getAttribute('ng-reflect-router-link') ||
                         el.getAttribute('ui-sref') || el.getAttribute('data-ui-sref') ||
                         el.getAttribute('data-route') || el.getAttribute('data-url') ||
                         el.getAttribute('data-href'));
            }).length;
            const navishClickables = clickables.filter((el) => el.closest(
                'nav, [role="navigation"], [role="menubar"], .navbar, .sidebar, ' +
                '.side-nav, .sidenav, .drawer, .menu, .dropdown-menu, header'
            )).length;
            const frameworkHook = Boolean(
                window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || window.__VUE__ ||
                window.angular || window.ng || document.querySelector('[ng-version], [data-reactroot], #__next, #__nuxt')
            );
            const appRoot = Boolean(document.querySelector('#root, #app'));
            const scriptHint = [...document.scripts].some((s) =>
                /react|vue|angular|svelte|next|nuxt|vite|webpack|chunk/i.test(s.src || '')
            );
            const hashRoute = location.hash.startsWith('#/');
            return {
                clickables: clickables.length,
                anchors: anchors.length,
                routerAttrs,
                noHrefClickables,
                navishClickables,
                frameworkHook,
                appRoot,
                scriptHint,
                hashRoute
            };
        }""")
    except Exception:
        signals = {}

    score = 0
    reasons = []
    strong_framework_signal = bool(signals.get("frameworkHook"))
    app_root_signal = bool(signals.get("appRoot") and signals.get("scriptHint"))

    if strong_framework_signal:
        score += 3
        reasons.append("framework hook")
    elif app_root_signal:
        score += 2
        reasons.append("app root plus bundled JS")
    if signals.get("scriptHint") and not app_root_signal:
        score += 1
        reasons.append("bundled JS")
    if signals.get("hashRoute"):
        score += 3
        reasons.append("hash route")
    if signals.get("routerAttrs", 0) > 0:
        score += 3
        reasons.append(f"{signals.get('routerAttrs')} router/data-route attrs")
    if api_call_count > 0 and signals.get("noHrefClickables", 0) >= 3:
        score += 2
        reasons.append("XHR plus JS-only controls")
    no_href = signals.get("noHrefClickables", 0)
    anchor_count = signals.get("anchors", 0)
    if no_href >= 10 and (anchor_count <= 3 or no_href >= anchor_count * 2):
        score += 2
        reasons.append("many JS-only controls")
    if signals.get("navishClickables", 0) >= 4 and (
        signals.get("routerAttrs", 0) > 0 or strong_framework_signal or app_root_signal or signals.get("hashRoute")
    ):
        score += 1
        reasons.append("dynamic nav")

    should_interact = score >= 3
    signals.update({
        "score": score,
        "reasons": reasons,
        "should_interact": should_interact,
    })
    return signals


class MermaidGenerator:
    COLORS = [
        "#FF0000", "#0000FF", "#008000", "#FFA500", "#9400D3", "#FF1493", "#00CED1", "#8B4513"
    ]
    
    # Common background noise to ignore in authentication maps
    AUTH_IGNORE_PATTERNS = {
        "/socket.io/", "/sockjs/", "websocket", "__webpack_hmr",
        "browser-sync", "hot-update", "telemetry", "metrics",
        # Frappe/ERPNext noise
        "frappe.desk.doctype.event.event.get_events",
        "frappe.desk.doctype.notification_log.notification_log.get_notification_logs"
    }

    @staticmethod
    def generate_flowchart(workflows, custom_ignore_patterns=None):
        sb = []
        sb.append("graph TD;")
        
        # Combine default ignore patterns with any custom ones
        ignore_list = list(MermaidGenerator.AUTH_IGNORE_PATTERNS)
        if custom_ignore_patterns:
            ignore_list.extend(custom_ignore_patterns)

        common_style = "stroke-width:2px,color:black,rx:5,ry:5"
        sb.append(f"    classDef status2xx fill:#d4edda,stroke:#28a745,{common_style};")
        sb.append(f"    classDef status3xx fill:#fff3cd,stroke:#ffc107,{common_style};")
        sb.append(f"    classDef status4xx fill:#f8d7da,stroke:#dc3545,{common_style};")
        sb.append(f"    classDef status5xx fill:#e2e3e5,stroke:#6f42c1,{common_style};")
        sb.append(f"    classDef statusOther fill:#fdfdfe,stroke:#6c757d,stroke-dasharray:5 5,{common_style};\n")

        node_cache = {}
        edge_owners = {}
        global_node_counter = 1
        
        workflow_colors = {}
        sorted_labels = sorted(workflows.keys())
        for i, label in enumerate(sorted_labels):
            workflow_colors[label] = MermaidGenerator.COLORS[i % len(MermaidGenerator.COLORS)]

        for flow_label, requests in workflows.items():
            previous_node_id = None
            current_subgraph = None
            
            for req in requests:
                # Check for Phase Markers (SSO)
                if req.get('type') == 'marker':
                    # Close previous subgraph if open
                    if current_subgraph:
                        sb.append("    end")
                    
                    # Start new subgraph — include the role label in the ID so that
                    # identical phase names across multiple roles don't produce duplicate
                    # subgraph IDs (which cause Mermaid rendering errors).
                    phase_label = req.get('label', 'Phase')
                    safe_phase = "".join(c if c.isalnum() else "_" for c in f"{flow_label}_{phase_label}")
                    sb.append(f"    subgraph {safe_phase} [{phase_label}]")
                    sb.append(f"    direction TB")
                    current_subgraph = safe_phase
                    continue

                method = req['method']
                url = req['url']
                parsed_url = urlparse(url)
                host = parsed_url.netloc
                path = parsed_url.path
                if not path: path = "/"
                status = req['status']
                
                # Filter out background noise
                if any(p.lower() in url.lower() for p in ignore_list):
                    continue

                # Data Extraction
                req_params = MermaidGenerator.get_param_keys(req)
                cookies_sent = MermaidGenerator.get_header_keys(req['request_headers'], "cookie")
                cookies_set = MermaidGenerator.get_header_keys(req['response_headers'], "set-cookie")
                resp_keys = MermaidGenerator.format_list(req.get('response_body_keys', []))
                js_cookies = MermaidGenerator.format_list(req.get('js_cookies', []))
                location = ""
                loc_val = req['response_headers'].get('location', '')
                if loc_val:
                    parsed_loc = urlparse(loc_val)
                    location = parsed_loc.path + ("?" + parsed_loc.query[:80] if parsed_loc.query else "")

                # Unique Key for Merging (Include auth-relevant shape so
                # role-specific params/cookie/token differences do not collapse).
                unique_key = "|".join([
                    method, host, path, str(status), req_params, cookies_set,
                    resp_keys, js_cookies, location,
                ])
                
                if unique_key in node_cache:
                    current_node_id = node_cache[unique_key]
                else:
                    current_node_id = f"N{global_node_counter}"
                    global_node_counter += 1
                    node_cache[unique_key] = current_node_id
                    
                    # Build Label
                    label = []
                    label.append(f"<div style='font-size: 1.1em; font-weight: 900; margin-bottom: 4px;'>{method} {trunc(path, 80)}</div>")
                    label.append(f"Host: <b>{host}</b><br/>")
                    label.append(f"Status: <b>{status}</b>")

                    code_style = "font-family: Consolas, monospace; font-size: 0.9em; background: rgba(255,255,255,0.6); border: 1px solid #aaa; padding: 2px 4px; display: block; margin-top: 2px; border-radius: 3px; text-align: left;"
                    header_style = "font-weight: bold; font-size: 0.9em; margin-top: 6px; display: block; text-decoration: underline;"

                    if req_params:
                        label.append(f"<span style='{header_style}'>Params:</span><span style='{code_style}'>{trunc(req_params)}</span>")
                    if cookies_sent:
                        label.append(f"<span style='{header_style}'>Cookies Sent:</span><span style='{code_style}'>{trunc(cookies_sent)}</span>")
                    if cookies_set:
                        label.append(f"<span style='{header_style}'>Cookies Set:</span><span style='{code_style}'>{trunc(cookies_set)}</span>")
                    if resp_keys:
                        label.append(f"<span style='{header_style}'>Response Keys:</span><span style='{code_style}'>{trunc(resp_keys)}</span>")
                    if js_cookies:
                        label.append(f"<span style='{header_style}'>JS Cookies Set:</span><span style='{code_style}'>{trunc(js_cookies)}</span>")
                    if location:
                        label.append(f"<span style='{header_style}'>Redirects To:</span><span style='{code_style}'>{trunc(location)}</span>")

                    label_str = "".join(label).replace('"', "'")
                    sb.append(f"    {current_node_id}[\"{label_str}\"];")
                    
                    if 200 <= status < 300: sb.append(f"    class {current_node_id} status2xx;")
                    elif 300 <= status < 400: sb.append(f"    class {current_node_id} status3xx;")
                    elif 400 <= status < 500: sb.append(f"    class {current_node_id} status4xx;")
                    elif 500 <= status < 600: sb.append(f"    class {current_node_id} status5xx;")
                    else: sb.append(f"    class {current_node_id} statusOther;")

                if previous_node_id and previous_node_id != current_node_id:
                    edge_key = f"{previous_node_id}->{current_node_id}"
                    if edge_key not in edge_owners:
                        edge_owners[edge_key] = []
                    if flow_label not in edge_owners[edge_key]:
                        edge_owners[edge_key].append(flow_label)
                
                previous_node_id = current_node_id
            
            # Close any lingering subgraph for this flow
            if current_subgraph:
                sb.append("    end")

        # Render Edges
        link_index = 0
        for edge_key, owners in edge_owners.items():
            parts = edge_key.split("->")
            for owner in owners:
                sb.append(f"    {parts[0]} --> {parts[1]};")
                color = workflow_colors.get(owner, "#333")
                sb.append(f"    linkStyle {link_index} stroke:{color},stroke-width:3px;")
                link_index += 1

        # Legend
        sb.append("\n    subgraph Legend [Legend]")
        sb.append("    direction LR")
        for label, color in workflow_colors.items():
            safe_label = "".join(c if c.isalnum() else "_" for c in label)
            sb.append(f"    L_{safe_label}(\"{label}\"):::legend{safe_label};")
            sb.append(f"    classDef legend{safe_label} fill:white,stroke:{color},stroke-width:3px;")
        sb.append("    end\n")

        return "\n".join(sb)

    @staticmethod
    def get_param_keys(req):
        keys = set()
        # URL Params
        parsed = urlparse(req['url'])
        if parsed.query:
            for pair in parsed.query.split('&'):
                if '=' in pair:
                    keys.add(pair.split('=')[0])
        
        # Body Params (JSON or Form)
        body = req.get('post_data')
        if body:
            if body.startswith('{'):
                try:
                    data = json.loads(body)
                    keys.update(data.keys())
                except Exception: pass
            elif '=' in body:
                for pair in body.split('&'):
                    if '=' in pair:
                        keys.add(pair.split('=')[0])
        
        return MermaidGenerator.format_list(keys)

    @staticmethod
    def get_header_keys(headers, target_header):
        keys = set()
        # Attributes to explicitly ignore if they somehow get parsed as keys
        ignore_list = {'path', 'domain', 'max-age', 'expires', 'samesite', 'httponly', 'secure', 'priority', 'size'}
        
        if isinstance(headers, dict):
            for k, v in headers.items():
                if k.lower() == target_header.lower():
                    if target_header.lower() == 'set-cookie':
                        # Playwright merges multiple Set-Cookie headers with newlines
                        # We iterate over each cookie line
                        cookie_lines = v.split('\n')
                        for line in cookie_lines:
                            # The cookie name=value is always the first part before any semicolon
                            main_part = line.split(';')[0]
                            if '=' in main_part:
                                key = main_part.split('=')[0].strip()
                                if key.lower() not in ignore_list:
                                    keys.add(key)
                    else:
                        # Standard Cookie header (request): name=val; name2=val2
                        parts = v.split(';')
                        for part in parts:
                            if '=' in part:
                                key = part.split('=')[0].strip()
                                if key.lower() not in ignore_list:
                                    keys.add(key)
        return MermaidGenerator.format_list(keys)

    @staticmethod
    def format_list(keys):
        sorted_keys = sorted(list(keys))
        return ", ".join(sorted_keys)

def _interact_and_collect_links(links, allowed_domains, discovered_endpoints, visited, to_visit, visited_normalized, skip_auth_exit=False):
    """Add discovered nav links to the crawl queue, deduplicating against what's already known."""
    for _nl in links:
        _np = urlparse(_nl)
        if _np.netloc in allowed_domains and is_crawlable_web_url(_nl):
            if skip_auth_exit and is_auth_exit_url(_nl):
                continue
            _npath = endpoint_from_url(_nl)
            discovered_endpoints.add(_npath)
            if _nl not in visited and _nl not in to_visit and normalize_url_for_dedup(_nl) not in visited_normalized:
                to_visit.append(_nl)


def _normalize_cookies(cookies, domain: str) -> list:
    """Normalise a cookies config entry (dict or list) into a list of Playwright cookie dicts."""
    result = []
    if isinstance(cookies, dict):
        for name, value in cookies.items():
            result.append({'name': name, 'value': str(value), 'domain': domain, 'path': '/'})
    elif isinstance(cookies, list):
        for c in cookies:
            c = dict(c)  # don't mutate original
            if 'domain' not in c:
                c['domain'] = domain
            if 'path' not in c:
                c['path'] = '/'
            result.append(c)
    return result


def load_existing_map(filepath):
    """
    Loads endpoints and role visibility from an existing XLSX or CSV map.
    Returns: (all_endpoints, role_findings)
    """
    all_endpoints = set()
    role_findings = {} # {role_name: set(endpoints)}
    
    lower_path = filepath.lower()

    if lower_path.endswith('.xlsx'):
        if not openpyxl:
            logger.error("openpyxl module required for XLSX import.")
            sys.exit(1)
        try:
            wb = openpyxl.load_workbook(filepath)
            ws = wb.active
            rows = list(ws.iter_rows(values_only=True))
            if not rows: return set(), {}
            
            headers = rows[0]
            role_names = headers[1:] # Skip "Endpoint"
            
            # Initialize sets
            for r in role_names: 
                if r: role_findings[str(r)] = set()
            
            for row in rows[1:]:
                endpoint = row[0]
                if not endpoint: continue
                all_endpoints.add(endpoint)
                
                for idx, cell_val in enumerate(row[1:]):
                    if idx < len(role_names) and cell_val: # If cell has content (X, VULN, etc)
                        role_name = str(role_names[idx])
                        role_findings[role_name].add(endpoint)
                        
        except Exception as e:
            logger.error(f"Failed to load XLSX map: {e}")
            sys.exit(1)

    elif lower_path.endswith('.csv'):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                headers = next(reader, None)
                if not headers: return set(), {}
                
                role_names = headers[1:]
                for r in role_names:
                    if r: role_findings[r] = set()
                
                for row in reader:
                    if not row: continue
                    endpoint = row[0]
                    if not endpoint: continue
                    all_endpoints.add(endpoint)
                    
                    for idx, cell_val in enumerate(row[1:]):
                        if idx < len(role_names) and cell_val:
                            role_name = role_names[idx]
                            role_findings[role_name].add(endpoint)
        except Exception as e:
            logger.error(f"Failed to load CSV map: {e}")
            sys.exit(1)
    else:
        logger.error("Unsupported file format. Use .xlsx or .csv")
        sys.exit(1)
        
    return all_endpoints, role_findings

async def probe_clickable_rows(page: Page, base_url: str, max_rows: int = 25) -> list:
    """
    Discovers URLs hidden behind clickable table rows (tr[tabindex="0"], etc.)
    by clicking each one, capturing the resulting URL, then navigating back.
    Returns a list of absolute URLs discovered.
    """
    ROW_SELECTOR = 'tr[tabindex="0"], [data-slot="table-row"][tabindex="0"], tr[role="row"][tabindex="0"]'
    discovered = []
    origin = urlparse(base_url).netloc

    try:
        row_count = await page.locator(ROW_SELECTOR).count()
    except Exception:
        return []

    if row_count == 0:
        return []

    logger.info(f"probe_clickable_rows: found {row_count} clickable row(s), probing up to {max_rows}")

    async def _try_activate(row, url_before):
        """Try focus+Enter, then click, then click first cell. Return new URL or None."""
        for attempt in ['enter', 'click', 'cell']:
            try:
                if attempt == 'enter':
                    await row.focus(timeout=TIMEOUT_LONG)
                    await page.keyboard.press("Enter")
                elif attempt == 'click':
                    await row.click(timeout=TIMEOUT_LONG)
                else:
                    cell = row.locator('td, [data-slot="table-cell"]').first
                    await cell.click(timeout=TIMEOUT_LONG)

                try:
                    await page.wait_for_url(lambda u: u != url_before, timeout=TIMEOUT_LONG)
                except Exception:
                    pass

                if page.url != url_before:
                    return page.url
            except Exception:
                pass
        return None

    for i in range(min(row_count, max_rows)):
        url_before = page.url
        try:
            row = page.locator(ROW_SELECTOR).nth(i)
            url_after = await _try_activate(row, url_before)
            if url_after:
                parsed = urlparse(url_after)
                if parsed.netloc == origin and not is_static_resource(url_after):
                    discovered.append(url_after)
                await page.go_back(wait_until="domcontentloaded", timeout=10000)
                await page.wait_for_timeout(500)
        except Exception as e:
            logger.debug(f"probe_clickable_rows: row {i} failed: {e}")
            try:
                if page.url != url_before:
                    await page.go_back(wait_until="domcontentloaded", timeout=10000)
            except Exception:
                pass

    return discovered


async def extract_links(page: Page, base_url: str):
    """
    Extract visible links and framework routes in one DOM evaluation.
    This avoids slow locator-by-locator anchor reads on constantly re-rendering SPAs.
    """
    # 1. Try Smart JS Extraction
    try:
        links = await page.evaluate("""() => {
            const urls = new Set();
            const isHashRouting = window.location.hash !== '';
            const nonRouteAnchors = new Set(['top', 'bottom', 'header', 'footer', 'content', 'main', 'nav', 'navbar', 'navigation', 'menu']);
            const uiOnlyHashPat = /^(collapse|accordion|panel|tab|section|modal|drawer|tooltip|popover)[a-z0-9_-]*$/i;

            const routeishHash = (hashValue) => {
                if (!hashValue) return false;
                let value = String(hashValue).trim();
                if (value.startsWith('#')) value = value.slice(1);
                if (value.startsWith('!')) value = value.slice(1);
                if (!value) return false;
                if (value.startsWith('/')) return true;
                const bare = value.replace(/^\\//, '');
                if (uiOnlyHashPat.test(bare)) return false;
                const compact = value.toLowerCase().replace(/[-_]/g, '');
                if (nonRouteAnchors.has(compact)) return false;
                if (value.includes('/')) return true;
                return /^[A-Za-z][A-Za-z0-9_.~-]{2,}$/.test(value) &&
                    (/[A-Z]/.test(value) || value.includes('.') || value.includes('-') || value.includes('_'));
            };

            const uiStateToHash = (value) => {
                if (!value) return '';
                let state = String(value).trim().split('(')[0].trim();
                if (!state) return '';
                if (state.startsWith('#')) return state;
                if (state.startsWith('/')) return '#' + state;
                return '#/' + state.replace(/\\./g, '/');
            };
            
            const addUrl = (val) => {
                if (!val) return;
                val = String(val).trim();
                if (!val) return;
                const lower = val.toLowerCase();
                if (lower.startsWith('javascript:') || lower.startsWith('mailto:') ||
                    lower.startsWith('tel:') || lower.startsWith('data:') ||
                    lower.startsWith('blob:')) return;
                // Handle SPA routes (#/Tools, #Tools, index#/Tools, index#TestLockout/0)
                // while ignoring ordinary UI anchors (e.g., #navbar-collapse).
                if (val.startsWith('#')) {
                    if (routeishHash(val)) {
                        const route = val.startsWith('#/') ? val : '#/' + val.replace(/^#!/, '').replace(/^#/, '').replace(/^\\//, '');
                        urls.add(window.location.origin + window.location.pathname + route);
                    }
                    return;
                }
                if (val.includes('#')) {
                    const hashPart = val.slice(val.indexOf('#') + 1);
                    if (routeishHash(hashPart)) {
                        urls.add(val);
                    }
                    return;
                }
                if (val.startsWith('/') || val.startsWith('http') ||
                    val.startsWith('./') || val.startsWith('../')) {
                    urls.add(val);
                    return;
                }
                // Framework router attrs frequently contain relative routes like
                // "users/1/edit" or "settings/profile" with no leading slash.
                if (/^[A-Za-z0-9_.~%-]+(?:\\/[A-Za-z0-9_.~%?&=:-]+)+\\/?$/.test(val) ||
                    /^[A-Za-z0-9_.~%-]+\\?[A-Za-z0-9_.~%&=:-]+$/.test(val)) {
                    urls.add(val);
                }
            };

            // Standard anchors and areas
            document.querySelectorAll('a[href], area[href]').forEach(a => addUrl(a.getAttribute('href')));
            
            // Buttons with formaction
            document.querySelectorAll('button[formaction]').forEach(b => addUrl(b.getAttribute('formaction')));
            
            // Framework attributes (Angular, Vue, React routers)
            const specificAttrs = [
                'data-href', 'data-url', 'data-route', 'data-link',
                'ng-href', 'ui-sref', 'data-ui-sref',
                'router-link', 'routerlink', 'ng-reflect-router-link', 'to'
            ];
            
            document.querySelectorAll('*').forEach(el => {
                specificAttrs.forEach(attr => {
                    if (el.hasAttribute(attr)) {
                        let val = el.getAttribute(attr);
                        if (val) {
                            if (attr === 'ui-sref' || attr === 'data-ui-sref') {
                                addUrl(uiStateToHash(val));
                                return;
                            }
                            // If it's an Angular-style route and we're in a hash-routing app, normalize it
                            if (isHashRouting && (attr.includes('router') || attr.includes('to')) && val.startsWith('/') && !val.startsWith('#')) {
                                addUrl('#' + val);
                            } else {
                                addUrl(val);
                            }
                        }
                    }
                });
                
                // Onclick handlers — location.href, location.assign, location.replace, window.open
                const click = el.getAttribute('onclick');
                if (click) {
                    const locPat = /(?:window\\.)?location(?:\\.href|\\.assign|\\.replace)?\\s*[=|(]\\s*['"](.*?)['"]/gi;
                    const openPat = /window\\.open\\s*\\(\\s*['"](.*?)['"]/gi;
                    let m;
                    while ((m = locPat.exec(click)) !== null) addUrl(m[1]);
                    while ((m = openPat.exec(click)) !== null) addUrl(m[1]);
                }

                // Role=link (ARIA)
                if (el.getAttribute('role') === 'link') {
                     const href = el.getAttribute('href') || el.getAttribute('data-href');
                     if (href) addUrl(href);
                }
            });

            // Form actions (reveals endpoint paths even without submitting)
            document.querySelectorAll('form[action]').forEach(f => {
                const action = f.getAttribute('action');
                if (action && !action.startsWith('javascript')) addUrl(action);
            });

            // Frames and iframes
            document.querySelectorAll('frame[src], iframe[src]').forEach(f => {
                addUrl(f.getAttribute('src'));
            });

            return Array.from(urls);
        }""")
    except Exception as e:
        logger.warning(f"Smart link extraction failed: {e}")
        links = []

    # Clean and Resolve
    cleaned_links = set()
    for link in links:
        try:
            full_url = normalize_crawl_link(link, base_url)
            if full_url:
                cleaned_links.add(full_url)
        except Exception: continue
        
    return cleaned_links


async def extract_form_candidates(page: Page, base_url: str, role_name: str) -> list[EndpointCandidate]:
    """Inventory forms and fields without submitting them."""
    try:
        forms = await page.evaluate("""() => [...document.forms].map((form) => ({
            action: form.getAttribute('action') || location.href,
            method: (form.getAttribute('method') || 'GET').toUpperCase(),
            fields: [...form.querySelectorAll('input[name], select[name], textarea[name], button[name]')]
                .map((el) => ({
                    name: el.getAttribute('name') || '',
                    type: (el.getAttribute('type') || el.tagName || 'string').toLowerCase()
                }))
                .filter((item) => item.name)
        }))""")
    except Exception:
        return []

    candidates = []
    for form in forms or []:
        try:
            action = urljoin(base_url, str(form.get("action") or base_url))
            schema = {str(item.get("name")): str(item.get("type") or "string") for item in form.get("fields", [])}
            candidates.append(EndpointCandidate.build(
                method=str(form.get("method") or "GET").upper(),
                raw_url=action,
                source="html_form",
                evidence=f"Form with {len(schema)} named field(s)",
                role=role_name,
                discovered_from=base_url,
                observed=False,
                validated=False,
                confidence="HIGH",
                request_body_schema=schema or None,
            ))
        except Exception:
            continue
    return candidates


async def extract_embedded_links(page: Page, base_url: str) -> set[str]:
    """Extract routes from child frames and recursively-open shadow roots."""
    links = set()
    try:
        for frame in page.frames:
            if frame == page.main_frame:
                continue
            links.update(await extract_links(frame, frame.url or base_url))
    except Exception:
        pass
    try:
        shadow_values = await page.evaluate("""() => {
            const values = new Set();
            const attrs = ['href', 'action', 'formaction', 'routerlink', 'ng-reflect-router-link',
                           'data-href', 'data-url', 'data-route', 'ui-sref', 'data-ui-sref'];
            const visit = (root) => {
                for (const el of root.querySelectorAll('*')) {
                    for (const attr of attrs) {
                        const value = el.getAttribute && el.getAttribute(attr);
                        if (value) values.add(value);
                    }
                    if (el.shadowRoot) visit(el.shadowRoot);
                }
            };
            visit(document);
            return [...values];
        }""")
        for value in shadow_values or []:
            normalized = normalize_crawl_link(value, base_url)
            if normalized:
                links.add(normalized)
    except Exception:
        pass
    return links


SAFE_FILTER_RE = re.compile(
    r"\b(filter|search|status|type|region|country|year|quarter|period|category|page|page size|sort)\b",
    re.IGNORECASE,
)


async def probe_safe_filter_selects(page: Page, role_name: str, recon_inventory: ReconInventory, max_options: int = 8) -> None:
    """Exercise clearly query-like native selects and restore their original value."""
    try:
        selects = await page.locator("select").all()
    except Exception:
        return
    for select in selects[:20]:
        try:
            if not await select.is_visible():
                continue
            metadata = await select.evaluate("""el => {
                const label = el.labels && el.labels.length ? [...el.labels].map(x => x.innerText).join(' ') : '';
                const form = el.closest('form');
                return {
                    descriptor: [label, el.name, el.id, el.getAttribute('aria-label'), el.getAttribute('placeholder')]
                        .filter(Boolean).join(' '),
                    formMethod: form ? (form.getAttribute('method') || 'GET').toUpperCase() : 'GET',
                    original: el.value,
                    values: [...el.options].filter(o => !o.disabled).map(o => o.value)
                };
            }""")
            if metadata.get("formMethod") not in {"GET", ""}:
                continue
            if not SAFE_FILTER_RE.search(metadata.get("descriptor") or ""):
                continue
            original = metadata.get("original")
            tried = 0
            for value in metadata.get("values", []):
                if value == original or tried >= max_options:
                    continue
                await select.select_option(value=value, timeout=TIMEOUT_MEDIUM)
                await page.wait_for_timeout(400)
                tried += 1
                recon_inventory.ui_metrics["safe_filter_options_explored"] = recon_inventory.ui_metrics.get("safe_filter_options_explored", 0) + 1
            if original is not None:
                await select.select_option(value=original, timeout=TIMEOUT_MEDIUM)
                await page.wait_for_timeout(250)
        except Exception as exc:
            logger.debug(f"[{role_name}] Safe filter select probe skipped: {exc}")


async def probe_lazy_scroll(page: Page, recon_inventory: ReconInventory, max_steps: int = 4) -> None:
    """Trigger bounded viewport and overflow-container lazy loading, then restore position."""
    try:
        result = await page.evaluate("""async (maxSteps) => {
            const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
            const originalY = window.scrollY;
            let steps = 0;
            let previousHeight = document.documentElement.scrollHeight;
            for (let i = 1; i <= maxSteps; i++) {
                const height = document.documentElement.scrollHeight;
                if (height <= window.innerHeight + 50) break;
                window.scrollTo(0, Math.min(height, Math.floor(height * i / maxSteps)));
                await sleep(350);
                steps++;
                const newHeight = document.documentElement.scrollHeight;
                if (i > 1 && newHeight === previousHeight && window.scrollY + window.innerHeight >= newHeight - 20) break;
                previousHeight = newHeight;
            }
            const containers = [...document.querySelectorAll('*')].filter((el) => {
                const style = getComputedStyle(el);
                return /(auto|scroll)/.test(style.overflowY || '') && el.scrollHeight > el.clientHeight * 1.5;
            }).slice(0, 5);
            for (const el of containers) {
                el.scrollTop = el.scrollHeight;
                await sleep(300);
                el.scrollTop = 0;
                steps++;
            }
            window.scrollTo(0, originalY);
            return steps;
        }""", max_steps)
        if result:
            recon_inventory.ui_metrics["lazy_scroll_steps"] = recon_inventory.ui_metrics.get("lazy_scroll_steps", 0) + int(result)
    except Exception:
        return

def load_prompts(path="prompts.md"):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        prompts = {}
        current_section = None
        for line in content.splitlines():
            if line.strip().startswith("## "):
                current_section = line.strip()[3:]
                prompts[current_section] = ""
            elif current_section:
                prompts[current_section] += line + "\n"
        return prompts
    except FileNotFoundError:
        return {}


def _extract_openai_text(data: dict) -> str:
    if data.get("output_text"):
        return data["output_text"]
    parts = []
    for item in data.get("output", []) or []:
        for content in item.get("content", []) or []:
            if content.get("type") in ("output_text", "text"):
                parts.append(content.get("text", ""))
    return "\n".join(p for p in parts if p)


def _extract_anthropic_text(data: dict) -> str:
    parts = []
    for content in data.get("content", []) or []:
        if content.get("type") == "text":
            parts.append(content.get("text", ""))
    return "\n".join(p for p in parts if p)


def _response_error_message(response, provider: str) -> str:
    retry_after = response.headers.get("retry-after") or response.headers.get("Retry-After") or ""
    request_id = (
        response.headers.get("request-id")
        or response.headers.get("x-request-id")
        or response.headers.get("cf-ray")
        or ""
    )
    try:
        body = response.text
    except Exception:
        body = ""
    body = (body or "").replace("\r", " ").replace("\n", " ")[:1200]
    bits = [f"{provider} HTTP {response.status_code} {response.reason}"]
    if retry_after:
        bits.append(f"retry-after={retry_after}")
    if request_id:
        bits.append(f"request-id={request_id}")
    if body:
        bits.append(f"body={body}")
    return "; ".join(bits)


def _raise_for_status_with_body(response, provider: str):
    if response.status_code >= 400:
        raise RuntimeError(_response_error_message(response, provider))


def _find_balanced_json_object(text: str) -> str:
    start = text.find("{")
    if start < 0:
        return ""

    depth = 0
    in_string = False
    escaped = False
    for idx in range(start, len(text)):
        ch = text[idx]
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:idx + 1]
    return ""


def _json_from_llm_text(response_text: str) -> dict:
    """Parse model JSON even when wrapped in markdown or explanatory text."""
    raw = (response_text or "").strip()
    candidates = [raw]
    if raw.startswith("```"):
        fenced = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE)
        fenced = re.sub(r"\s*```$", "", fenced)
        candidates.insert(0, fenced.strip())
    balanced = _find_balanced_json_object(raw)
    if balanced:
        candidates.insert(0, balanced)

    last_error = None
    for candidate in candidates:
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError as e:
            last_error = e
    if last_error:
        raise last_error
    raise json.JSONDecodeError("No JSON object found in model response", raw, 0)


def _normalize_confidence(value) -> str:
    confidence = str(value or "LOW").upper()
    if confidence in {"HIGH", "MEDIUM", "LOW"}:
        return confidence
    if confidence in {"CERTAIN", "FIRM"}:
        return "HIGH"
    if confidence in {"TENTATIVE", "INFO", "INFORMATION"}:
        return "LOW"
    return "LOW"


def _normalize_severity(value) -> str:
    severity = str(value or "Information").strip().title()
    if severity == "Critical":
        return "High"
    if severity in {"High", "Medium", "Low", "Information"}:
        return severity
    return "Information"


def _parse_llm_verdict(response_text: str):
    try:
        result = _json_from_llm_text(response_text)
        verdict = str(result.get("verdict", "UNKNOWN")).upper()
        if verdict not in {"VULNERABLE", "SUSPICIOUS", "SAFE", "UNKNOWN"}:
            verdict = "UNKNOWN"
        confidence = _normalize_confidence(result.get("confidence", "LOW"))
        reason = str(result.get("reason", "No reason provided by AI"))
        severity = _normalize_severity(result.get("severity", "Information"))
        return verdict, confidence, reason, severity
    except (json.JSONDecodeError, AttributeError, TypeError) as e:
        upper_text = (response_text or "").upper()
        verdict_match = re.search(r'"?VERDICT"?\s*[:=]\s*"?([A-Z]+)"?', upper_text)
        verdict = verdict_match.group(1) if verdict_match else "UNKNOWN"
        if verdict not in {"VULNERABLE", "SUSPICIOUS", "SAFE", "UNKNOWN"}:
            if re.search(r"\bVULNERABLE\b", upper_text):
                verdict = "VULNERABLE"
            elif re.search(r"\bSUSPICIOUS\b", upper_text):
                verdict = "SUSPICIOUS"
            elif re.search(r"\bSAFE\b", upper_text):
                verdict = "SAFE"
            else:
                verdict = "UNKNOWN"
        return verdict, "LOW", f"Failed to parse JSON response from AI: {e}", "Information"


def _call_openai_verify(api_key: str, model: str, prompt: str) -> str:
    if requests is None:
        raise RuntimeError("requests module not installed")
    response = requests.post(
        "https://api.openai.com/v1/responses",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "input": prompt,
            "text": {"format": {"type": "json_object"}},
        },
        timeout=60,
    )
    _raise_for_status_with_body(response, "openai")
    return _extract_openai_text(response.json())


def _call_anthropic_verify(api_key: str, model: str, prompt: str) -> str:
    if requests is None:
        raise RuntimeError("requests module not installed")
    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": 1024,
            "temperature": 0,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=60,
    )
    _raise_for_status_with_body(response, "anthropic")
    return _extract_anthropic_text(response.json())


def build_verify_client(config: dict, gemini_client=None):
    provider = str(config.get("verify_provider", "gemini")).lower().strip()
    if provider in ("", "gemini", "google"):
        return gemini_client
    if provider == "openai":
        key = config.get("openai_api_key")
        if not key:
            logger.warning("verify_provider=openai but openai_api_key is missing; falling back to Gemini verifier.")
            return gemini_client
        return {"provider": "openai", "api_key": key}
    if provider in ("anthropic", "claude"):
        key = config.get("anthropic_api_key")
        if not key:
            logger.warning("verify_provider=anthropic but anthropic_api_key is missing; falling back to Gemini verifier.")
            return gemini_client
        return {"provider": "anthropic", "api_key": key}
    logger.warning(f"Unknown verify_provider={provider!r}; falling back to Gemini verifier.")
    return gemini_client


def verify_model_name(config: dict) -> str:
    provider = str(config.get("verify_provider", "gemini")).lower().strip()
    if provider == "openai":
        return config.get("openai_verify_model", "gpt-5.2")
    if provider in ("anthropic", "claude"):
        return config.get("anthropic_verify_model", "claude-sonnet-4-20250514")
    return config.get("gemini_verify_model", config.get("gemini_model", "gemini-1.5-flash"))


def _verifier_provider_name(config: dict, verify_client=None) -> str:
    if isinstance(verify_client, dict):
        return str(verify_client.get("provider") or "").lower()
    provider = str(config.get("verify_provider", "gemini")).lower().strip()
    if provider in ("", "google"):
        return "gemini"
    if provider == "claude":
        return "anthropic"
    return provider


def verifier_ai_concurrency(config: dict, verify_client=None) -> int:
    provider = _verifier_provider_name(config, verify_client)
    default = 1 if provider == "openai" else 2 if provider == "anthropic" else 3
    try:
        value = int(config.get("verify_ai_concurrency", default))
    except (TypeError, ValueError):
        value = default
    return max(1, value)


def verifier_ai_delay_ms(config: dict, verify_client=None) -> int:
    provider = _verifier_provider_name(config, verify_client)
    default = 1500 if provider == "openai" else 500 if provider == "anthropic" else 0
    try:
        value = int(config.get("verify_ai_delay_ms", default))
    except (TypeError, ValueError):
        value = default
    return max(0, value)


class AsyncRequestSpacer:
    def __init__(self, delay_ms: int):
        self.delay = max(0.0, delay_ms / 1000.0)
        self.lock = asyncio.Lock()
        self.next_allowed = 0.0

    async def wait(self):
        if self.delay <= 0:
            return
        async with self.lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            if now < self.next_allowed:
                await asyncio.sleep(self.next_allowed - now)
            self.next_allowed = loop.time() + self.delay


def _retry_after_seconds(error_text: str) -> Optional[float]:
    match = re.search(r"retry-after=([0-9.]+)", error_text or "", re.IGNORECASE)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def _response_header_value(resp_str: str, header_name: str) -> str:
    name = header_name.lower()
    for line in (resp_str or "").splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        if k.lower().strip() == name:
            return v.strip()
    return ""


def build_verifier_metadata(endpoint: str, base_status, base_url: str, base_body: str,
                            test_status, test_url: str, test_body: str,
                            base_resp: str = "", test_resp: str = "",
                            kind: str = "page") -> str:
    target_abs = endpoint
    if re.match(r"^[A-Z]+\s+", endpoint or ""):
        target_path = (endpoint or "").split(None, 1)[1]
    else:
        target_path = endpoint_from_url(endpoint) if endpoint.startswith(("http://", "https://")) else endpoint
    tags = []
    if HIGH_RISK_ENDPOINT_RE.search(endpoint or ""):
        tags.append("high_risk_route")
    if _high_risk_route_severity(endpoint) == "High":
        tags.append("action_or_management_route")
    elif HIGH_RISK_ENDPOINT_RE.search(endpoint or ""):
        tags.append("report_or_business_data_route")
    if is_soft_403(test_body):
        tags.append("test_soft_403")
    if _is_login_url(test_url):
        tags.append("test_login_redirect")
    if _test_stayed_on_target(target_path, test_url):
        tags.append("test_stayed_on_target")
    else:
        tags.append("test_final_url_differs")

    return "\n".join([
        f"Kind: {kind}",
        f"Target endpoint/path: {target_path}",
        f"Target URL: {target_abs}",
        f"Baseline final URL: {base_url}",
        f"Test final URL: {test_url}",
        f"Baseline body length: {len(base_body or '')}",
        f"Test body length: {len(test_body or '')}",
        f"Baseline content-type: {_response_header_value(base_resp, 'content-type') or 'unknown'}",
        f"Test content-type: {_response_header_value(test_resp, 'content-type') or 'unknown'}",
        f"Route tags: {', '.join(tags) if tags else 'none'}",
        f"Status comparison: baseline={base_status}, test={test_status}",
    ])


async def verify_with_llm(client, model, prompt_template, url, base_role, base_status, base_content, test_role, test_status, test_content, all_role_names=None, retries=3, request_spacer=None, metadata=""):
    if not client: return "UNKNOWN", "Low", "AI Client not initialized", "Information"

    roles_str = ", ".join(all_role_names) if all_role_names else base_role
    base_text = str(base_content or "")
    test_text = str(test_content or "")
    prompt = prompt_template.format(
        url=url,
        baseline_role=base_role,
        test_role=test_role,
        all_roles=roles_str,
        base_status=base_status,
        base_content=base_text[:8000], # Truncate to avoid context limits
        test_status=test_status,
        test_content=test_text[:8000],
        metadata=metadata or "None"
    )

    for attempt in range(retries):
        try:
            if request_spacer is not None:
                await request_spacer.wait()

            if isinstance(client, dict):
                provider = client.get("provider")
                if provider == "openai":
                    response_text = await asyncio.wait_for(
                        asyncio.to_thread(_call_openai_verify, client["api_key"], model, prompt),
                        timeout=75
                    )
                elif provider == "anthropic":
                    response_text = await asyncio.wait_for(
                        asyncio.to_thread(_call_anthropic_verify, client["api_key"], model, prompt),
                        timeout=75
                    )
                else:
                    raise RuntimeError(f"Unsupported verifier provider: {provider}")
            else:
                response = await asyncio.wait_for(
                    asyncio.to_thread(
                        client.models.generate_content,
                        model=model,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            response_mime_type='application/json',
                            temperature=0.0
                        )
                    ),
                    timeout=60
                )
                response_text = getattr(response, "text", "") or ""

            return _parse_llm_verdict(response_text)
        
        except asyncio.TimeoutError:
            logger.warning(f"AI call timed out (attempt {attempt + 1}/{retries}). Retrying...")
            await asyncio.sleep(2)
        except Exception as e:
            # Check for rate limits (429) or quota issues
            err_str = str(e).lower()
            if "429" in err_str or "quota" in err_str or "too many requests" in err_str:
                retry_after = _retry_after_seconds(str(e))
                wait_time = retry_after if retry_after is not None else (2 ** attempt) + random.uniform(0, 1)
                logger.warning(f"AI Rate Limit hit ({e}). Retrying in {wait_time:.2f}s...")
                await asyncio.sleep(wait_time)
            else:
                logger.error(f"LLM Verification Failed: {e}")
                return "UNKNOWN", "Low", f"LLM Error: {str(e)}", "Information"

    return "UNKNOWN", "Low", "Max retries exceeded", "Information"

def is_soft_403(body):
    """
    Heuristic check for 'Soft 403' pages (200 OK but content says Access Denied).
    Matches the logic in the Java tool.
    """
    if not body: return False
    lower = body.lower()
    indicators = [
        "access denied",
        "unauthorized",
        "permission denied",
        "forbidden",
        "please login",
        "please log in",
        "please sign in",
        "you do not have permission",
        "you don't have permission",
        "you are not authorized",
        "not allowed",
    ]
    # Check for direct indicators or error + permission combo
    if any(ind in lower for ind in indicators):
        return True
    if "error" in lower and "permission" in lower:
        return True
    return False


HIGH_RISK_ENDPOINT_RE = re.compile(
    r"(?i)(?:"
    r"/edit(?:/|$)|/tambah(?:/|$)|/create(?:/|$)|/add(?:/|$)|"
    r"/update(?:/|$)|/manage(?:/|$)|/admin(?:/|$)|/pengaturan(?:/|$)|"
    r"edit_password|/laporan[^/]*(?:/|$)|/report[^/]*(?:/|$)|"
    r"/penyesuaian(?:/|$)|/masuk/tambah(?:/|$)|/keluar/tambah(?:/|$)"
    r")"
)

HIGH_RISK_BODY_TERMS = (
    "form", "input", "textarea", "select", "button", "submit", "save", "update",
    "edit", "delete", "password", "username", "report", "laporan", "download",
    "table", "supplier", "customer", "total", "status", "barang", "penyesuaian",
    "name", "brand", "item", "full name", "address", "telephone", "phone",
    "email", "group", "nama", "alamat", "kode", "simpan",
)


def _looks_like_high_risk_bac(endpoint: str, base_status, base_body: str, base_url: str,
                              test_status, test_body: str, test_url: str) -> tuple[bool, str, str]:
    """Deterministically flag obvious direct access to sensitive/action routes.

    This is intentionally biased toward surfacing findings. It only fires when
    the target route shape is high-risk, both responses are successful, the test
    role was not redirected away, and the response has enough action/report data
    to be useful evidence.
    """
    endpoint_lower = (endpoint or "").lower()
    if not HIGH_RISK_ENDPOINT_RE.search(endpoint_lower):
        return False, "", "Information"
    if base_status != 200 or test_status != 200:
        return False, "", "Information"
    if _is_login_url(test_url) or _is_login_url(base_url):
        return False, "", "Information"
    if is_soft_403(test_body):
        return False, "", "Information"

    def _norm(u):
        return (u or "").split("#", 1)[0].split("?", 1)[0].rstrip("/")

    target_path = _norm(endpoint)
    base_path = _norm(endpoint_from_url(base_url))
    test_path = _norm(endpoint_from_url(test_url))
    if test_path and target_path and test_path != target_path and base_path == target_path:
        return False, "", "Information"

    text = (test_body or "").lower()
    body_len = len(text.strip())
    if body_len < 40:
        return False, "", "Information"
    term_hits = [term for term in HIGH_RISK_BODY_TERMS if term in text]
    is_action_route = any(
        t in endpoint_lower
        for t in ("/edit", "edit_password", "/tambah", "/create", "/add", "/update", "/manage", "/pengaturan")
    )
    if is_action_route:
        severity = "High"
        if term_hits:
            evidence_text = f"action/form content ({', '.join(term_hits[:5])})"
        else:
            evidence_text = "a non-denial body on an action route"
        reason = (
            f"High-risk direct-access route returned HTTP 200 with {evidence_text}; "
            "surfacing as probable broken access control without relying on AI."
        )
        return True, reason, severity

    if len(term_hits) < 1 and body_len < 120:
        return False, "", "Information"

    severity = "Medium"
    if term_hits:
        evidence_text = f"report/table content ({', '.join(term_hits[:5])})"
    else:
        evidence_text = "a substantive non-denial body"
    reason = (
        f"High-risk report/business-data route returned HTTP 200 with {evidence_text}; "
        "surfacing as probable broken access control without relying on AI."
    )
    return True, reason, severity


def _norm_route_path(value: str) -> str:
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        value = endpoint_from_url(value)
    return (value or "").split("#", 1)[0].split("?", 1)[0].rstrip("/") or "/"


def _test_stayed_on_target(endpoint: str, test_url: str) -> bool:
    target_path = _norm_route_path(endpoint)
    test_path = _norm_route_path(test_url)
    return bool(target_path and test_path and target_path == test_path)


def _high_risk_route_severity(endpoint: str) -> str:
    endpoint_lower = (endpoint or "").lower()
    if any(t in endpoint_lower for t in ("/edit", "edit_password", "/tambah", "/create", "/add", "/update", "/manage", "/pengaturan")):
        return "High"
    return "Medium"


def _should_promote_suspicious_to_vuln(endpoint: str, test_status, test_body: str, test_url: str) -> tuple[bool, str, str]:
    """Turn strong high-risk SUSPICIOUS/UNKNOWN evidence into a finding.

    The middle bucket should not be used when a protected action/report route
    returned a real 2xx response at the requested object path. That is exactly
    the situation this tool is designed to surface with minimal human triage.
    """
    endpoint_lower = (endpoint or "").lower()
    if not HIGH_RISK_ENDPOINT_RE.search(endpoint_lower):
        return False, "", "Information"
    try:
        status = int(test_status)
    except (TypeError, ValueError):
        return False, "", "Information"
    if status < 200 or status >= 300:
        return False, "", "Information"
    if _is_login_url(test_url) or is_soft_403(test_body):
        return False, "", "Information"
    if not _test_stayed_on_target(endpoint, test_url):
        return False, "", "Information"

    text = (test_body or "").lower()
    body_len = len(text.strip())
    term_hits = [term for term in HIGH_RISK_BODY_TERMS if term in text]
    is_action_route = _high_risk_route_severity(endpoint) == "High"
    if not is_action_route and body_len < 120 and not term_hits:
        return False, "", "Information"
    if is_action_route and body_len < 40 and not term_hits:
        return False, "", "Information"

    severity = _high_risk_route_severity(endpoint)
    if term_hits:
        evidence = f"protected-page indicators ({', '.join(term_hits[:5])})"
    else:
        evidence = "a substantive non-denial body"
    reason = (
        f"Verifier returned a non-final verdict, but high-risk route '{endpoint}' returned HTTP {status} "
        f"at the requested path with {evidence}; promoting to VULNERABLE to avoid manual triage."
    )
    return True, reason, severity


def _safe_llm_result_should_stay_suspicious(target: str, confidence: str, test_status,
                                            test_body: str, test_url: str) -> tuple[bool, str]:
    """Guardrail for model false negatives.

    A model can still call an ambiguous direct-access response SAFE. For this
    tool's workflow, the endpoint already came from another role's crawl and the
    current role did not discover it naturally, so a live 200 on a protected-ish
    page should remain visible unless denial is clear.
    """
    try:
        status = int(test_status)
    except (TypeError, ValueError):
        status = 0
    if status < 200 or status >= 300:
        return False, ""
    if _is_login_url(test_url) or is_soft_403(test_body):
        return False, ""

    confidence_upper = str(confidence or "").upper()
    target_lower = (target or "").lower()
    text = (test_body or "").lower()
    if HIGH_RISK_ENDPOINT_RE.search(target_lower):
        if not _test_stayed_on_target(target, test_url):
            return False, ""
        return True, "LLM returned SAFE, but the test role received a live 2xx response on a high-risk action/report route."

    if confidence_upper == "HIGH":
        return False, ""
    if len(text.strip()) < 120:
        return False, ""
    term_hits = [term for term in HIGH_RISK_BODY_TERMS if term in text]
    if len(term_hits) >= 2:
        return True, (
            "LLM returned SAFE with non-high confidence, but the test role received a live 2xx response "
            f"with protected-page indicators ({', '.join(term_hits[:5])})."
        )
    return False, ""


def record_suspicious(results_container: dict, endpoint: str, role_name: str, baseline_role_name: str,
                      reason: str, evidence: dict = None, confidence: str = "LOW",
                      severity: str = "Information"):
    results_container['suspicious'].add((endpoint, role_name))
    details = results_container.setdefault('suspicious_detail', [])
    if any(item.get("endpoint") == endpoint and item.get("role") == role_name for item in details):
        return
    details.append({
        "endpoint": endpoint,
        "role": role_name,
        "baseline_role": baseline_role_name,
        "severity": _normalize_severity(severity),
        "confidence": _normalize_confidence(confidence),
        "reason": reason or "Suspicious authorization behavior requires manual review.",
        "evidence": evidence or {}
    })

def _is_login_url(u):
    """True if a URL's path looks like an unauthenticated login/signin page.

    Path-only check (avoids false matches on `/login_history`, `/post_login_data`).
    """
    if not u:
        return False
    try:
        path = urlparse(u.lower()).path or ""
    except Exception:
        return False
    # Match common login segment names; anchor at '/' so we don't match arbitrary substrings.
    return any(seg in path for seg in ('/login', '/signin', '/wp_login', '/wp-login', '/session-timeout', '/sessiontimeout'))


async def _refresh_role_session(browser, role, ai_client, ai_model):
    """Re-authenticate a role using stored credentials. Updates cookies/storage in place.

    Requires `role['_login']` (set by the --logins flow). Returns True on success.
    Roles built without --logins have no creds and cannot be refreshed.
    """
    creds = role.get('_login')
    if not creds:
        return False
    try:
        new_role = await perform_login(
            browser,
            creds['target'],
            creds['username'],
            creds['password'],
            ai_client,
            ai_model,
            sso_selector=creds.get('sso'),
        )
        if not new_role:
            return False
        role['cookies'] = new_role.get('cookies', [])
        role['storage'] = new_role.get('storage', {})
        role['headers'] = new_role.get('headers', {})
        if 'start_url' in new_role:
            role['start_url'] = new_role['start_url']
        logger.info(f"Re-authenticated role '{role.get('name', '?')}'.")
        return True
    except Exception as e:
        logger.error(f"Re-auth failed for role '{role.get('name', '?')}': {e}")
        return False


async def _merge_context_cookies_into_role(context, role, lock=None):
    """Pull live cookies from a Playwright context (post-Set-Cookie) and merge into role.

    Catches the case where the server rotated the session ID mid-request — without this,
    the regenerated cookie dies on context.close() and every subsequent call uses the
    stale ID. Cookies are matched by (name, domain, path); existing entries are updated
    in place, new ones are appended.
    """
    try:
        live = await context.cookies()
    except Exception:
        return
    if not live:
        return

    def _do_merge():
        existing = role.get('cookies') or []
        idx = {(c.get('name'), c.get('domain', ''), c.get('path', '/')): i for i, c in enumerate(existing)}
        for lc in live:
            key = (lc.get('name'), lc.get('domain', ''), lc.get('path', '/'))
            if key in idx:
                existing[idx[key]] = lc
            else:
                existing.append(lc)
                idx[key] = len(existing) - 1
        role['cookies'] = existing

    if lock is not None:
        async with lock:
            _do_merge()
    else:
        _do_merge()


async def _build_role_context(browser, role, target_url, page_username="", page_password=None):
    """Create a Playwright BrowserContext preloaded with a role's cookies/storage/headers.

    Used both for persistent verify-phase sessions (RoleSession) and the legacy
    one-context-per-call path inside fetch_page_metrics.
    """
    kwargs = dict(
        ignore_https_errors=True,
        viewport={'width': 1920, 'height': 1080},
        device_scale_factor=1,
    )
    if page_password:
        kwargs["http_credentials"] = {
            "username": page_username or "",
            "password": page_password,
        }
    context = await browser.new_context(**kwargs)

    if 'storage' in role and role['storage']:
        try:
            ls_data = role['storage'].get('localStorage', '{}')
            ss_data = role['storage'].get('sessionStorage', '{}')
            await context.add_init_script(f"""
                const ls = {ls_data};
                const ss = {ss_data};
                for (const [key, value] of Object.entries(ls)) {{
                    window.localStorage.setItem(key, value);
                }}
                for (const [key, value] of Object.entries(ss)) {{
                    window.sessionStorage.setItem(key, value);
                }}
            """)
        except Exception:
            pass

    if 'cookies' in role and role['cookies']:
        domain = urlparse(target_url).hostname
        cookies_to_add = _normalize_cookies(role['cookies'], domain)
        if cookies_to_add:
            await context.add_cookies(cookies_to_add)

    headers = role.get('headers', {})
    if headers:
        safe_headers = {
            k: str(v) for k, v in headers.items()
            if k.lower() != 'host'
        }
        if safe_headers:
            await context.set_extra_http_headers(safe_headers)

    return context


class RoleSession:
    """Persistent Playwright context for one role across the verify phase.

    Removes the per-call new_context()/close() overhead in fetch_page_metrics and
    lets Playwright handle Set-Cookie natively across requests. Re-auth is
    serialized via reauth_lock — when a session is rebuilt, the old context is
    torn down and a fresh one (with refreshed cookies from perform_login) replaces it.
    """
    def __init__(self, browser, role, target_url, page_username="", page_password=""):
        self.browser = browser
        self.role = role
        self.target_url = target_url
        self.page_username = page_username
        self.page_password = page_password
        self.context = None
        self.reauth_lock = asyncio.Lock()

    async def init(self):
        self.context = await _build_role_context(
            self.browser, self.role, self.target_url, self.page_username, self.page_password
        )

    async def reauth(self, ai_client, ai_model):
        """Refresh credentials via stored login + rebuild the context atomically.

        Caller must hold self.reauth_lock. Returns True if both the login and the
        context rebuild succeeded.
        """
        ok = await _refresh_role_session(self.browser, self.role, ai_client, ai_model)
        if not ok:
            return False
        old = self.context
        try:
            self.context = await _build_role_context(
                self.browser, self.role, self.target_url, self.page_username, self.page_password
            )
        except Exception as e:
            logger.error(f"RoleSession.reauth: rebuild context failed for '{self.role.get('name','?')}': {e}")
            self.context = old  # keep old (broken) context rather than leaving None
            return False
        if old is not None:
            try:
                await old.close()
            except Exception:
                pass
        return True

    async def close(self):
        if self.context is not None:
            try:
                await self.context.close()
            except Exception:
                pass
            self.context = None


async def fetch_page_metrics(browser, role, target_url, endpoint, page_username="", page_password=None, persist_cookies_lock=None, shared_context=None):
    """
    Fetches page metrics (Status Code, Body Content, Final URL) for heuristic comparison.
    Also captures raw Request and Response strings for evidence.
    Returns: (status, body, final_url, req_str, resp_str) or (None, None, None, None, None) on failure.

    If `shared_context` is provided, it is reused for the request (page-only lifecycle).
    Otherwise a fresh context is created and torn down per call (legacy behaviour).
    """
    context = None
    own_context = False
    try:
        if shared_context is not None:
            context = shared_context
        else:
            context = await _build_role_context(browser, role, target_url, page_username, page_password)
            own_context = True

        page = await context.new_page()
        page.set_default_timeout(5000)
        page.set_default_navigation_timeout(30000)

        full_url = urljoin(target_url, endpoint)

        async def _cleanup_failure():
            try:
                await page.close()
            except Exception:
                pass
            if own_context:
                try:
                    await context.close()
                except Exception:
                    pass

        # Navigate
        try:
            response = await page.goto(full_url, wait_until="domcontentloaded", timeout=45000)
        except Exception:
            await _cleanup_failure()
            return None, None, None, None, None

        if not response:
            await _cleanup_failure()
            return None, None, None, None, None
            
        status = response.status
        final_url = response.url
        
        # Capture Response Body (Full, no truncation)
        try:
            raw_body = await response.body()
            body = raw_body.decode('utf-8', errors='replace')
        except Exception:
            body = "[Binary Content]"

        # Wait for any JS navigation to settle
        try:
            await page.wait_for_load_state('networkidle', timeout=3000)
        except Exception:
            pass

        # Detect JS redirects: if the browser ended up at a different URL than the server's
        # response URL, a client-side redirect occurred. In that case we keep the raw HTML
        # (the pre-redirect content the server actually exposed) and update final_url so
        # heuristics can see the redirect. If no JS redirect, use inner_text for cleaner
        # AI comparison (strips CSS/script boilerplate from raw HTML).
        def _norm_url(u): return (u or '').split('?')[0].rstrip('/')
        current_page_url = page.url
        if _norm_url(current_page_url) != _norm_url(final_url):
            # JS redirect detected — raw HTML is the exposed pre-redirect content; update
            # final_url so the heuristics in the worker see where the browser ended up
            final_url = current_page_url
        else:
            # Try content-area selectors first to exclude navigation/sidebars,
            # which differ between roles and confuse the AI similarity check.
            # Fall back to body if none match.
            for _sel in ['main', '[role="main"]', '#content', '.content', 'article', 'body']:
                try:
                    visible_text = await page.inner_text(_sel, timeout=3000)
                    if visible_text and len(visible_text.strip()) > 50:
                        body = visible_text
                        break
                except Exception:
                    continue

        # Capture Exact Request
        # Page responses expose the request object
        req = response.request
        req_headers = await req.all_headers()
        req_method = req.method
        req_url = req.url
        
        req_str = f"{req_method} {req_url} HTTP/1.1\n"
        for k, v in req_headers.items():
            req_str += f"{k}: {v}\n"
        if req.post_data:
             req_str += f"\n{req.post_data}"
        
        # Capture Response String
        resp_headers = await response.all_headers()
        resp_str = f"HTTP/1.1 {status} {response.status_text}\n"
        for k, v in resp_headers.items():
            resp_str += f"{k}: {v}\n"
        resp_str += f"\n{body}" # Full body, no truncation

        # Persist any updated cookies (e.g. server rotated the session ID via Set-Cookie)
        # back into the role so the NEXT call uses the rotated session, not the stale one.
        # With a shared_context this is largely redundant (Playwright tracks Set-Cookie
        # natively), but harmless and useful when the caller still wants role['cookies']
        # kept in sync with the live context.
        if persist_cookies_lock is not None:
            await _merge_context_cookies_into_role(context, role, lock=persist_cookies_lock)

        try:
            await page.close()
        except Exception:
            pass
        if own_context:
            await context.close()
        return status, body, final_url, req_str, resp_str

    except Exception as e:
        logger.warning(f"Verification fetch error for {endpoint}: {e}")
        if own_context and context is not None:
            try:
                await context.close()
            except Exception:
                pass
        return None, None, None, None, None


async def replay_api_call(role, call: ApiCall, target_url: str, client=None):
    """Replay a captured ApiCall with the given role's credentials via httpx.

    Returns (status_code, body_text, final_url) or (None, error_str, abs_url) on failure.
    """
    try:
        import httpx
    except ImportError:
        return None, "httpx not installed - run: pip install httpx", call.url

    abs_url = call.url if call.url.startswith(("http://", "https://")) else urljoin(target_url, call.path)
    headers = replay_headers_for_call(role, call)
    cookies = role_cookie_dict(role)
    if cookies:
        headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies.items())
    replay_body = replay_body_for_call(role, call.body)
    content = replay_body.encode("utf-8", errors="replace") if isinstance(replay_body, str) else replay_body

    try:
        if client is not None:
            client.cookies.clear()
            resp = await client.request(
                method=call.method,
                url=abs_url,
                content=content,
                headers=headers,
            )
            return resp.status_code, resp.text, str(resp.url)

        async with httpx.AsyncClient(follow_redirects=False, timeout=15) as owned_client:
            owned_client.cookies.clear()
            resp = await owned_client.request(
                method=call.method,
                url=abs_url,
                content=content,
                headers=headers,
            )
            return resp.status_code, resp.text, str(resp.url)
    except Exception as e:
        return None, str(e), abs_url


async def crawl_role(playwright, role, start_url, max_pages, ignore_patterns, headless, sem, delay, follow_redirects=False, spa_mode=False, role_ui_elements=None, proxy=None, blacklist=None, ai_client=None, ai_model=None, spa_max_clicks=0, api_harvest_mode=False, page_username="", page_password=None, screenshot_dir=None, traffic_log=None, static_js_recon=True, js_template_resolution=True, recon_max_assets=150, recon_max_bytes=50 * 1024 * 1024, allow_risky_recon_actions=False, validate_static_get=False, recon_validation_limit=100):
    """
    Crawls the site as a specific role.
    """
    async with sem:
        role_name = role.get('name', 'Unknown Role')
        logger.info(f"Starting crawl for role: {role_name}")
        target_domain = urlparse(start_url).netloc
        allowed_domains = {target_domain}
        recon_inventory = ReconInventory(role=role_name)
        first_party_js_assets = {}
        _pending_recon_tasks = []
        discovered_api_calls = []
        _api_call_seen = set()

        def _remember_api_call(call: ApiCall) -> bool:
            key = (call.method, call.path)
            if key in _api_call_seen:
                return False
            _api_call_seen.add(key)
            discovered_api_calls.append(call)
            recon_inventory.add(EndpointCandidate.build(
                method=call.method,
                raw_url=call.url or call.path,
                source="network",
                evidence=f"Observed {call.method} {call.path}",
                role=role_name,
                discovered_from=call.url,
                observed=True,
                validated=True,
                confidence="HIGH",
                request_body_schema=infer_body_schema(call.body),
            ))
            return True
        
        if role_ui_elements is not None:
            if role_name not in role_ui_elements:
                role_ui_elements[role_name] = set()

        # Blacklist for buttons/links (e.g. logout) — used as hard-skip tier
        effective_blacklist = set(HARD_SKIP_TERMS)
        if blacklist:
            effective_blacklist.update(str(term).lower() for term in blacklist if str(term).strip())

        # Launch browser
        # Use anti-detection args to make headless mode behave more like a real browser
        browser_args = [
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-accelerated-2d-canvas",
            "--no-first-run",
            "--no-zygote",
            "--disable-gpu",
            "--hide-scrollbars",
            "--mute-audio",
            "--window-size=1920,1080"
        ]
        
        if not proxy:
            browser_args.append("--no-proxy-server")
        
        cdp_url = os.environ.get("SK_CDP_URL")
        if cdp_url:
            logger.info(f"[{role_name}] Attaching crawler to existing Chrome over CDP: {cdp_url}")
            browser = await playwright.chromium.connect_over_cdp(cdp_url)
        else:
            browser = await playwright.chromium.launch(
                headless=headless,
                channel="chrome" if not headless else None,
                args=browser_args,
                proxy={"server": proxy} if proxy else None
            )
        _ctx_kwargs = dict(
            ignore_https_errors=True,
            viewport={'width': 1920, 'height': 1080},
            device_scale_factor=1,
        )
        if page_password:
            _ctx_kwargs["http_credentials"] = {
                "username": page_username or "",
                "password": page_password,
            }
        reuse_context = bool(cdp_url and browser.contexts)
        context = browser.contexts[0] if reuse_context else await browser.new_context(**_ctx_kwargs)

        async def _capture_recon_response(response):
            """Keep bounded first-party JS bodies for passive bundle analysis."""
            try:
                response_url = response.url
                parsed = urlparse(response_url)
                if parsed.netloc not in allowed_domains:
                    if response.request.resource_type == "document" and len(visited) <= 1:
                        allowed_domains.add(parsed.netloc)
                    else:
                        return
                response_headers = await response.all_headers()
                content_type = str(response_headers.get("content-type", "")).lower()
                if not (parsed.path.lower().endswith((".js", ".mjs")) or "javascript" in content_type):
                    return
                body = await asyncio.wait_for(response.body(), timeout=10.0)
                if len(body) > 12 * 1024 * 1024:
                    recon_inventory.skipped_assets.append({"url": response_url, "reason": "individual asset exceeds 12 MiB"})
                    return
                asset_text = body.decode("utf-8", errors="replace")
                source_map_header = response_headers.get("sourcemap") or response_headers.get("x-sourcemap")
                if source_map_header:
                    asset_text += f"\n//# sourceMappingURL={source_map_header}"
                first_party_js_assets[response_url] = asset_text
                recon_inventory.assets_downloaded.add(response_url)
            except Exception as exc:
                logger.debug(f"[{role_name}] Could not retain JavaScript asset for recon: {exc}")

        def _track_recon_response(response):
            task = asyncio.create_task(_capture_recon_response(response))
            _pending_recon_tasks.append(task)
            task.add_done_callback(
                lambda done: _pending_recon_tasks.remove(done)
                if done in _pending_recon_tasks else None
            )

        context.on("response", _track_recon_response)

        # SPA Mode: Capture backend traffic
        # Note: we intentionally do NOT add XHR/fetch paths to discovered_endpoints here.
        # API calls are captured via the JS hooks (window.__skApiLog) into discovered_api_calls.
        # Page endpoints must only come from the main crawl loop's settled final_url so that
        # redirected roles don't falsely "discover" access-controlled pages, which would
        # cause the BAC test matrix to skip testing them.

        # Preserve native browser globals when attached to a user-driven CDP
        # profile; synthetic webdriver descriptors can themselves be detected.
        if not reuse_context:
            await context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                });
            """)

        # API-Harvest: inject fetch/XHR hooks so every API call is recorded
        await context.add_init_script("""
(function() {
    if (window.__skHooked) return;
    window.__skHooked = true;
    window.__skApiLog = [];

    // --- window.fetch hook ---
    const _origFetch = window.fetch;
    window.fetch = function(input, init) {
        try {
            const url = (typeof input === 'string') ? input
                        : (input && input.url) ? input.url : String(input);
            const reqHeaders = (input instanceof Request) ? Object.fromEntries(input.headers.entries()) : {};
            const initHeaders = (init && init.headers) ? Object.fromEntries(
                    (init.headers instanceof Headers)
                        ? init.headers.entries()
                        : Object.entries(init.headers)) : {};
            window.__skApiLog.push({
                method: ((init && init.method) || (input && input.method) || 'GET').toUpperCase(),
                url: url,
                body: (init && init.body != null) ? String(init.body) : null,
                headers: Object.assign({}, reqHeaders, initHeaders)
            });
        } catch(e) {}
        return _origFetch.apply(this, arguments);
    };

    // --- XMLHttpRequest hook ---
    const _origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
        this.__skMethod = method ? method.toUpperCase() : 'GET';
        this.__skUrl    = url || '';
        this.__skHeaders = {};
        return _origOpen.apply(this, arguments);
    };
    const _origSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
    XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
        try {
            if (!this.__skHeaders) this.__skHeaders = {};
            this.__skHeaders[name] = value;
        } catch(e) {}
        return _origSetRequestHeader.apply(this, arguments);
    };
    const _origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(body) {
        try {
            window.__skApiLog.push({
                method: this.__skMethod || 'GET',
                url:    this.__skUrl   || '',
                body:   (body != null) ? String(body) : null,
                headers: this.__skHeaders || {}
            });
        } catch(e) {}
        return _origSend.apply(this, arguments);
    };
})();
""")

        # Inject Local/Session Storage if available
        if 'storage' in role and role['storage']:
            try:
                ls_data = role['storage'].get('localStorage', '{}')
                ss_data = role['storage'].get('sessionStorage', '{}')
                
                await context.add_init_script(f"""
                    const ls = {ls_data};
                    const ss = {ss_data};
                    for (const [key, value] of Object.entries(ls)) {{
                        window.localStorage.setItem(key, value);
                    }}
                    for (const [key, value] of Object.entries(ss)) {{
                        window.sessionStorage.setItem(key, value);
                    }}
                """)
            except Exception as e:
                logger.error(f"[{role_name}] Failed to inject storage state: {e}")

        # Set cookies
        if 'cookies' in role and role['cookies']:
            domain = urlparse(start_url).hostname
            cookies_to_add = _normalize_cookies(role['cookies'], domain)
            if cookies_to_add:
                try:
                    await context.add_cookies(cookies_to_add)
                except Exception as e:
                    logger.error(f"[{role_name}] Failed to add cookies: {e}")

        # Set headers
        if 'headers' in role and role['headers']:
            # Sanitize headers: skip 'Host' which causes ERR_INVALID_ARGUMENT in Playwright
            # and ensure all values are strings.
            safe_headers = {
                k: str(v) for k, v in role['headers'].items() 
                if k.lower() != 'host'
            }
            if safe_headers:
                await context.set_extra_http_headers(safe_headers)

        page = await context.new_page()
        page.set_default_timeout(5000)
        page.set_default_navigation_timeout(30000)

        def _on_websocket(socket):
            try:
                recon_inventory.add(EndpointCandidate.build(
                    method="WEBSOCKET",
                    raw_url=socket.url,
                    source="websocket",
                    evidence="WebSocket created by browser page",
                    role=role_name,
                    discovered_from=getattr(page, "url", start_url),
                    observed=True,
                    validated=True,
                    confidence="HIGH",
                ))
            except Exception:
                pass

        page.on("websocket", _on_websocket)
        _pending_traffic_tasks = []

        # Network-level XHR/fetch capture — works for all apps regardless of JS framework.
        # Fires at the Playwright network layer so it catches calls the JS hooks may miss.
        if api_harvest_mode:
            def _on_network_api(request):
                try:
                    url_str = request.url
                    if is_static_resource(url_str):
                        return
                    parsed = urlparse(url_str)
                    if parsed.netloc and parsed.netloc not in allowed_domains:
                        return
                    path = endpoint_from_url(url_str)
                    api_shaped = bool(re.search(r"/(?:api|rest|graphql|odata|services?)(?:/|$)", parsed.path or "", re.IGNORECASE))
                    if request.resource_type not in ("xhr", "fetch") and not api_shaped:
                        # Still retain a provenance-aware network route without treating
                        # it as a replayable API call.
                        recon_inventory.add(EndpointCandidate.build(
                            method=request.method,
                            raw_url=url_str,
                            source="network_route",
                            evidence=f"Browser resource type: {request.resource_type}",
                            role=role_name,
                            discovered_from=url_str,
                            observed=True,
                            validated=True,
                            confidence="HIGH",
                        ))
                        return
                    method = request.method.upper()
                    abs_url = url_str if url_str.startswith(("http://", "https://")) else urljoin(start_url, url_str)
                    headers = getattr(request, "headers", {}) or {}
                    if callable(headers):
                        headers = {}
                    if not _remember_api_call(ApiCall(
                        method=method, url=abs_url, path=path,
                        body=request.post_data, headers=headers
                    )):
                        return
                    logger.debug(f"[{role_name}] API captured: {method} {path}")
                except Exception:
                    pass
            context.on("request", _on_network_api)

        if traffic_log is not None:
            async def _capture_request(request):
                try:
                    parsed_req = urlparse(request.url)
                    req_path_lower = (parsed_req.path or '').lower()
                    if any(req_path_lower.endswith(ext) for ext in _TRAFFIC_SKIP_EXTENSIONS):
                        return
                    try:
                        response = await asyncio.wait_for(request.response(), timeout=8.0)
                    except (asyncio.TimeoutError, Exception):
                        return
                    if response is None:
                        return
                    req_hdrs = {k: v for k, v in (await request.all_headers()).items() if not k.startswith(':')}
                    req_body = request.post_data_buffer or b""
                    path_qs = (parsed_req.path or "/") + (("?" + parsed_req.query) if parsed_req.query else "")
                    raw_req = build_redacted_http_message(
                        f"{request.method} {redact_url(path_qs)} HTTP/1.1",
                        req_hdrs,
                        req_body or b"",
                    )
                    resp_hdrs = {k: v for k, v in (await response.all_headers()).items() if not k.startswith(':')}
                    try:
                        resp_body = await asyncio.wait_for(response.body(), timeout=8.0)
                    except (asyncio.TimeoutError, Exception):
                        resp_body = b""
                    raw_resp = build_redacted_http_message(
                        f"HTTP/1.1 {response.status} {response.status_text}",
                        resp_hdrs,
                        resp_body,
                    )
                    mime = resp_hdrs.get("content-type", "").split(";")[0].strip() or "unknown"
                    port_val = parsed_req.port or (443 if parsed_req.scheme == "https" else 80)
                    traffic_log.append({
                        "time": datetime.now().astimezone().isoformat(),
                        "url": redact_url(request.url),
                        "host": parsed_req.hostname or "",
                        "port": int(port_val),
                        "protocol": parsed_req.scheme,
                        "path": parsed_req.path or "/",
                        "method": request.method,
                        "responseCode": response.status,
                        "responseSize": len(resp_body),
                        "mimeType": mime,
                        "request": base64.b64encode(raw_req).decode("ascii"),
                        "response": base64.b64encode(raw_resp).decode("ascii"),
                        "issues": [],
                        "tags": []
                    })
                except Exception:
                    pass
            def _track_traffic_task(req):
                task = asyncio.create_task(_capture_request(req))
                _pending_traffic_tasks.append(task)
                task.add_done_callback(
                    lambda done: _pending_traffic_tasks.remove(done)
                    if done in _pending_traffic_tasks else None
                )

            context.on("requestfinished", _track_traffic_task)

        visited = set()
        visited_normalized = set()  # normalized patterns to prevent ID-looping
        to_visit = [start_url]
        discovered_endpoints = set()
        _ss_counter = 0             # sequential screenshot index

        # Per-endpoint baseline cache: { endpoint_path: (status, body, final_url, req_str, resp_str) }
        # Populated after each successful page.goto so the verification phase can reuse the
        # response captured at crawl time instead of re-fetching (which races with concurrent
        # workers and dies when the server rotates the session ID).
        endpoint_responses = {}

        # Track which interactive elements we've already clicked to avoid repetition
        interacted_selectors = set()

        # Domain constraint
        authenticated_crawl = role_has_authenticated_state(role)

        def _add_crawl_candidate(candidate_url: str, queue: bool = True) -> bool:
            """Map and optionally queue a URL if it is valid for this role's crawl."""
            if not candidate_url or not is_crawlable_web_url(candidate_url) or is_noise_navigation_url(candidate_url):
                return False
            parsed_candidate = urlparse(candidate_url)
            if parsed_candidate.netloc not in allowed_domains:
                return False
            crawl_path_prefix = os.environ.get("SK_CRAWL_PATH_PREFIX", "").strip()
            if crawl_path_prefix and not parsed_candidate.path.startswith(crawl_path_prefix):
                logger.debug(
                    f"[{role_name}] Skipping same-host route outside crawl path prefix "
                    f"'{crawl_path_prefix}': {candidate_url}"
                )
                return False
            if authenticated_crawl and is_auth_exit_url(candidate_url):
                logger.debug(f"[{role_name}] Skipping auth/session route during authenticated crawl: {candidate_url}")
                return False
            path = endpoint_from_url(candidate_url)
            discovered_endpoints.add(path)
            recon_inventory.add(EndpointCandidate.build(
                method="GET",
                raw_url=candidate_url,
                source="dom_route",
                evidence=f"Route extracted from DOM while visiting {getattr(page, 'url', start_url)}",
                role=role_name,
                discovered_from=getattr(page, "url", start_url),
                observed=False,
                validated=False,
                confidence="HIGH",
            ))
            if (
                queue and
                candidate_url not in visited and
                candidate_url not in to_visit and
                normalize_url_for_dedup(candidate_url) not in visited_normalized
            ):
                to_visit.append(candidate_url)
            return True

        auth_retry_counts = {}

        async def _rebuild_crawl_context():
            nonlocal context, page
            try:
                await page.close()
            except Exception:
                pass
            if reuse_context:
                page = await context.new_page()
                page.set_default_timeout(5000)
                page.set_default_navigation_timeout(30000)
                page.on("websocket", _on_websocket)
                return
            try:
                await context.close()
            except Exception:
                pass

            context = await browser.new_context(**_ctx_kwargs)
            context.on("response", _track_recon_response)
            await context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                });
            """)
            await context.add_init_script("""
(function() {
    if (window.__skHooked) return;
    window.__skHooked = true;
    window.__skApiLog = [];

    const _origFetch = window.fetch;
    window.fetch = function(input, init) {
        try {
            const url = (typeof input === 'string') ? input
                        : (input && input.url) ? input.url : String(input);
            const reqHeaders = (input instanceof Request) ? Object.fromEntries(input.headers.entries()) : {};
            const initHeaders = (init && init.headers) ? Object.fromEntries(
                    (init.headers instanceof Headers)
                        ? init.headers.entries()
                        : Object.entries(init.headers)) : {};
            window.__skApiLog.push({
                method: ((init && init.method) || (input && input.method) || 'GET').toUpperCase(),
                url: url,
                body: (init && init.body != null) ? String(init.body) : null,
                headers: Object.assign({}, reqHeaders, initHeaders)
            });
        } catch(e) {}
        return _origFetch.apply(this, arguments);
    };

    const _origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
        this.__skMethod = method ? method.toUpperCase() : 'GET';
        this.__skUrl    = url || '';
        this.__skHeaders = {};
        return _origOpen.apply(this, arguments);
    };
    const _origSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
    XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
        try {
            if (!this.__skHeaders) this.__skHeaders = {};
            this.__skHeaders[name] = value;
        } catch(e) {}
        return _origSetRequestHeader.apply(this, arguments);
    };
    const _origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(body) {
        try {
            window.__skApiLog.push({
                method: this.__skMethod || 'GET',
                url:    this.__skUrl   || '',
                body:   (body != null) ? String(body) : null,
                headers: this.__skHeaders || {}
            });
        } catch(e) {}
        return _origSend.apply(this, arguments);
    };
})();
""")

            if 'storage' in role and role['storage']:
                try:
                    ls_data = role['storage'].get('localStorage', '{}')
                    ss_data = role['storage'].get('sessionStorage', '{}')
                    await context.add_init_script(f"""
                        const ls = {ls_data};
                        const ss = {ss_data};
                        for (const [key, value] of Object.entries(ls)) {{
                            window.localStorage.setItem(key, value);
                        }}
                        for (const [key, value] of Object.entries(ss)) {{
                            window.sessionStorage.setItem(key, value);
                        }}
                    """)
                except Exception as e:
                    logger.error(f"[{role_name}] Failed to inject storage state during context rebuild: {e}")

            if 'cookies' in role and role['cookies']:
                domain = urlparse(start_url).hostname
                cookies_to_add = _normalize_cookies(role['cookies'], domain)
                if cookies_to_add:
                    try:
                        await context.add_cookies(cookies_to_add)
                    except Exception as e:
                        logger.error(f"[{role_name}] Failed to add cookies during context rebuild: {e}")

            if 'headers' in role and role['headers']:
                safe_headers = {
                    k: str(v) for k, v in role['headers'].items()
                    if k.lower() != 'host'
                }
                if safe_headers:
                    await context.set_extra_http_headers(safe_headers)

            page = await context.new_page()
            page.set_default_timeout(5000)
            page.set_default_navigation_timeout(30000)
            page.on("websocket", _on_websocket)
            if api_harvest_mode:
                context.on("request", _on_network_api)
            if traffic_log is not None:
                context.on("requestfinished", _track_traffic_task)

        async def _recover_authenticated_crawl(current_url: str, landed_url: str, auth_state: dict) -> bool:
            nonlocal pages_crawled
            key = normalize_url_for_dedup(current_url)
            auth_retry_counts[key] = auth_retry_counts.get(key, 0) + 1

            if not role.get('_login'):
                logger.warning(
                    f"[{role_name}] Authenticated crawl lost session on {current_url} -> {landed_url}, "
                    "but this role has no stored login for re-authentication. Skipping route."
                )
                return False

            if auth_retry_counts[key] > 1:
                logger.warning(
                    f"[{role_name}] Authenticated crawl still lands on auth wall for {current_url} -> {landed_url} "
                    "after retry. Skipping route."
                )
                return False

            logger.warning(
                f"[{role_name}] Authenticated crawl hit auth wall on {current_url} -> {landed_url}. "
                "Re-authenticating and retrying this route once."
            )
            refreshed = await _refresh_role_session(browser, role, ai_client, ai_model)
            if not refreshed:
                logger.warning(f"[{role_name}] Re-authentication failed during crawl recovery. Skipping route: {current_url}")
                return False

            await _rebuild_crawl_context()
            visited.discard(current_url)
            visited_normalized.discard(key)
            pages_crawled = max(0, pages_crawled - 1)
            if current_url not in to_visit:
                to_visit.insert(0, current_url)
            return True

        pages_crawled = 0
        global_handled_chrome_controls = set()
        global_no_progress_chrome_controls = {}

        while to_visit:
            if max_pages > 0 and pages_crawled >= max_pages:
                logger.info(f"[{role_name}] Reached max pages limit ({max_pages}). Stopping.")
                break

            current_url = to_visit.pop(0)

            if not is_crawlable_web_url(current_url):
                logger.debug(f"[{role_name}] Skipping non-web/static URL: {current_url}")
                continue

            if is_noise_navigation_url(current_url):
                logger.debug(f"[{role_name}] Skipping UI-only/navigation-noise URL: {current_url}")
                continue

            if authenticated_crawl and is_auth_exit_url(current_url):
                logger.info(f"[{role_name}] Skipping auth/session route during authenticated crawl: {current_url}")
                continue

            if current_url in visited:
                continue

            if should_ignore(current_url, ignore_patterns):
                logger.debug(f"[{role_name}] Skipping ignored URL: {current_url}")
                continue

            visited.add(current_url)
            visited_normalized.add(normalize_url_for_dedup(current_url))
            pages_crawled += 1
            api_count_before_page = len(discovered_api_calls)
            
            logger.info(f"[{role_name}] Visiting ({pages_crawled}): {current_url}")

            try:
                # Treat DOM readiness as successful navigation. Analytics, chat,
                # personalization, and ad streams on modern commerce sites often keep
                # the network permanently busy; waiting 30 seconds for networkidle and
                # then navigating a second time both slows the crawl and duplicates
                # traffic. Give background requests a short settling window instead.
                try:
                    response = await page.goto(current_url, wait_until="domcontentloaded", timeout=30000)
                except Exception as e:
                    if "Download is starting" in str(e):
                        logger.info(f"[{role_name}] URL triggers a download: {current_url}")
                        # Still record it as an endpoint
                        discovered_endpoints.add(endpoint_from_url(current_url))
                        continue
                    raise
                try:
                    await page.wait_for_load_state("networkidle", timeout=3000)
                except Exception:
                    pass
                
                # Check for static/binary content
                if response:
                    content_type = response.headers.get('content-type', '').lower()
                    if any(t in content_type for t in ['image/', 'video/', 'audio/', 'application/pdf', 'application/zip']):
                        logger.warning(f"[{role_name}] Stuck on static/binary resource ({content_type}). Backtracking...")
                        continue

                # Capture baseline response for the verification phase. Mirrors
                # fetch_page_metrics so the AI sees the same body shape regardless of
                # whether the baseline came from cache or a fresh fetch. Captured
                # before dismiss_popups so the cached body matches a fresh navigation.
                try:
                    if response:
                        _cap_status = response.status
                        _cap_final_url = response.url
                        # Body — prefer inner_text from main/content area to strip nav noise
                        _cap_body = None
                        for _sel in ['main', '[role="main"]', '#content', '.content', 'article', 'body']:
                            try:
                                _txt = await page.inner_text(_sel, timeout=2000)
                                if _txt and len(_txt.strip()) > 50:
                                    _cap_body = _txt
                                    break
                            except Exception:
                                continue
                        if _cap_body is None:
                            try:
                                _raw = await response.body()
                                _cap_body = _raw.decode('utf-8', errors='replace')
                            except Exception:
                                _cap_body = ""
                        # Request string
                        try:
                            _req = response.request
                            _req_headers = await _req.all_headers()
                            _cap_req = f"{_req.method} {_req.url} HTTP/1.1\n"
                            for _k, _v in _req_headers.items():
                                _cap_req += f"{_k}: {_v}\n"
                            if _req.post_data:
                                _cap_req += f"\n{_req.post_data}"
                        except Exception:
                            _cap_req = ""
                        # Response string
                        try:
                            _resp_headers = await response.all_headers()
                            _cap_resp = f"HTTP/1.1 {_cap_status} {response.status_text}\n"
                            for _k, _v in _resp_headers.items():
                                _cap_resp += f"{_k}: {_v}\n"
                            _cap_resp += f"\n{_cap_body}"
                        except Exception:
                            _cap_resp = ""
                        # Use the same endpoint key as the report/verify matrix.
                        _cap_path = endpoint_from_url(current_url)
                        endpoint_responses[_cap_path] = (_cap_status, _cap_body, _cap_final_url, _cap_req, _cap_resp)
                        _cap_final_path = endpoint_from_url(_cap_final_url)
                        if _cap_final_path != _cap_path:
                            endpoint_responses[_cap_final_path] = (_cap_status, _cap_body, _cap_final_url, _cap_req, _cap_resp)
                except Exception as _cap_err:
                    logger.debug(f"[{role_name}] Baseline-cache capture failed for {current_url}: {_cap_err}")

                # Allow time for dynamic content to settle (SPA handling)
                await dismiss_popups(page)

                # Screenshot (--ss)
                if screenshot_dir:
                    try:
                        _ss_path_part = urlparse(page.url).path or 'root'
                        safe_name = re.sub(r'[\\/:*?"<>|]', '_', _ss_path_part).strip('_')[:150] or 'root'
                        _ss_counter += 1
                        ss_path = os.path.join(screenshot_dir, f"{_ss_counter:04d}_{safe_name}.png")
                        await page.screenshot(path=ss_path, full_page=True)
                    except Exception as _ss_err:
                        logger.debug(f"[{role_name}] Screenshot failed for {current_url}: {_ss_err}")

                if page_password:
                    await _fill_page_password(page, page_username, page_password)
                    # The gate page may have returned a non-200 status (401/403 is common).
                    # After a successful password fill the browser is now on the real page,
                    # so synthesise a 200 response object so link extraction runs normally.
                    if response is None or response.status not in (200, 201, 202):
                        response = type('_R', (), {'status': 200, 'headers': {}})()  # lightweight stand-in

                soft_auth_overlay_present = False
                if authenticated_crawl:
                    auth_state = await capture_auth_state(page, context)
                    if is_probable_logged_out_state(auth_state, current_url):
                        landed_url = auth_state.get("url") or page.url
                        recovered = await _recover_authenticated_crawl(current_url, landed_url, auth_state)
                        if recovered:
                            continue
                        logger.warning(f"[{role_name}] Skipping route after auth loss: {current_url}")
                        continue
                    soft_auth_overlay_present = bool(
                        auth_state.get("auth_wall_text") and
                        auth_state.get("login_cta_visible") and
                        auth_state.get("success_text")
                    )

                # Interaction: Open Sidenav (Juice Shop specific) to reveal menu links
                try:
                    # Broaden discovery: Click on menus, account icons, and baskets
                    interactive_selectors = [
                        'button[aria-label="Open Sidenav"]',
                        'button[aria-label="Show/hide account menu"]', # Juice Shop Account
                        'button[aria-label="Show basket"]',             # Juice Shop Basket
                        'mat-icon:has-text("account_circle")',
                        'mat-icon:has-text("shopping_cart")',
                        'button[aria-label="Open Side Menu"]',
                        '.mat-toolbar-row button', 
                        'button:has-text("Menu")',
                        '.navbar-toggler',
                        '[aria-haspopup="true"]'
                    ]
                    
                    for sel in interactive_selectors:
                        # Optimization: Only interact with global nav elements once per session
                        if sel in interacted_selectors:
                            continue
                            
                        # Ensure state is clean before interacting
                        try:
                            if await page.is_visible('.cdk-overlay-backdrop') or await page.is_visible('.mat-mdc-dialog-container'):
                                await page.keyboard.press("Escape")
                                await page.wait_for_timeout(500)
                        except Exception: pass

                        if await page.is_visible(sel):
                            logger.info(f"[{role_name}] Found interactive element: {sel}")
                            
                            # Capture UI Element Identity
                            if role_ui_elements is not None:
                                try:
                                    el = page.locator(sel).first
                                    id_text = (await el.inner_text() or await el.get_attribute("aria-label") or await el.get_attribute("id") or sel).strip()
                                    if id_text:
                                        role_ui_elements[role_name].add(f"Interactive: {id_text}")
                                except Exception: pass

                            try:
                                # Check if this element triggers navigation (href or routerlink)
                                element = page.locator(sel).first
                                is_nav = await element.evaluate("""el => {
                                    return el.hasAttribute('href') || 
                                           el.hasAttribute('routerlink') || 
                                           el.closest('a[href]') !== null || 
                                           el.closest('[routerlink]') !== null;
                                }""")
                                
                                if is_nav:
                                    # It's a link! Don't click it yet (would leave page).
                                    # Just extract the link and add to queue.
                                    logger.info(f"[{role_name}] Element is a navigation link. Queuing without clicking.")
                                    
                                    # Extract specifically from this element or its parent
                                    nav_info = await element.evaluate("""el => {
                                        const anchor = el.closest('a[href]') || el.closest('[routerlink]');
                                        if (!anchor) return null;
                                        return {
                                            href: anchor.getAttribute('href'),
                                            routerLink: anchor.getAttribute('routerlink')
                                        };
                                    }""")
                                    
                                    if nav_info:
                                        target_path = nav_info['href'] or nav_info['routerLink']
                                        if target_path:
                                            # Juice Shop uses routerlink="/basket", but routing is at #/basket
                                            if nav_info['routerLink'] and not target_path.startswith('#'):
                                                target_path = "#" + target_path
                                            
                                            full_url = normalize_crawl_link(target_path, page.url)
                                            if full_url:
                                                _add_crawl_candidate(full_url)

                                    # Mark as interacted so we don't check again
                                    interacted_selectors.add(sel)
                                    continue

                                # If NOT a link, proceed with Click/Hover logic
                                logger.info(f"[{role_name}] Interacting (Menu/Toggle): {sel}")
                                
                                # Proactively hover first (triggers CSS hover menus)
                                await page.hover(sel)
                                await page.wait_for_timeout(200)
                                
                                await page.click(sel)
                                await page.wait_for_timeout(1000) # Wait for animation/render
                                
                                # Mark as interacted so we don't repeat on every page
                                interacted_selectors.add(sel)
                                
                                # --- Incremental Link Extraction (Level 1) ---
                                try:
                                    sub_links = await _bounded_crawl_await(
                                        extract_links(page, final_url if 'final_url' in locals() else page.url),
                                        CRAWL_DOM_TIMEOUT_SEC,
                                        set(),
                                        role_name,
                                        "extracting menu links",
                                    )
                                    for sl in sub_links:
                                        _add_crawl_candidate(sl)
                                except Exception:
                                    pass

                                # --- Sub-Item Discovery (Level 2: Jiggle the Handle) ---
                                # Look for visible list items inside the open menu and hover them
                                try:
                                    # Selectors for common menu items (Lists and Menus)
                                    sub_item_selectors = [
                                        '.mat-mdc-list-item', 'mat-list-item', 
                                        '.mat-mdc-menu-item', 'button[mat-menu-item]',
                                        '[role="menuitem"]', 'li.nav-item'
                                    ]
                                    
                                    # Strategy: Identify Parents by Text first to handle Accordion shifting
                                    parent_texts = []
                                    try:
                                        # Scan for parents first
                                        all_items = await page.locator(', '.join(sub_item_selectors)).all()
                                        for item in all_items[:20]: # Increased limit for deep menus
                                            if await item.is_visible():
                                                cls = await item.get_attribute("class") or ""
                                                txt = await item.text_content() or ""
                                                aria_popup = await item.get_attribute("aria-haspopup") or ""
                                                
                                                # Check if parent: explicitly marked, has expand icon, or has aria-haspopup
                                                is_parent = ("parent" in cls or "expand" in txt or 
                                                             aria_popup != "" or
                                                             await item.locator("mat-icon:has-text('expand_more')").count() > 0 or
                                                             await item.locator("svg.mat-mdc-menu-submenu-icon").count() > 0)
                                                
                                                if is_parent and txt.strip():
                                                    parent_texts.append(txt.strip())
                                    except Exception: pass
                                    
                                    # 1. Interact with identified Parents (Click/Expand)
                                    for p_text in parent_texts:
                                        try:
                                            # Find by text - more generic locator
                                            item = page.locator(f":is({', '.join(sub_item_selectors)}):has-text('{p_text}')").first
                                            if await item.is_visible():
                                                logger.info(f"[{role_name}] Expanding parent: {p_text}")
                                                await item.click()
                                                # Increased wait for sub-menu animation and link rendering
                                                await page.wait_for_timeout(1500)
                                                
                                                # Extract links while expanded
                                                sub_links = await _bounded_crawl_await(
                                                    extract_links(page, final_url if 'final_url' in locals() else page.url),
                                                    CRAWL_DOM_TIMEOUT_SEC,
                                                    set(),
                                                    role_name,
                                                    f"extracting links after expanding {p_text[:40]}",
                                                )
                                                logger.debug(f"[{role_name}] Incremental extraction for '{p_text}' found {len(sub_links)} links.")
                                                for sl in sub_links:
                                                    _add_crawl_candidate(sl)
                                        except Exception: pass

                                    # 2. Hover pass for everything else (non-parents / flat lists)
                                    # This catches items that are just links but might have hover effects
                                    # We do this AFTER parent expansion attempts to cover default state
                                    for sub_sel in sub_item_selectors:
                                        count = await page.locator(sub_sel).count()
                                        for i in range(min(count, 10)):
                                            try:
                                                item = page.locator(sub_sel).nth(i)
                                                if await item.is_visible():
                                                    await item.hover()
                                                    await page.wait_for_timeout(200)
                                            except Exception: pass
                                            
                                    # Final extract after hover pass
                                    final_sub = await _bounded_crawl_await(
                                        extract_links(page, final_url if 'final_url' in locals() else page.url),
                                        CRAWL_DOM_TIMEOUT_SEC,
                                        set(),
                                        role_name,
                                        "extracting final menu links",
                                    )
                                    for sl in final_sub:
                                        _add_crawl_candidate(sl)
                                except Exception: pass
                                
                                # --- Reset State ---
                                # Escape and Click-off to ensure clean slate for next interaction
                                await page.keyboard.press("Escape")
                                await page.mouse.click(10, 10) # Click top-left safe zone
                                await page.wait_for_timeout(500)
                                
                            except Exception:
                                pass
                            
                except Exception:
                    pass
                
                # Interaction: Click items that might open modals (Juice Shop products)
                # This helps find links inside product details
                try:
                    # Limit to first few items to avoid massive crawl times
                    items = await page.locator('.mat-card, .product, .item-card').all()
                    for i, item in enumerate(items[:3]): 
                        if await item.is_visible():
                            await item.click()
                            await page.wait_for_timeout(500)
                            # Close the modal if one appeared (Esc)
                            await page.keyboard.press("Escape")
                            await page.wait_for_timeout(200)
                except Exception: pass
                
                await page.wait_for_timeout(delay)

                # Check for redirects and update allowed domains on first hit
                final_url = page.url
                parsed_final = urlparse(final_url)
                
                # Extract links now, before SPA discovery can navigate away
                _pre_spa_links = await _bounded_crawl_await(
                    extract_links(page, final_url),
                    CRAWL_DOM_TIMEOUT_SEC,
                    set(),
                    role_name,
                    "extracting links before SPA discovery",
                )
                _embedded_links = await _bounded_crawl_await(
                    extract_embedded_links(page, final_url),
                    CRAWL_DOM_TIMEOUT_SEC,
                    set(),
                    role_name,
                    "extracting iframe and shadow-DOM links",
                )
                _pre_spa_links |= _embedded_links
                _form_candidates = await _bounded_crawl_await(
                    extract_form_candidates(page, final_url, role_name),
                    CRAWL_FAST_TIMEOUT_SEC,
                    [],
                    role_name,
                    "inventorying forms",
                )
                recon_inventory.extend(_form_candidates)
                await _bounded_crawl_await(
                    probe_lazy_scroll(page, recon_inventory),
                    CRAWL_FAST_TIMEOUT_SEC,
                    None,
                    role_name,
                    "probing bounded lazy scroll",
                )
                await _bounded_crawl_await(
                    probe_safe_filter_selects(page, role_name, recon_inventory),
                    CRAWL_DOM_TIMEOUT_SEC,
                    None,
                    role_name,
                    "probing safe filter options",
                )

                # --- Nav Expansion Pass (always-on) ---
                # Hover and click items within nav/sidebar/menu containers to reveal
                # dropdown sub-navigation without full monkey-clicking.
                if not spa_mode:
                    try:
                        # --- Hamburger / toggle button pass ---
                        # Click toggle buttons that reveal nav drawers/sidebars, harvest links, then close.
                        _hamburger_selectors = (
                            'button[aria-label*="menu" i], button[aria-label*="hamburger" i], '
                            'button[aria-label*="navigation" i], button[aria-label*="toggle" i], '
                            'button[aria-label*="open menu" i], button[aria-label*="sidebar" i], '
                            'button[aria-label*="account" i], button[aria-label*="profile" i], '
                            'button[aria-label*="user" i], button[aria-label*="avatar" i], '
                            'button[aria-controls][aria-expanded], '
                            '#mega-menu-toggle, #menu-toggle, #nav-toggle, #hamburger, '
                            '#user-menu, #account-menu, #profile-menu, '
                            '.hamburger, .hamburger-menu, .menu-toggle, .nav-toggle, '
                            '.navbar-toggler, .sidebar-toggle, '
                            '.avatar, .user-avatar, .profile-avatar, '
                            '[data-testid*="avatar" i], [data-testid*="profile" i], '
                            '[data-testid*="user-menu" i], [data-testid*="account" i]'
                        )
                        _hamburgers = await page.locator(_hamburger_selectors).all()
                        for _hb in _hamburgers[:5]:
                            try:
                                if not await _hb.is_visible():
                                    continue
                                # Skip if already expanded
                                _expanded_attr = await _hb.get_attribute("aria-expanded")
                                if _expanded_attr == "true":
                                    continue
                                await _hb.click(timeout=1500)
                                await page.wait_for_timeout(800)
                                _hb_links = await _bounded_crawl_await(
                                    extract_links(page, final_url),
                                    CRAWL_DOM_TIMEOUT_SEC,
                                    set(),
                                    role_name,
                                    "extracting hamburger menu links",
                                )
                                _interact_and_collect_links(_hb_links, allowed_domains, discovered_endpoints, visited, to_visit, visited_normalized, skip_auth_exit=authenticated_crawl)
                                # Close the menu
                                await page.keyboard.press("Escape")
                                await page.wait_for_timeout(300)
                            except Exception:
                                pass
                    except Exception:
                        pass

                    try:
                        _nav_containers = await page.locator(
                            'nav, [role="navigation"], [role="menubar"], '
                            '.sidebar, #sidebar, .side-nav, #sidenav, '
                            '.navbar, .navbar-nav, .nav-menu, .main-menu, '
                            '.menu-wrapper, #menu, .site-nav, .primary-nav'
                        ).all()
                        for _nc in _nav_containers[:6]:
                            try:
                                # Find items that likely have sub-menus
                                _expandables = await _nc.locator(
                                    '[aria-haspopup], [aria-expanded="false"], '
                                    '.dropdown-toggle, .has-children, .has-submenu, '
                                    'li:has(ul), li:has(ol)'
                                ).all()
                                for _ex in _expandables[:15]:
                                    try:
                                        if not await _ex.is_visible():
                                            continue
                                        await _ex.hover(timeout=TIMEOUT_SHORT)
                                        await page.wait_for_timeout(300)
                                        await _ex.click(timeout=TIMEOUT_SHORT)
                                        await page.wait_for_timeout(500)
                                        _nav_links = await _bounded_crawl_await(
                                            extract_links(page, final_url),
                                            CRAWL_DOM_TIMEOUT_SEC,
                                            set(),
                                            role_name,
                                            "extracting expanded nav links",
                                        )
                                        _interact_and_collect_links(_nav_links, allowed_domains, discovered_endpoints, visited, to_visit, visited_normalized, skip_auth_exit=authenticated_crawl)
                                        await page.keyboard.press("Escape")
                                        await page.wait_for_timeout(200)
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                    except Exception:
                        pass

                # JS-hook harvest: catches any XHR/fetch not yet picked up by the network listener
                _page_api_call_count = 0
                if api_harvest_mode:
                    _page_calls = await _bounded_crawl_await(
                        _harvest_api_log(page, final_url, allowed_domains),
                        CRAWL_FAST_TIMEOUT_SEC,
                        [],
                        role_name,
                        "harvesting page API calls",
                    )
                    # Dedup against what the network listener already captured
                    for _pc in _page_calls:
                        _remember_api_call(_pc)
                    _page_api_call_count = max(
                        len(_page_calls),
                        len(discovered_api_calls) - api_count_before_page,
                    )
                    if _page_calls:
                        logger.info(f"[{role_name}] JS-hook harvest: {len(_page_calls)} additional API calls on {urlparse(final_url).path or '/'}")

                interaction_profile = {}
                spa_discovery_active = bool(spa_mode)
                # Large commerce/catalog pages can expose hundreds of controls and
                # continuously mutate the DOM.  Allow callers doing a broad route/API
                # inventory to disable adaptive clicking without disabling network and
                # JavaScript-hook harvesting.  Forced --spa mode still takes priority.
                adaptive_spa_disabled = os.environ.get("SK_DISABLE_ADAPTIVE_SPA", "").lower() in {
                    "1", "true", "yes", "on"
                }
                if not spa_discovery_active and not adaptive_spa_disabled:
                    interaction_profile = await _bounded_crawl_await(
                        assess_interaction_profile(
                            page,
                            link_count=len(_pre_spa_links),
                            api_call_count=_page_api_call_count,
                        ),
                        CRAWL_FAST_TIMEOUT_SEC,
                        {},
                        role_name,
                        "assessing SPA interaction profile",
                    )
                    spa_discovery_active = bool(interaction_profile.get("should_interact"))

                # --- SPA Mode: Systematic Discovery (Click and Rescan with Priority) ---
                if spa_discovery_active:
                    if spa_mode:
                        logger.info(f"[{role_name}] SPA Discovery: Starting forced discovery on {current_url}")
                    else:
                        _reasons = ", ".join(interaction_profile.get("reasons") or ["dynamic page signals"])
                        logger.info(f"[{role_name}] SPA Discovery: Adaptive mode on {current_url} ({_reasons})")
                    try:
                        click_selectors = [
                            'button', 'a', '[role="button"]', '[role="link"]',
                            '[role="tab"]', '[role="option"]', '[role="combobox"]', '[role="treeitem"]',
                            '[role="gridcell"]', '[role="menuitem"]',
                            'input[type="button"]', 'input[type="submit"]',
                            'a.btn', 'div.btn', 'span.btn',
                            'div[onclick]', 'li[onclick]', 'span[onclick]', 'td[onclick]',
                            '[data-action]', '[ng-click]', '[ui-sref]', '[data-ui-sref]',
                            '[tabindex]:not([tabindex="-1"])',
                            '.mat-mdc-button-base', '.mat-mdc-raised-button',
                            '.btn', '.button',
                            'mat-list-item', '.mat-list-item', 'li.nav-item'
                        ]
                        selector_str = ", ".join(click_selectors)
                        
                        to_click_queue = [] # Identities to click
                        known_identities = set() # Identities we've ever seen
                        clicked_identities = set() # Identities we've actually clicked
                        identity_discovery_times = {} # interaction count when first seen
                        element_activator = {} # {child_identity: activator_identity that revealed it}
                        last_successful_click_identity = None # Identity of the last successfully clicked element
                        element_group = {} # {identity: container_key} — nearest menu/list ancestor
                        dismissed_contexts = set() # Activator identities whose panels were explicitly closed
                        label_click_counts = {}  # {friendly_name_lower: count} — caps re-clicks on re-rendered lists
                        LABEL_CLICK_CAP = 3       # stop after N clicks of the same visible label
                        no_progress_clicks = {}   # semantic_key -> repeated clicks that changed nothing useful
                        nav_toggle_clicks = set() # semantic keys for nav/profile/menu toggles already tried on this route
                        queued_navigation_identities = set() # direct route links already queued for normal crawl
                        low_value_no_progress_groups = {} # route+code-shape -> no-progress examples clicked
                        NO_PROGRESS_CAP = 2 if spa_mode else 1
                        LOW_VALUE_GROUP_CAP = 2

                        # === SPA Interaction Memory ===
                        # Persists across multiple opens of the same modal/drawer so the crawler
                        # can correctly scope elements and close panels without guessing.
                        modal_closer_memory = {}   # opener_identity → closer_identity
                        modal_contents_memory = {} # opener_identity → set[identity]
                        _modal_opener_identity = None  # which button opened the current modal

                        modal_active_since = None
                        modal_escape_attempts = 0
                        start_page_url = page.url
                        if spa_max_clicks > 0:
                            max_interactions = spa_max_clicks
                        elif spa_mode:
                            max_interactions = float('inf')
                        else:
                            max_interactions = ADAPTIVE_SPA_CLICK_CAP
                        interactions = 0
                        _initial_retry_done = False

                        # Wait for at least one interactive element before scanning (React/Angular may still be mounting)
                        try:
                            await page.wait_for_selector('button, [role="button"], a[href]', state='visible', timeout=5000)
                        except Exception:
                            pass

                        while interactions < max_interactions:
                            # 0. Aggressive Modal Detection
                            # Includes MUI, Angular Material, Bootstrap, and ARIA-based patterns
                            modal_indicators = [
                                '.cdk-overlay-backdrop', '.MuiBackdrop-root', '[role="dialog"]',
                                '[aria-modal="true"][role="dialog"]', '[aria-modal="true"][role="alertdialog"]',
                                '.mat-mdc-dialog-container', '.modal-backdrop',
                                '.MuiPopover-paper', '.MuiDialog-container', '.MuiModal-root',
                                '.fixed.inset-0', '.absolute.inset-0', # Tailwind patterns
                                '.ui-widget-overlay', '.jbox-overlay',
                                # NOTE: do NOT add MuiDrawer-paper here — MUI always keeps the
                                # drawer element in the DOM (just off-screen via CSS transform)
                                # which would permanently trigger modal detection. The geometric
                                # heuristic below correctly detects drawers only when OPEN.
                                # Live chat / chatbot widgets — treat as modal to isolate clicks
                                '.intercom-app', '.intercom-lightweight-app',
                                '.drift-widget-container', '#drift-widget',
                                '#hubspot-messages-iframe-container',
                                '.crisp-client', '#crisp-chatbox',
                                '#launcher',  # Zendesk
                                '.tawk-min-container', '#tawkchat-container',
                            ]
                            modal_selectors = ", ".join(modal_indicators)
                            
                            is_modal_visible = False
                            try:
                                # Heuristic: Check if any known modal selector is visible OR
                                # if there is a fixed/absolute element covering a large portion of
                                # the VISIBLE viewport. Uses getBoundingClientRect() rather than
                                # offsetWidth/offsetHeight so CSS-transformed-off-screen elements
                                # (e.g. a closed MUI Drawer with transform:translateX(100%)) are
                                # NOT falsely detected as modals.
                                is_modal_visible = await page.evaluate(f"""() => {{
                                    const selectors = "{modal_selectors}";
                                    const modalEl = document.querySelector(selectors);
                                    if (modalEl) {{
                                        const r = modalEl.getBoundingClientRect();
                                        // Must overlap the visible viewport meaningfully
                                        if (r.width > 0 && r.height > 0 &&
                                            r.left < window.innerWidth && r.right > 0 &&
                                            r.top < window.innerHeight && r.bottom > 0) return true;
                                    }}

                                    const els = document.querySelectorAll('div, section');
                                    for (const el of els) {{
                                        const style = window.getComputedStyle(el);
                                        if ((style.position === 'fixed' || style.position === 'absolute') &&
                                            parseInt(style.zIndex) > 100 &&
                                            style.display !== 'none' && style.visibility !== 'hidden' &&
                                            parseFloat(style.opacity) > 0.1) {{
                                            const r = el.getBoundingClientRect();
                                            if (r.width > (window.innerWidth * 0.4) &&
                                                r.height > (window.innerHeight * 0.4) &&
                                                r.left < window.innerWidth && r.right > 0 &&
                                                r.top < window.innerHeight && r.bottom > 0) {{
                                                return true;
                                            }}
                                        }}
                                    }}
                                    return false;
                                }}""")
                            except Exception: pass

                            if is_modal_visible:
                                if modal_active_since is None:
                                    modal_active_since = interactions
                                    modal_escape_attempts = 0
                                    _modal_opener_identity = last_successful_click_identity
                                    logger.info(f"[{role_name}] SPA Discovery: Modal/Overlay detected. Focusing content.")
                                    # Memory: if we've seen this modal before, re-queue the known closer
                                    # so it gets clicked last (second pass) without needing to rediscover it.
                                    if _modal_opener_identity and _modal_opener_identity in modal_closer_memory:
                                        _known_closer = modal_closer_memory[_modal_opener_identity]
                                        clicked_identities.discard(_known_closer)          # allow re-click in second pass
                                        if _known_closer not in to_click_queue:
                                            to_click_queue.insert(0, _known_closer)        # front so second pass finds it fast
                                            _kc_label = _known_closer.split('|')[4][:30] if '|' in _known_closer else _known_closer[:30]
                                            logger.info(f"[{role_name}] SPA Memory: Re-queued known closer '{_kc_label}' at queue front.")
                                    # Fix 6: Pre-populate modal_contents_memory from common MUI Drawer / overlay
                                    # selectors. Handles elements that passed the initial viewport check and were
                                    # assigned element_activator=None, making them invisible to disc_time scoping.
                                    if _modal_opener_identity and _modal_opener_identity not in modal_contents_memory:
                                        for _mcs in ['.MuiDrawer-paper', '.MuiDrawer-root', '[aria-modal="true"] > div',
                                                     '[role="presentation"] > div[tabindex="-1"]']:
                                            try:
                                                _mc_container = page.locator(_mcs).first
                                                if await _mc_container.is_visible(timeout=TIMEOUT_BRIEF):
                                                    for _mc_el in await _mc_container.locator(selector_str).all():
                                                        try:
                                                            if not await _mc_el.is_visible(): continue
                                                            _mc_t = (await _mc_el.text_content() or "").strip()
                                                            _mc_a = (await _mc_el.get_attribute("aria-label") or "").strip()
                                                            _mc_i = (await _mc_el.get_attribute("id") or "").strip()
                                                            _mc_r = (await _mc_el.get_attribute("role") or "").strip()
                                                            _mc_g = await _mc_el.evaluate("el => el.tagName.toLowerCase()")
                                                            _mc_c = (await _mc_el.get_attribute("class") or "").strip()
                                                            _mc_nav = ""
                                                            try:
                                                                _mc_nav = await _mc_el.evaluate("""el => {
                                                                    const stateToHash = (v) => {
                                                                        if (!v) return '';
                                                                        const state = String(v).trim().split('(')[0].trim();
                                                                        if (!state) return '';
                                                                        if (state.startsWith('#')) return state;
                                                                        if (state.startsWith('/')) return '#' + state;
                                                                        return '#/' + state.replace(/\\./g, '/');
                                                                    };
                                                                    const selfState = el.getAttribute('ui-sref') || el.getAttribute('data-ui-sref');
                                                                    if (selfState) return stateToHash(selfState);
                                                                    const self = el.getAttribute('href') || el.getAttribute('routerlink') ||
                                                                        el.getAttribute('ng-reflect-router-link') || el.getAttribute('data-href') ||
                                                                        el.getAttribute('data-url') || el.getAttribute('data-route');
                                                                    if (self) return self;
                                                                    const anchor = el.closest('a[href]') || el.closest('[routerlink]') || el.closest('[ng-reflect-router-link]') ||
                                                                        el.closest('[ui-sref]') || el.closest('[data-ui-sref]') ||
                                                                        el.querySelector('a[href], [routerlink], [ng-reflect-router-link], [ui-sref], [data-ui-sref], [data-href], [data-url], [data-route]');
                                                                    if (!anchor) return '';
                                                                    const anchorState = anchor.getAttribute('ui-sref') || anchor.getAttribute('data-ui-sref');
                                                                    if (anchorState) return stateToHash(anchorState);
                                                                    return anchor.getAttribute('href') || anchor.getAttribute('routerlink') ||
                                                                        anchor.getAttribute('ng-reflect-router-link') || anchor.getAttribute('data-href') ||
                                                                        anchor.getAttribute('data-url') || anchor.getAttribute('data-route') || '';
                                                                }""") or ""
                                                            except Exception:
                                                                pass
                                                            _mc_ident = build_click_identity(_mc_g, _mc_r, _mc_i, _mc_a, _mc_t, _mc_c, _mc_nav)
                                                            modal_contents_memory.setdefault(_modal_opener_identity, set()).add(_mc_ident)
                                                        except Exception:
                                                            pass
                                                    if _modal_opener_identity in modal_contents_memory:
                                                        logger.info(f"[{role_name}] SPA Memory: Pre-populated {len(modal_contents_memory[_modal_opener_identity])} inner elements from '{_mcs}'.")
                                                    break
                                            except Exception:
                                                pass
                            else:
                                if modal_active_since is not None:
                                    logger.info(f"[{role_name}] SPA Discovery: Modal cleared.")
                                    _closer_candidate = last_successful_click_identity
                                    # Memory: learn which button just closed this modal
                                    if _closer_candidate and _modal_opener_identity:
                                        if _modal_opener_identity not in modal_closer_memory:
                                            modal_closer_memory[_modal_opener_identity] = _closer_candidate
                                            _op_label = _modal_opener_identity.split('|')[4][:30] if '|' in _modal_opener_identity else _modal_opener_identity[:30]
                                            _cl_label = _closer_candidate.split('|')[4][:30] if '|' in _closer_candidate else _closer_candidate[:30]
                                            logger.info(f"[{role_name}] SPA Memory: Learned '{_cl_label}' closes modal opened by '{_op_label}'.")
                                    # Decide whether to re-queue interior elements.
                                    # Don't re-queue if the modal was properly dismissed: either by a
                                    # recognised dismiss button, or by the memorised closer for this opener.
                                    _last_was_dismiss = bool(
                                        (_closer_candidate and is_modal_dismiss_identity(_closer_candidate)) or
                                        (_closer_candidate and _modal_opener_identity and
                                         modal_closer_memory.get(_modal_opener_identity) == _closer_candidate)
                                    )
                                    if not _last_was_dismiss:
                                        for ident, disc_time in list(identity_discovery_times.items()):
                                            if disc_time >= modal_active_since:
                                                clicked_identities.discard(ident)
                                    # Mark the activator that opened this panel as a dismissed context.
                                    if _modal_opener_identity:
                                        dismissed_contexts.add(_modal_opener_identity)
                                        _dc_label = _modal_opener_identity.split('|')[4][:30] if '|' in _modal_opener_identity else _modal_opener_identity[:30]
                                        logger.info(f"[{role_name}] SPA Discovery: Modal cleared — marked opener '{_dc_label}' as dismissed context.")
                                    _modal_opener_identity = None
                                modal_active_since = None
                                modal_escape_attempts = 0

                            # 1. Scan DOM for current candidates
                            candidates = await page.locator(selector_str).all()
                            
                            # 2. Update Discovery Queue (Depth-First Priority)
                            current_scan_results = []
                            new_discoveries = []
                            
                            for el in candidates:
                                try:
                                    if not await el.is_visible(): continue

                                    # Extra viewport-intersection check: Playwright's is_visible() does NOT
                                    # account for CSS transforms. A MUI Drawer with translateX(100%) is
                                    # technically "visible" by Playwright but is off-screen. We must skip
                                    # such elements so they are only discovered once the drawer actually opens.
                                    try:
                                        _in_vp = await el.evaluate("""el => {
                                            const r = el.getBoundingClientRect();
                                            return r.width > 0 && r.height > 0 &&
                                                   r.right > 0 && r.left < window.innerWidth &&
                                                   r.bottom > 0 && r.top < window.innerHeight;
                                        }""")
                                        if not _in_vp:
                                            continue
                                    except Exception:
                                        pass  # can't determine — include element (safe fallback)

                                    # Identity for tracking
                                    el_tag = await el.evaluate("el => el.tagName.toLowerCase()")
                                    text = (await el.text_content() or "").strip()
                                    aria_label = (await el.get_attribute("aria-label") or "").strip()
                                    el_id = (await el.get_attribute("id") or "").strip()
                                    el_role = (await el.get_attribute("role") or "").strip()
                                    el_title = (await el.get_attribute("title") or "").strip()
                                    el_name = (await el.get_attribute("name") or "").strip()
                                    el_class = (await el.get_attribute("class") or "").strip()
                                    nav_url = ""
                                    try:
                                        nav_url = await el.evaluate("""el => {
                                            const stateToHash = (v) => {
                                                if (!v) return '';
                                                const state = String(v).trim().split('(')[0].trim();
                                                if (!state) return '';
                                                if (state.startsWith('#')) return state;
                                                if (state.startsWith('/')) return '#' + state;
                                                return '#/' + state.replace(/\\./g, '/');
                                            };
                                            const selfState = el.getAttribute('ui-sref') || el.getAttribute('data-ui-sref');
                                            if (selfState) return stateToHash(selfState);
                                            const self_href = el.getAttribute('href') ||
                                                              el.getAttribute('routerlink') ||
                                                              el.getAttribute('ng-reflect-router-link') ||
                                                              el.getAttribute('data-href') ||
                                                              el.getAttribute('data-url') ||
                                                              el.getAttribute('data-route');
                                            if (self_href) return self_href;
                                            const anchor = el.closest('a[href]') || el.closest('[routerlink]') || el.closest('[ng-reflect-router-link]') ||
                                                el.closest('[ui-sref]') || el.closest('[data-ui-sref]') ||
                                                el.querySelector('a[href], [routerlink], [ng-reflect-router-link], [ui-sref], [data-ui-sref], [data-href], [data-url], [data-route]');
                                            if (anchor) {
                                                const anchorState = anchor.getAttribute('ui-sref') || anchor.getAttribute('data-ui-sref');
                                                if (anchorState) return stateToHash(anchorState);
                                                return anchor.getAttribute('href') ||
                                                       anchor.getAttribute('routerlink') ||
                                                       anchor.getAttribute('ng-reflect-router-link') ||
                                                       anchor.getAttribute('data-href') ||
                                                       anchor.getAttribute('data-url') ||
                                                       anchor.getAttribute('data-route') || '';
                                            }
                                            return '';
                                        }""") or ""
                                    except Exception:
                                        nav_url = ""
                                    
                                    identity = build_click_identity(
                                        el_tag, el_role, el_id, aria_label, text, el_class, nav_url
                                    )
                                    current_scan_results.append((identity, el, text, aria_label, el_id, el_title, el_name, el_tag, el_role))

                                    # Route-like elements are cheaper and more reliable as queued
                                    # crawl targets than as SPA clicks. Do this every scan, not only
                                    # on first discovery, because Angular can hydrate href/ui-sref
                                    # after the element identity was first observed.
                                    try:
                                        full_nav_url = normalize_crawl_link(nav_url, page.url)
                                        if full_nav_url and _add_crawl_candidate(full_nav_url):
                                            queued_navigation_identities.add(identity)
                                    except Exception:
                                        pass
                                    
                                    if identity not in known_identities:
                                        new_discoveries.append(identity)
                                        known_identities.add(identity)
                                        identity_discovery_times[identity] = interactions
                                        # Record which activator click caused this element to appear.
                                        # Used later to re-expand collapsed menus after back-navigation.
                                        element_activator[identity] = last_successful_click_identity
                                        # Record the nearest menu/list container so siblings can be
                                        # detected even when the menu was pre-expanded (activator = None).
                                        try:
                                            grp = await el.evaluate("""el => {
                                                let p = el.parentElement;
                                                for (let i = 0; i < 6; i++) {
                                                    if (!p) return null;
                                                    const cls = p.className || '';
                                                    const tag = p.tagName;
                                                    const role = (p.getAttribute && p.getAttribute('role')) || '';
                                                    // Match shared container classes — but NOT MuiListItem-*
                                                    // (each child has its own li wrapper with a unique class,
                                                    //  so matching on MuiList would stop at the wrong level).
                                                    if (cls.includes('wrapperInner') ||
                                                        cls.includes('MuiList-root') ||
                                                        cls.includes('MuiMenu-list') ||
                                                        tag === 'UL' || tag === 'OL' || tag === 'NAV' ||
                                                        role === 'menu' || role === 'listbox' || role === 'list') {
                                                        return tag + '|' + cls.slice(0, 80);
                                                    }
                                                    p = p.parentElement;
                                                }
                                                return null;
                                            }""")
                                            if grp:
                                                element_group[identity] = grp
                                        except Exception: pass

                                except Exception: continue
                                
                            # Prioritize NEW discoveries
                            if new_discoveries:
                                logger.info(f"[{role_name}] SPA Discovery: Found {len(new_discoveries)} new interactive elements.")
                                for nd in reversed(new_discoveries):
                                    to_click_queue.insert(0, nd)

                            # Memory: if a modal is open, tag newly-discovered elements as belonging
                            # to it. On subsequent opens of the same modal, these identities are used
                            # to scope the click queue even if disc_time pre-dates modal_active_since.
                            if new_discoveries and is_modal_visible and _modal_opener_identity:
                                modal_contents_memory.setdefault(_modal_opener_identity, set()).update(new_discoveries)
                                logger.debug(f"[{role_name}] SPA Memory: Learned {len(new_discoveries)} contents for modal '{_modal_opener_identity.split('|')[4][:30] if _modal_opener_identity else '?'}'.")

                            # Debug: log every visible element seen this iteration
                            if logger.isEnabledFor(logging.DEBUG) and current_scan_results:
                                _seen = [r[2] or r[3] or r[4] or r[5] or "?" for r in current_scan_results]
                                logger.debug(f"[{role_name}] Visible elements ({len(_seen)}): {', '.join(_seen[:50])}")

                            # One-time retry: if nothing was found on the very first scan, the JS
                            # framework (React/Angular) may still be mounting. Wait and retry once.
                            if not current_scan_results and interactions == 0 and not _initial_retry_done:
                                _initial_retry_done = True
                                logger.info(f"[{role_name}] SPA Discovery: Initial scan found 0 visible elements. Waiting 3s for full render...")
                                await page.wait_for_timeout(3000)
                                continue
                            
                            # 2b. Disappeared-sibling recovery (SPA accordion collapse without URL change)
                            # If the last click caused queued siblings (same activator/group) to
                            # become invisible — e.g. clicking "Company" closes the Administration
                            # MUI Collapse, hiding Users / Groups & Roles / Organization — re-expand
                            # the activator NOW before we try to find the next target.
                            # This complements the URL-change sibling recovery at step 6.
                            if last_successful_click_identity and not is_modal_visible:
                                _jc_act = element_activator.get(last_successful_click_identity)
                                _jc_grp = element_group.get(last_successful_click_identity)
                                if _jc_act or _jc_grp:
                                    _vis_ids = {r[0] for r in current_scan_results}
                                    _disappeared = [
                                        ident for ident in to_click_queue
                                        if ident not in clicked_identities
                                        and ident not in _vis_ids
                                        and (
                                            (_jc_act is not None and element_activator.get(ident) == _jc_act)
                                            or (_jc_grp is not None and element_group.get(ident) == _jc_grp)
                                        )
                                    ]
                                    if _disappeared:
                                        _act_str = (last_successful_click_identity.split('|')[4][:30]).strip()
                                        logger.info(f"[{role_name}] SPA Discovery: {len(_disappeared)} sibling(s) disappeared after clicking '{_act_str}'. Re-expanding activator.")
                                        last_successful_click_identity = None  # prevent re-triggering next iter
                                        _expanded = False
                                        if _jc_act:
                                            activator_parts = _jc_act.split('|')
                                            activator_text = activator_parts[4].strip() if len(activator_parts) >= 5 else ""
                                            activator_aria = activator_parts[3].strip() if len(activator_parts) >= 4 else ""
                                            _a_role = activator_parts[1].strip() if len(activator_parts) >= 2 else ""
                                            _a_id   = activator_parts[2].strip() if len(activator_parts) >= 3 else ""
                                            try:
                                                if activator_aria:
                                                    recovered_element = page.locator(f'[aria-label="{activator_aria}"]').first
                                                elif _a_id:
                                                    recovered_element = page.locator(f'[id="{_a_id}"]').first
                                                elif activator_text and _a_role:
                                                    recovered_element = page.locator(f'[role="{_a_role}"]:has-text("{activator_text}")').first
                                                elif activator_text:
                                                    recovered_element = page.locator(f':has-text("{activator_text}")').first
                                                else:
                                                    recovered_element = None
                                                if recovered_element and await recovered_element.is_visible(timeout=TIMEOUT_MEDIUM):
                                                    await recovered_element.click(timeout=TIMEOUT_MEDIUM)
                                                    await page.wait_for_timeout(800)
                                                    _expanded = True
                                                    logger.info(f"[{role_name}] SPA Discovery: Re-expanded '{activator_text or activator_aria}'. Resuming sibling clicks.")
                                            except Exception as _re_err:
                                                logger.warning(f"[{role_name}] SPA Discovery: Re-expand for disappeared siblings failed: {_re_err}")
                                        if _expanded:
                                            continue  # re-scan DOM to pick up newly visible siblings

                            # 3. Find the next target
                            target_identity = None
                            target_info = None
                            
                            _modal_scoped = modal_active_since is not None and modal_escape_attempts < 2

                            # Memory-based modal helpers for target selection
                            _modal_known_contents = modal_contents_memory.get(_modal_opener_identity) if _modal_opener_identity else None
                            _modal_known_closer   = modal_closer_memory.get(_modal_opener_identity)   if _modal_opener_identity else None

                            def _in_modal_scope(ident):
                                """True if this identity belongs to the current modal context."""
                                # Newly discovered during this modal session
                                if identity_discovery_times.get(ident, 0) >= modal_active_since:
                                    return True
                                # Previously learned as a content element of this exact modal
                                if _modal_known_contents and ident in _modal_known_contents:
                                    return True
                                # Element whose activator IS the opener (pre-existing elements re-exposed by this modal)
                                if (_modal_opener_identity and
                                        element_activator.get(ident) == _modal_opener_identity):
                                    return True
                                return False

                            def _is_this_modal_closer(ident):
                                """True if this identity is a close/dismiss button for the current modal."""
                                return is_modal_dismiss_identity(ident) or ident == _modal_known_closer

                            current_route_for_guards = page.url

                            def _blocked_by_loop_guard(ident):
                                if _modal_scoped:
                                    return False
                                global_key = click_identity_global_key(ident)
                                if global_key in global_handled_chrome_controls:
                                    return True
                                semantic_key = click_identity_semantic_key(ident, current_route_for_guards)
                                if no_progress_clicks.get(semantic_key, 0) >= NO_PROGRESS_CAP:
                                    return True
                                if (
                                    global_no_progress_chrome_controls.get(global_key, 0) >= 2 and
                                    is_persistent_chrome_identity(ident, role_name)
                                ):
                                    return True
                                if is_nav_toggle_identity(ident) and semantic_key in nav_toggle_clicks:
                                    return True
                                label = click_identity_label(ident)
                                if is_low_value_code_label(label) and not click_identity_nav_target(ident):
                                    route_key = normalize_url_for_dedup(current_route_for_guards or "")
                                    group_key = (route_key, low_value_code_group(label))
                                    if low_value_no_progress_groups.get(group_key, 0) >= LOW_VALUE_GROUP_CAP:
                                        return True
                                return False

                            # First pass: visit all explorable modal content before touching close buttons.
                            # Uses memory-based scoping so elements discovered before the modal opened
                            # (e.g. MUI Drawer contents with disc_time=0) are still included correctly.
                            for identity in to_click_queue:
                                if identity in clicked_identities: continue
                                if identity in queued_navigation_identities and not _modal_scoped:
                                    clicked_identities.add(identity)
                                    continue
                                if _blocked_by_loop_guard(identity): continue
                                if _modal_scoped:
                                    if not _in_modal_scope(identity):
                                        continue  # outside this modal's scope
                                    if _is_this_modal_closer(identity):
                                        continue  # defer close/dismiss to second pass
                                for info in current_scan_results:
                                    if info[0] == identity:
                                        target_identity = identity
                                        target_info = info
                                        break
                                if target_identity: break

                            # Second pass (modal only): all explorable content is done — now click
                            # the close/cancel/dismiss button to properly exit the panel.
                            if not target_identity and _modal_scoped:
                                for identity in to_click_queue:
                                    if identity in clicked_identities and identity != _modal_known_closer: continue
                                    if not _in_modal_scope(identity):
                                        continue
                                    for info in current_scan_results:
                                        if info[0] == identity:
                                            target_identity = identity
                                            target_info = info
                                            break
                                    if target_identity: break
                                
                            if not target_identity:
                                # SYSTEMATIC ESCAPE LOGIC
                                if is_modal_visible:
                                    # Fast-path: if we know the closer for this modal, click it directly.
                                    if _modal_known_closer:
                                        _kc_p = _modal_known_closer.split('|')
                                        _kc_aria = _kc_p[3].strip() if len(_kc_p) > 3 else ""
                                        _kc_id   = _kc_p[2].strip() if len(_kc_p) > 2 else ""
                                        _kc_text = _kc_p[4].strip() if len(_kc_p) > 4 else ""
                                        try:
                                            if _kc_aria:
                                                _kc_loc = page.locator(f'[aria-label="{_kc_aria}"]').first
                                            elif _kc_id:
                                                _kc_loc = page.locator(f'[id="{_kc_id}"]').first
                                            elif _kc_text:
                                                _kc_loc = page.locator(f':has-text("{_kc_text}")').first
                                            else:
                                                _kc_loc = None
                                            if _kc_loc and await _kc_loc.is_visible(timeout=TIMEOUT_SHORT):
                                                await _kc_loc.click(timeout=1500)
                                                await page.wait_for_timeout(600)
                                                logger.info(f"[{role_name}] SPA Memory: Clicked known modal closer directly. Retrying.")
                                                continue   # re-enter loop; modal detection will confirm if it closed
                                        except Exception as _kce:
                                            logger.debug(f"[{role_name}] SPA Memory: Known closer direct-click failed: {_kce}")
                                    modal_escape_attempts += 1
                                    if modal_escape_attempts > 3:
                                        logger.warning(f"[{role_name}] SPA Discovery: Modal stuck after {modal_escape_attempts} attempts. Resetting context and continuing.")
                                        # Purge modal-scoped identities so future modal instances still work
                                        for ident, disc_time in list(identity_discovery_times.items()):
                                            if disc_time >= modal_active_since:
                                                clicked_identities.discard(ident)
                                        modal_active_since = None
                                        modal_escape_attempts = 0
                                        continue

                                    logger.info(f"[{role_name}] SPA Discovery: Attempting modal escape (attempt {modal_escape_attempts}).")
                                    # Attempt 1: Escape key (works for most dismissible dialogs)
                                    await page.keyboard.press("Escape")

                                    if modal_escape_attempts >= 1:
                                        logger.info(f"[{role_name}] SPA Discovery: Escape key not working. Trying dismiss_popups (Acknowledge/OK/Close buttons).")
                                        # Attempt 1+: Click named dismiss buttons — handles Acknowledge dialogs
                                        # that require explicit confirmation and ignore Escape.
                                        await dismiss_popups(page)

                                    if modal_escape_attempts >= 3:
                                        logger.info(f"[{role_name}] SPA Discovery: Attempting click-off.")
                                        await page.mouse.click(10, 10)

                                    # Wait for modal to actually disappear (up to 1.5s) instead of flat sleeping
                                    modal_closed = False
                                    try:
                                        escaped_modal_selectors = modal_selectors.replace('"', '\\"')
                                        await page.wait_for_function(
                                            f"""() => {{
                                                const el = document.querySelector("{escaped_modal_selectors}");
                                                if (!el) return true;
                                                const style = window.getComputedStyle(el);
                                                return el.offsetWidth === 0 || el.offsetHeight === 0 ||
                                                       style.display === 'none' || style.visibility === 'hidden' ||
                                                       parseFloat(style.opacity) < 0.05;
                                            }}""",
                                            timeout=1500
                                        )
                                        modal_closed = True
                                    except Exception:
                                        pass

                                    if modal_closed:
                                        logger.info(f"[{role_name}] SPA Discovery: Modal successfully closed.")
                                        for ident, disc_time in list(identity_discovery_times.items()):
                                            if disc_time >= modal_active_since:
                                                clicked_identities.discard(ident)
                                        # Mark the activator that opened this panel as a dismissed context.
                                        # Prevents the pre-click re-expose from reopening it when
                                        # now-stale interior elements are dequeued (e.g. after dismiss_popups
                                        # closes a MUI Drawer via button[aria-label^="close"]).
                                        if _modal_opener_identity:
                                            dismissed_contexts.add(_modal_opener_identity)
                                            _dc_label = _modal_opener_identity.split('|')[4][:30] if '|' in _modal_opener_identity else _modal_opener_identity[:30]
                                            logger.info(f"[{role_name}] SPA Discovery: Modal escape — marked opener '{_dc_label}' as dismissed context.")
                                        modal_active_since = None
                                        modal_escape_attempts = 0
                                        _modal_opener_identity = None    # prevent stale opener from poisoning next modal detection

                                    continue

                                logger.info(f"[{role_name}] SPA Discovery: No more unclicked visible elements in queue.")
                                break
                            
                            # 4. Prepare for Click
                            identity, el, text, aria_label, el_id, el_title, el_name, el_tag, el_role = target_info
                            interactions += 1
                            # Do NOT add to clicked_identities yet — only mark as clicked after a successful
                            # interaction so that modal-blocked failures can be retried once the modal closes.

                            friendly_name = (el_title or el_name or text or aria_label or el_id or "Unnamed").strip()
                            _fn_key = friendly_name.lower()

                            # Always record visible elements in the UI map BEFORE safety checks.
                            # Skipped/destructive elements are still visible to the role and belong in the map.
                            if role_ui_elements is not None:
                                role_ui_elements[role_name].add(f"{el_tag.upper()} ({el_role or 'action'}): {friendly_name}")

                            if authenticated_crawl and soft_auth_overlay_present and is_auth_entry_control(text, aria_label, el_title, el_id, el_name):
                                clicked_identities.add(identity)
                                logger.info(f"[{role_name}] SPA Discovery: Soft-skip auth CTA during authenticated crawl: '{text or aria_label or el_id}'")
                                continue

                            # Re-render guard: if a list re-mounts (React/Angular re-render after
                            # Expand All, Collapse All, or sibling click), the same visible label
                            # comes back with a fresh DOM identity and looks "new". Cap repeats to
                            # prevent infinite loops.
                            if _fn_key and label_click_counts.get(_fn_key, 0) >= LABEL_CLICK_CAP:
                                clicked_identities.add(identity)
                                logger.info(f"[{role_name}] SPA Discovery: Label cap reached for '{friendly_name}' ({LABEL_CLICK_CAP}×) — skipping re-rendered duplicate.")
                                continue

                            # Tier 0: Toggle/switch detection — class-based, no text to match on
                            # MUI Switch and similar components render with an empty-text clickable
                            # wrapper whose child input is the actual checkbox. Clicking it changes state.
                            _TOGGLE_CLASS_INDICATORS = (
                                'MuiSwitch-switchBase', 'PrivateSwitchBase-root',
                                'MuiCheckbox-root', 'rc-switch',
                            )
                            _el_class = ""
                            try:
                                _el_class = (await el.get_attribute("class") or "").strip()
                            except Exception:
                                pass
                            if any(ti in _el_class for ti in _TOGGLE_CLASS_INDICATORS):
                                # Try to get a meaningful label from the child input
                                _child_label = ""
                                try:
                                    _child_label = await el.evaluate("""el => {
                                        const inp = el.querySelector('input[type="checkbox"], input[type="radio"]');
                                        return inp ? (inp.getAttribute('aria-label') || inp.getAttribute('name') || '') : '';
                                    }""")
                                except Exception:
                                    pass
                                _toggle_desc = _child_label or text or aria_label or "toggle switch"
                                if not allow_risky_recon_actions:
                                    clicked_identities.add(identity)
                                    recon_inventory.ui_metrics["risky_actions_skipped"] = recon_inventory.ui_metrics.get("risky_actions_skipped", 0) + 1
                                    logger.info(f"[{role_name}] SPA Discovery: Recon-safe skip (toggle): '{_toggle_desc}'")
                                    continue
                                if ai_client:
                                    _page_title = ""
                                    try:
                                        _page_title = await page.title()
                                    except Exception:
                                        pass
                                    _verdict, _reason = await gemini_risk_check(
                                        ai_client, ai_model,
                                        _toggle_desc, _toggle_desc, el_title, el_role, el_tag,
                                        page.url, _page_title
                                    )
                                    if _verdict == "SKIP":
                                        clicked_identities.add(identity)
                                        logger.info(f"[{role_name}] SPA Discovery: Gemini-skip (toggle): '{_toggle_desc}' — {_reason}")
                                        continue
                                else:
                                    clicked_identities.add(identity)
                                    logger.info(f"[{role_name}] SPA Discovery: Hard-skip toggle/switch (no AI): '{_toggle_desc}'")
                                    continue

                            # Tier 1: Hard skip — always skip, no AI needed
                            if is_hard_skip(text, aria_label, el_title, el_id, el_name, effective_blacklist):
                                clicked_identities.add(identity)
                                recon_inventory.ui_metrics["destructive_actions_skipped"] = recon_inventory.ui_metrics.get("destructive_actions_skipped", 0) + 1
                                logger.info(f"[{role_name}] SPA Discovery: Hard-skip (destructive): '{text or aria_label or el_id}'")
                                continue

                            # Tier 2: Risky terms — ask Gemini for context-aware verdict
                            if is_risky_element(text, aria_label, el_title, el_id, el_name):
                                if not allow_risky_recon_actions:
                                    clicked_identities.add(identity)
                                    recon_inventory.ui_metrics["risky_actions_skipped"] = recon_inventory.ui_metrics.get("risky_actions_skipped", 0) + 1
                                    logger.info(f"[{role_name}] SPA Discovery: Recon-safe skip (risky): '{text or aria_label or el_id}'")
                                    continue
                                if ai_client:
                                    _page_title = ""
                                    try:
                                        _page_title = await page.title()
                                    except Exception:
                                        pass
                                    _verdict, _reason = await gemini_risk_check(
                                        ai_client, ai_model,
                                        text, aria_label, el_title, el_role, el_tag,
                                        page.url, _page_title
                                    )
                                    if _verdict == "SKIP":
                                        clicked_identities.add(identity)
                                        logger.info(f"[{role_name}] SPA Discovery: Gemini-skip (risky): '{text or aria_label}' — {_reason}")
                                        continue
                                    else:
                                        logger.info(f"[{role_name}] SPA Discovery: Gemini approved '{text or aria_label}': {_reason}")
                                else:
                                    # No AI client — skip risky elements as a precaution
                                    clicked_identities.add(identity)
                                    logger.info(f"[{role_name}] SPA Discovery: Skipping risky element (no AI): '{text or aria_label or el_id}'")
                                    continue

                            # Pre-click visibility guard: element may have become stale since the
                            # DOM scan (e.g. Gemini review took a few seconds, or an animation ran).
                            # If invisible, attempt a single activator re-expose to recover it.
                            try:
                                _pre_visible = await el.is_visible(timeout=400)
                            except Exception:
                                _pre_visible = True  # can't check — optimistically proceed

                            if not _pre_visible:
                                logger.debug(f"[{role_name}] SPA Discovery: '{friendly_name}' stale at click time — attempting activator re-expose.")
                                _pre_act = element_activator.get(identity)

                                # If this element's activator panel was explicitly closed,
                                # skip permanently — no point reopening a dismissed drawer/modal.
                                if _pre_act and _pre_act in dismissed_contexts:
                                    clicked_identities.add(identity)
                                    logger.info(f"[{role_name}] SPA Discovery: Context explicitly dismissed — skipping '{friendly_name}' permanently.")
                                    continue

                                _pre_recovered = False
                                if _pre_act:
                                    _pa = _pre_act.split('|')
                                    _pa_text = _pa[4].strip() if len(_pa) >= 5 else ""
                                    _pa_aria = _pa[3].strip() if len(_pa) >= 4 else ""
                                    _pa_role = _pa[1].strip() if len(_pa) >= 2 else ""
                                    _pa_id   = _pa[2].strip() if len(_pa) >= 3 else ""
                                    try:
                                        if _pa_aria:
                                            _pa_loc = page.locator(f'[aria-label="{_pa_aria}"]').first
                                        elif _pa_id:
                                            _pa_loc = page.locator(f'[id="{_pa_id}"]').first
                                        elif _pa_text and _pa_role:
                                            _pa_loc = page.locator(f'[role="{_pa_role}"]:has-text("{_pa_text}")').first
                                        elif _pa_text:
                                            _pa_loc = page.locator(f':has-text("{_pa_text}")').first
                                        else:
                                            _pa_loc = None
                                        if _pa_loc and await _pa_loc.is_visible(timeout=1500):
                                            await _pa_loc.click(timeout=1500)
                                            await page.wait_for_timeout(600)
                                            # Re-scan for the element with a fresh locator
                                            for _fsh in await page.locator(selector_str).all():
                                                try:
                                                    if not await _fsh.is_visible(): continue
                                                    _ft = (await _fsh.text_content() or "").strip()
                                                    _fa = (await _fsh.get_attribute("aria-label") or "").strip()
                                                    _fi = (await _fsh.get_attribute("id") or "").strip()
                                                    _fr = (await _fsh.get_attribute("role") or "").strip()
                                                    _ftg = await _fsh.evaluate("el => el.tagName.toLowerCase()")
                                                    _fc = (await _fsh.get_attribute("class") or "").strip()
                                                    _fnav = ""
                                                    try:
                                                        _fnav = await _fsh.evaluate("""el => {
                                                            const stateToHash = (v) => {
                                                                if (!v) return '';
                                                                const state = String(v).trim().split('(')[0].trim();
                                                                if (!state) return '';
                                                                if (state.startsWith('#')) return state;
                                                                if (state.startsWith('/')) return '#' + state;
                                                                return '#/' + state.replace(/\\./g, '/');
                                                            };
                                                            const selfState = el.getAttribute('ui-sref') || el.getAttribute('data-ui-sref');
                                                            if (selfState) return stateToHash(selfState);
                                                            const self = el.getAttribute('href') || el.getAttribute('routerlink') ||
                                                                el.getAttribute('ng-reflect-router-link') || el.getAttribute('data-href') ||
                                                                el.getAttribute('data-url') || el.getAttribute('data-route');
                                                            if (self) return self;
                                                            const anchor = el.closest('a[href]') || el.closest('[routerlink]') || el.closest('[ng-reflect-router-link]') ||
                                                                el.closest('[ui-sref]') || el.closest('[data-ui-sref]') ||
                                                                el.querySelector('a[href], [routerlink], [ng-reflect-router-link], [ui-sref], [data-ui-sref], [data-href], [data-url], [data-route]');
                                                            if (!anchor) return '';
                                                            const anchorState = anchor.getAttribute('ui-sref') || anchor.getAttribute('data-ui-sref');
                                                            if (anchorState) return stateToHash(anchorState);
                                                            return anchor.getAttribute('href') || anchor.getAttribute('routerlink') ||
                                                                anchor.getAttribute('ng-reflect-router-link') || anchor.getAttribute('data-href') ||
                                                                anchor.getAttribute('data-url') || anchor.getAttribute('data-route') || '';
                                                        }""") or ""
                                                    except Exception:
                                                        pass
                                                    if build_click_identity(_ftg, _fr, _fi, _fa, _ft, _fc, _fnav) == identity:
                                                        el = _fsh
                                                        _pre_recovered = True
                                                        logger.info(f"[{role_name}] SPA Discovery: Re-discovered '{friendly_name}' via pre-click activator re-expose.")
                                                        break
                                                except Exception:
                                                    continue
                                    except Exception as _pae:
                                        logger.debug(f"[{role_name}] SPA Discovery: Pre-click re-expose failed: {_pae}")
                                if not _pre_recovered:
                                    # Can't recover — skip permanently to avoid an infinite stale loop
                                    clicked_identities.add(identity)
                                    logger.warning(f"[{role_name}] SPA Discovery: '{friendly_name}' could not be re-exposed. Skipping permanently.")
                                    continue

                            # 5. Click!
                            pre_click_url = page.url
                            pre_endpoint_count = len(discovered_endpoints)
                            pre_api_count = len(discovered_api_calls)
                            low_value_click = (
                                is_low_value_code_label(friendly_name) and
                                not click_identity_nav_target(identity)
                            )
                            pre_state_sig = ""
                            if not low_value_click:
                                pre_state_sig = await _bounded_crawl_await(
                                    page_state_signature(page),
                                    CRAWL_FAST_TIMEOUT_SEC,
                                    "",
                                    role_name,
                                    "capturing pre-click page state",
                                )
                            semantic_click_key = click_identity_semantic_key(identity, pre_click_url)
                            global_click_key = click_identity_global_key(identity)
                            nav_toggle_click = is_nav_toggle_identity(identity)
                            persistent_chrome_click = is_persistent_chrome_identity(identity, role_name)

                            logger.info(f"[{role_name}] SPA Discovery: Clicking '{friendly_name}' ({interactions})")
                            click_success = False
                            try:
                                # Proactively hover first for CSS-based menus
                                await el.hover(timeout=TIMEOUT_SHORT)
                                await page.wait_for_timeout(200)
                                # Try normal click first — respects visibility/actionability checks
                                await el.click(timeout=TIMEOUT_MEDIUM)
                                click_success = True
                            except Exception:
                                # Fallback: force click for elements obscured by overlays or off-screen
                                try:
                                    await el.click(timeout=TIMEOUT_SHORT, force=True)
                                    click_success = True
                                except Exception:
                                    pass

                            if not click_success:
                                if is_modal_visible:
                                    # Click was likely blocked by the modal overlay — do NOT mark as clicked
                                    # so the element is retried once the modal is dismissed
                                    logger.info(f"[{role_name}] SPA Discovery: '{friendly_name}' blocked by modal. Will retry after modal closes.")
                                else:
                                    # Genuine failure (not modal-related) — mark as clicked to avoid looping
                                    clicked_identities.add(identity)
                                    logger.warning(f"[{role_name}] SPA Discovery: Click failed for '{friendly_name}'")
                                continue

                            clicked_identities.add(identity)  # Only marked as done after a successful click
                            recon_inventory.ui_metrics["safe_actions_explored"] = recon_inventory.ui_metrics.get("safe_actions_explored", 0) + 1
                            last_successful_click_identity = identity
                            if persistent_chrome_click and global_click_key not in global_handled_chrome_controls:
                                global_handled_chrome_controls.add(global_click_key)
                                logger.info(f"[{role_name}] SPA Discovery: Persistent control '{friendly_name}' handled once; suppressing repeats across pages.")
                            if _fn_key:
                                label_click_counts[_fn_key] = label_click_counts.get(_fn_key, 0) + 1

                            # If we just clicked a close/dismiss button, mark its activator's
                            # context as dismissed so the pre-click re-expose won't reopen
                            # the panel when interior sibling elements go stale.
                            _clicked_aria_lower = (aria_label or "").lower()
                            _clicked_text_lower = (text or "").lower()
                            if any(t in _clicked_aria_lower or t in _clicked_text_lower
                                   for t in ("close", "dismiss", "cancel", "stop walk")):
                                _dismiss_act = element_activator.get(identity)
                                if _dismiss_act:
                                    dismissed_contexts.add(_dismiss_act)
                                    _da_label = _dismiss_act.split('|')[4][:30] if '|' in _dismiss_act else _dismiss_act[:30]
                                    logger.debug(f"[{role_name}] SPA Discovery: Marked context of '{_da_label}' as dismissed.")

                            # Wait for DOM to settle after click — prefer networkidle over flat sleep
                            intra_click_delay = min(800, max(300, delay // 10))
                            try:
                                await page.wait_for_load_state("networkidle", timeout=intra_click_delay)
                            except Exception:
                                await page.wait_for_timeout(min(300, intra_click_delay))

                            click_progress = []
                            if page.url != pre_click_url:
                                click_progress.append("url")

                            try:
                                post_click_links = await _bounded_crawl_await(
                                    extract_links(page, page.url),
                                    CRAWL_DOM_TIMEOUT_SEC,
                                    set(),
                                    role_name,
                                    "extracting post-click links",
                                )
                                _interact_and_collect_links(
                                    post_click_links,
                                    allowed_domains,
                                    discovered_endpoints,
                                    visited,
                                    to_visit,
                                    visited_normalized,
                                    skip_auth_exit=authenticated_crawl,
                                )
                                if len(discovered_endpoints) > pre_endpoint_count:
                                    click_progress.append("endpoints")
                            except Exception:
                                pass

                            if api_harvest_mode:
                                try:
                                    post_click_calls = await _bounded_crawl_await(
                                        _harvest_api_log(page, page.url, allowed_domains),
                                        CRAWL_FAST_TIMEOUT_SEC,
                                        [],
                                        role_name,
                                        "harvesting post-click API calls",
                                    )
                                    for _call in post_click_calls:
                                        _remember_api_call(_call)
                                    if len(discovered_api_calls) > pre_api_count:
                                        click_progress.append("api")
                                except Exception:
                                    pass

                            post_state_sig = ""
                            if not low_value_click:
                                post_state_sig = await _bounded_crawl_await(
                                    page_state_signature(page),
                                    CRAWL_FAST_TIMEOUT_SEC,
                                    "",
                                    role_name,
                                    "capturing post-click page state",
                                )
                            if post_state_sig and pre_state_sig and post_state_sig != pre_state_sig:
                                click_progress.append("dom")

                            recon_inventory.state_transitions.append({
                                "action": friendly_name[:160],
                                "from_url": redact_url(pre_click_url),
                                "to_url": redact_url(page.url),
                                "from_state": pre_state_sig,
                                "to_state": post_state_sig,
                                "progress": sorted(set(click_progress)),
                            })

                            if nav_toggle_click:
                                nav_toggle_clicks.add(semantic_click_key)

                            if click_progress:
                                no_progress_clicks.pop(semantic_click_key, None)
                                logger.debug(f"[{role_name}] SPA Discovery: '{friendly_name}' progress={','.join(sorted(set(click_progress)))}")
                            else:
                                no_progress_clicks[semantic_click_key] = no_progress_clicks.get(semantic_click_key, 0) + 1
                                if persistent_chrome_click:
                                    global_no_progress_chrome_controls[global_click_key] = global_no_progress_chrome_controls.get(global_click_key, 0) + 1
                                if low_value_click:
                                    route_key = normalize_url_for_dedup(pre_click_url or current_route_for_guards or "")
                                    group_key = (route_key, low_value_code_group(friendly_name))
                                    low_value_no_progress_groups[group_key] = low_value_no_progress_groups.get(group_key, 0) + 1
                                    if low_value_no_progress_groups[group_key] == LOW_VALUE_GROUP_CAP:
                                        logger.info(
                                            f"[{role_name}] SPA Discovery: Low-value list pattern '{low_value_code_group(friendly_name)}' "
                                            f"produced no progress {LOW_VALUE_GROUP_CAP}x; skipping matching siblings on this route."
                                        )
                                logger.info(f"[{role_name}] SPA Discovery: No new route/API/DOM change from '{friendly_name}'. Suppressing repeats.")

                            # Screenshot after each SPA click (same URL, different state)
                            if screenshot_dir:
                                try:
                                    _ss_path_part = urlparse(page.url).path or 'root'
                                    _ss_base = re.sub(r'[\\/:*?"<>|]', '_', _ss_path_part).strip('_')[:100] or 'root'
                                    _ss_counter += 1
                                    _ss_path = os.path.join(screenshot_dir, f"{_ss_counter:04d}_{_ss_base}_click{interactions}.png")
                                    await page.screenshot(path=_ss_path, full_page=True)
                                except Exception as _ss_err:
                                    logger.debug(f"[{role_name}] SPA click screenshot failed: {_ss_err}")

                            # 6. Post-Click Handling
                            # Compare only scheme+netloc+path — ignore hash/fragment changes
                            # so modals that update the URL hash don't abort the discovery loop
                            _cur = urlparse(page.url)
                            _start = urlparse(start_page_url)
                            if (_cur.scheme, _cur.netloc, _cur.path) != (_start.scheme, _start.netloc, _start.path):
                                # Before breaking, check for siblings that share the same
                                # menu/list container OR the same activator click.
                                # Container-based detection handles pre-expanded menus where
                                # activator_of_clicked is None (e.g. MUI accordion already open).
                                activator_of_clicked = element_activator.get(identity)
                                group_of_clicked = element_group.get(identity)
                                pending_siblings = [
                                    ident for ident in to_click_queue
                                    if ident not in clicked_identities
                                    and (
                                        (activator_of_clicked is not None
                                         and element_activator.get(ident) == activator_of_clicked)
                                        or
                                        (group_of_clicked is not None
                                         and element_group.get(ident) == group_of_clicked)
                                    )
                                ]

                                if pending_siblings:
                                    logger.info(f"[{role_name}] SPA Discovery: Navigated away but {len(pending_siblings)} sibling(s) still pending. Returning to start page.")
                                    back_ok = False
                                    try:
                                        # Use goto() rather than go_back() — SPAs often use
                                        # history.replaceState so there is nothing to go back to.
                                        await page.goto(start_page_url, wait_until="domcontentloaded", timeout=15000)
                                        await page.wait_for_timeout(1500)

                                        # Dismiss any acknowledgement / cookie / welcome popups that
                                        # appeared on page load — these block all subsequent interaction
                                        # and are the most common cause of silent recovery failures.
                                        await dismiss_popups(page)
                                        await page.wait_for_timeout(500)

                                        # Determine if the dropdown/accordion is already open.
                                        # Two strategies in priority order — both needed because
                                        # different component libraries use different expansion signals:
                                        #   Strategy 1: aria-expanded on the activator (ARIA-compliant libs).
                                        #   Strategy 2: sibling visible inside its stored group container
                                        #               (MUI Collapse, CSS-based accordions that do NOT
                                        #               set aria-expanded but DO have stable class names).
                                        # The old plain ":has-text()" check was deliberately removed —
                                        # it matched any element on the page containing the sibling text
                                        # (breadcrumbs, headings, etc.) causing systematic false positives.
                                        sib_parts = pending_siblings[0].split('|')
                                        sib_text = sib_parts[4].strip() if len(sib_parts) >= 5 else ""
                                        sib_role = sib_parts[1].strip() if len(sib_parts) >= 2 else ""
                                        children_visible = False

                                        # Strategy 1: aria-expanded on the activator
                                        if activator_of_clicked and not children_visible:
                                            try:
                                                act_parts = activator_of_clicked.split('|')
                                                act_aria_chk = act_parts[3].strip() if len(act_parts) >= 4 else ""
                                                act_id_chk   = act_parts[2].strip() if len(act_parts) >= 3 else ""
                                                act_text_chk = act_parts[4].strip() if len(act_parts) >= 5 else ""
                                                act_role_chk = act_parts[1].strip() if len(act_parts) >= 2 else ""
                                                if act_aria_chk:
                                                    chk_loc = page.locator(f'[aria-label="{act_aria_chk}"]').first
                                                elif act_id_chk:
                                                    chk_loc = page.locator(f'[id="{act_id_chk}"]').first
                                                elif act_text_chk and act_role_chk:
                                                    chk_loc = page.locator(f'[role="{act_role_chk}"]:has-text("{act_text_chk}")').first
                                                elif act_text_chk:
                                                    chk_loc = page.locator(f':has-text("{act_text_chk}")').first
                                                else:
                                                    chk_loc = None
                                                if chk_loc:
                                                    expanded_attr = await chk_loc.get_attribute('aria-expanded', timeout=TIMEOUT_SHORT)
                                                    if expanded_attr == 'true':
                                                        children_visible = True
                                            except Exception:
                                                pass

                                        # Strategy 2: sibling visible inside its known group container.
                                        # Uses stable framework class names (strips CSS-in-JS hashes
                                        # like mui-abc123 / css-xyz / jss1 that change per build).
                                        if not children_visible and sib_text and group_of_clicked:
                                            try:
                                                grp_parts = group_of_clicked.split('|', 1)
                                                grp_tag = grp_parts[0].lower() if grp_parts else ""
                                                grp_cls_raw = grp_parts[1] if len(grp_parts) > 1 else ""
                                                stable = [c for c in grp_cls_raw.split()
                                                          if not any(c.lower().startswith(p) for p in ('css-', 'mui-', 'jss'))]
                                                if stable:
                                                    grp_sel = f"{grp_tag}.{stable[0]}" if grp_tag else f".{stable[0]}"
                                                    inner_sel = f'[role="{sib_role}"]:has-text("{sib_text}")' if sib_role else f':has-text("{sib_text}")'
                                                    children_visible = await page.locator(f'{grp_sel} {inner_sel}').first.is_visible(timeout=1500)
                                            except Exception:
                                                pass

                                        if children_visible:
                                            logger.info(f"[{role_name}] SPA Discovery: Siblings visible on restored page — no re-expand needed.")
                                            back_ok = True
                                        elif activator_of_clicked:
                                            # Siblings hidden — re-click the activator to expand the menu
                                            act_parts = activator_of_clicked.split('|')
                                            if len(act_parts) >= 5:
                                                act_text = act_parts[4].strip()
                                                act_aria = act_parts[3].strip()
                                                act_role = act_parts[1].strip()
                                                act_id   = act_parts[2].strip()
                                                try:
                                                    if act_aria:
                                                        re_el = page.locator(f'[aria-label="{act_aria}"]').first
                                                    elif act_id:
                                                        re_el = page.locator(f'[id="{act_id}"]').first
                                                    elif act_text and act_role:
                                                        re_el = page.locator(f'[role="{act_role}"]:has-text("{act_text}")').first
                                                    elif act_text:
                                                        re_el = page.locator(f':has-text("{act_text}")').first
                                                    else:
                                                        re_el = None
                                                    if re_el and await re_el.is_visible(timeout=TIMEOUT_LONG):
                                                        logger.info(f"[{role_name}] SPA Discovery: Re-expanding menu via '{act_text or act_aria}'.")
                                                        await re_el.click(timeout=TIMEOUT_MEDIUM)
                                                        await page.wait_for_timeout(1000)
                                                        # Dismiss any popup triggered by re-expanding
                                                        await dismiss_popups(page)
                                                        back_ok = True
                                                except Exception:
                                                    pass
                                        else:
                                            # No recorded activator — try to find a collapsed ancestor
                                            # in the live DOM that contains one of the sibling texts.
                                            # This handles pre-expanded menus that collapse after navigation.
                                            sib_text_for_search = sib_text  # already extracted above
                                            logger.info(f"[{role_name}] SPA Discovery: No activator — searching DOM for collapsed ancestor of '{sib_text_for_search}'.")
                                            try:
                                                activator_handle = await page.evaluate_handle(
                                                    """(text) => {
                                                        const EXPAND_SELS = '[aria-expanded="false"], [data-state="closed"], details:not([open]), .collapsed';
                                                        const candidates = document.querySelectorAll(EXPAND_SELS);
                                                        for (const el of candidates) {
                                                            if (el.offsetWidth > 0 && el.offsetHeight > 0 &&
                                                                el.textContent && el.textContent.includes(text)) {
                                                                return el;
                                                            }
                                                        }
                                                        return null;
                                                    }""",
                                                    sib_text_for_search
                                                )
                                                act_el = activator_handle.as_element()
                                                if act_el:
                                                    logger.info(f"[{role_name}] SPA Discovery: Clicking collapsed ancestor to re-expand.")
                                                    await act_el.click(timeout=TIMEOUT_MEDIUM)
                                                    await page.wait_for_timeout(1000)
                                                    await dismiss_popups(page)
                                                    back_ok = True
                                                else:
                                                    logger.warning(f"[{role_name}] SPA Discovery: Siblings hidden but no activator known — cannot re-expand. Siblings will be missed.")
                                            except Exception as _e:
                                                logger.warning(f"[{role_name}] SPA Discovery: Collapsed ancestor search failed ({_e}). Siblings will be missed.")
                                    except Exception as e:
                                        logger.warning(f"[{role_name}] SPA Discovery: Return-to-start failed: {e}")

                                    if back_ok:
                                        continue  # Resume loop — next iteration will pick the next sibling

                                logger.info(f"[{role_name}] SPA Discovery: Page navigated away. Ending current discovery loop.")
                                if screenshot_dir:
                                    try:
                                        _ss_path_part = urlparse(page.url).path or 'root'
                                        _ss_name = re.sub(r'[\\/:*?"<>|]', '_', _ss_path_part).strip('_')[:150] or 'root'
                                        _ss_counter += 1
                                        await page.screenshot(path=os.path.join(screenshot_dir, f"{_ss_counter:04d}_{_ss_name}.png"), full_page=True)
                                    except Exception as _ss_err:
                                        logger.debug(f"[{role_name}] SPA screenshot failed: {_ss_err}")
                                break
                            
                        logger.info(f"[{role_name}] SPA Discovery finished. Total interactions: {interactions}")

                        # --- API-Harvest batch dispatch pass ---
                        if api_harvest_mode:
                            # 1. Passive harvest: API calls that fired during page load/render
                            _passive = await _bounded_crawl_await(
                                _harvest_api_log(page, start_page_url, allowed_domains),
                                CRAWL_FAST_TIMEOUT_SEC,
                                [],
                                role_name,
                                "harvesting passive SPA API calls",
                            )
                            for _call in _passive:
                                _remember_api_call(_call)

                            # 2. Batch dispatch is never safe by default, even for an
                            # unauthenticated page: public forms can send email, create
                            # tickets, or mutate anonymous state. It is available only
                            # behind an explicit opt-in intended for controlled fixtures.
                            if not allow_risky_recon_actions:
                                logger.info(f"[{role_name}] API Harvest: recon-safe mode disabled synthetic batch clicks.")
                            _batch_sel = ", ".join(click_selectors) if allow_risky_recon_actions else "__sk_recon_safe_no_batch_dispatch__"
                            try:
                                _navigated = await _bounded_crawl_await(
                                    page.evaluate("""(batchSel) => {
                                        const els = [...document.querySelectorAll(batchSel)];
                                        const origHref = location.href;
                                        for (const el of els) {
                                            const r = el.getBoundingClientRect();
                                            if (r.width <= 0 || r.height <= 0 ||
                                                r.right <= 0 || r.left >= window.innerWidth ||
                                                r.bottom <= 0 || r.top >= window.innerHeight) continue;
                                            try { el.dispatchEvent(new MouseEvent('click', {bubbles:true, cancelable:true})); }
                                            catch(e) {}
                                            if (location.href !== origHref) { return true; }
                                        }
                                        return false;
                                    }""", _batch_sel),
                                    CRAWL_FAST_TIMEOUT_SEC,
                                    False,
                                    role_name,
                                    "batch-dispatching SPA API harvest clicks",
                                )
                            except Exception:
                                _navigated = False

                            if _navigated:
                                _batch_calls = await _bounded_crawl_await(
                                    _harvest_api_log(page, start_page_url, allowed_domains),
                                    CRAWL_FAST_TIMEOUT_SEC,
                                    [],
                                    role_name,
                                    "harvesting navigated batch API calls",
                                )
                                for _call in _batch_calls:
                                    _remember_api_call(_call)
                                try:
                                    await page.goto(start_page_url, wait_until="domcontentloaded", timeout=15000)
                                    await dismiss_popups(page)
                                except Exception:
                                    pass
                            else:
                                await page.wait_for_timeout(800)  # let async fetches settle
                                _batch_calls = await _bounded_crawl_await(
                                    _harvest_api_log(page, start_page_url, allowed_domains),
                                    CRAWL_FAST_TIMEOUT_SEC,
                                    [],
                                    role_name,
                                    "harvesting batch API calls",
                                )
                                for _call in _batch_calls:
                                    _remember_api_call(_call)

                            logger.info(f"[{role_name}] API Harvest: captured {len(discovered_api_calls)} unique API calls on {start_page_url}")

                    except Exception as e:
                        logger.error(f"[{role_name}] SPA Discovery Error: {e}", exc_info=True)

                if authenticated_crawl:
                    auth_state = await capture_auth_state(page, context)
                    if is_probable_logged_out_state(auth_state, current_url):
                        landed_url = auth_state.get("url") or page.url
                        recovered = await _recover_authenticated_crawl(current_url, landed_url, auth_state)
                        if recovered:
                            continue
                        logger.warning(f"[{role_name}] Skipping route after post-discovery auth loss: {current_url}")
                        continue

                # Handling domain changes / redirects
                if pages_crawled == 1:
                    # On first page, we accept the redirect as the new base (e.g., http -> https or login redirect)
                    if parsed_final.netloc != target_domain:
                        logger.info(f"[{role_name}] Initial Redirect to {parsed_final.netloc}. Updating allowed domains.")
                        allowed_domains.add(parsed_final.netloc)
                else:
                    # Subsequent pages: Check if we left the allowed domain(s)
                    if parsed_final.netloc not in allowed_domains:
                        if follow_redirects:
                            logger.info(f"[{role_name}] Following external redirect to: {parsed_final.netloc}")
                            allowed_domains.add(parsed_final.netloc)
                        else:
                            logger.warning(f"[{role_name}] External redirect blocked: {final_url}")
                            # Record the redirect endpoint but stop processing content
                            path = endpoint_from_url(final_url)
                            discovered_endpoints.add(path) 
                            continue

                # Add the final URL path to discovered endpoints
                path = endpoint_from_url(final_url)
                    
                if not is_static_resource(final_url):
                     discovered_endpoints.add(path)

                if response is None or response.status == 200:
                    # Extract links from current page state and merge with pre-SPA links
                    links = _pre_spa_links
                    if page.url != final_url:
                        # SPA discovery navigated away — also grab links from the landed page
                        _post_links = await _bounded_crawl_await(
                            extract_links(page, page.url),
                            CRAWL_DOM_TIMEOUT_SEC,
                            set(),
                            role_name,
                            "extracting links from SPA landed page",
                        )
                        links = links | _post_links
                    else:
                        # Still on the same page — re-extract to catch any DOM additions from SPA clicks
                        links = links | await _bounded_crawl_await(
                            extract_links(page, final_url),
                            CRAWL_DOM_TIMEOUT_SEC,
                            set(),
                            role_name,
                            "extracting links after SPA discovery",
                        )

                    # Probe clickable rows (e.g. tr[tabindex="0"]) that use
                    # JS onClick navigation and have no href attribute.
                    row_links = await probe_clickable_rows(page, final_url)
                    if row_links:
                        logger.info(f"[{role_name}] probe_clickable_rows: +{len(row_links)} URL(s) from clickable rows")
                        links.update(row_links)

                    logger.info(f"[{role_name}] Found {len(links)} raw links on {current_url}")

                    for link in links:
                        clean_link = normalize_crawl_link(link, final_url)
                        if not clean_link:
                            continue

                        # Only follow links on allowed domains
                        if urlparse(clean_link).netloc in allowed_domains:
                            # Check if matches ignore pattern
                            is_ignored = should_ignore(clean_link, ignore_patterns)
                            if _add_crawl_candidate(clean_link, queue=not is_ignored) and is_ignored:
                                logger.debug(f"[{role_name}] Mapped but Ignored (pattern): {clean_link}")
                        else:
                            # Log external links but don't follow unless configured (logic above handles redirects)
                            # Here we just skip queueing them
                            logger.debug(f"[{role_name}] Ignored (domain mismatch): {clean_link}")

                # --- Incremental Link Extraction (Inside Loop Fix) ---
                # Also normalize paths in the sub-item extraction loop
                # (Note: sub_links extraction happens inside the interactive loop above)
            except Exception as e:
                logger.error(f"[{role_name}] Error processing {current_url}: {e}", exc_info=True)

        # Flush any pending traffic captures before closing the context
        if _pending_traffic_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*_pending_traffic_tasks, return_exceptions=True),
                    timeout=15.0
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                for t in _pending_traffic_tasks:
                    t.cancel()

        # Finish retaining script responses before expanding lazy chunks.  This
        # is deliberately passive: assets are fetched, never executed.
        if _pending_recon_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*_pending_recon_tasks, return_exceptions=True),
                    timeout=20.0,
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                for task in _pending_recon_tasks:
                    task.cancel()

        if static_js_recon:
            # Service workers and Workbox manifests often contain routes/chunks
            # that normal page navigation never loads.
            try:
                worker_urls = await page.evaluate("""async () => {
                    if (!('serviceWorker' in navigator)) return [];
                    const regs = await navigator.serviceWorker.getRegistrations();
                    return regs.map((reg) => (reg.active || reg.waiting || reg.installing))
                        .filter(Boolean).map((worker) => worker.scriptURL);
                }""")
                for worker_url in worker_urls or []:
                    parsed_worker = urlparse(worker_url)
                    if parsed_worker.netloc not in allowed_domains:
                        continue
                    recon_inventory.assets_advertised.add(worker_url)
                    if worker_url in first_party_js_assets:
                        continue
                    worker_response = await context.request.get(worker_url, timeout=15000, fail_on_status_code=False)
                    if worker_response.ok:
                        worker_body = await worker_response.body()
                        if len(worker_body) <= 12 * 1024 * 1024:
                            first_party_js_assets[worker_url] = worker_body.decode("utf-8", errors="replace")
                            recon_inventory.assets_downloaded.add(worker_url)
            except Exception as exc:
                logger.debug(f"[{role_name}] Service-worker inventory unavailable: {exc}")

        if static_js_recon and first_party_js_assets:
            try:
                static_inventory = await expand_and_analyze_assets(
                    context.request,
                    first_party_js_assets,
                    role=role_name,
                    allowed_hosts={urlparse(f"https://{domain}").hostname for domain in allowed_domains},
                    max_assets=max(1, int(recon_max_assets)),
                    max_total_bytes=max(1, int(recon_max_bytes)),
                    fetch_source_maps=True,
                    browser_page=page,
                    resolve_templates=js_template_resolution,
                )
                recon_inventory.merge(static_inventory)
                if validate_static_get:
                    validated_count = await validate_safe_get_candidates(
                        context.request,
                        recon_inventory,
                        allowed_hosts={urlparse(f"https://{domain}").hostname for domain in allowed_domains},
                        limit=recon_validation_limit,
                    )
                    logger.info(f"[{role_name}] Validated {validated_count} static GET/HEAD candidates (explicit opt-in).")
                coverage = static_inventory.coverage()
                logger.info(
                    f"[{role_name}] Static recon: {coverage['assets_advertised']} assets advertised, "
                    f"{coverage['assets_downloaded']} downloaded, {coverage['assets_parsed']} parsed, "
                    f"{coverage['endpoint_candidates']} candidates."
                )
            except Exception as exc:
                logger.warning(f"[{role_name}] Static JavaScript recon failed without aborting crawl: {exc}")

        # Static asset expansion itself creates tagged browser traffic. Flush
        # those final captures before closing the context and returning results.
        if _pending_traffic_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*_pending_traffic_tasks, return_exceptions=True),
                    timeout=15.0,
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                for task in _pending_traffic_tasks:
                    task.cancel()

        # Cleanup. Browser/context close can throw if the visible window was
        # manually closed or Playwright already tore it down; do not lose crawl
        # results over cleanup.
        if reuse_context:
            try:
                await asyncio.wait_for(page.close(), timeout=CRAWL_CLOSE_TIMEOUT_SEC)
            except Exception as e:
                logger.debug(f"[{role_name}] Page cleanup failed: {e}")
        else:
            try:
                await asyncio.wait_for(context.close(), timeout=CRAWL_CLOSE_TIMEOUT_SEC)
            except Exception as e:
                logger.debug(f"[{role_name}] Context cleanup failed: {e}")
            try:
                await asyncio.wait_for(browser.close(), timeout=CRAWL_CLOSE_TIMEOUT_SEC)
            except Exception as e:
                logger.debug(f"[{role_name}] Browser cleanup failed: {e}")
        return sorted(list(discovered_endpoints)), discovered_api_calls, endpoint_responses, recon_inventory


async def crawl_role_with_timeout(timeout_sec, *args, **kwargs):
    role = args[1] if len(args) > 1 else kwargs.get("role", {})
    role_name = role.get("name", "Unknown Role") if isinstance(role, dict) else "Unknown Role"
    try:
        if timeout_sec and timeout_sec > 0:
            return await asyncio.wait_for(crawl_role(*args, **kwargs), timeout=timeout_sec)
        return await crawl_role(*args, **kwargs)
    except asyncio.TimeoutError:
        logger.error(f"[{role_name}] Crawl role timed out after {timeout_sec}s; continuing with other roles.")
        return [], [], {}, ReconInventory(role=role_name)


async def verify_endpoint_worker(sem, browser, target_url, endpoint, baseline_role, test_role, ai_client, config, auth_prompt, results_container, page_username="", page_password=None, all_role_names=None, reasoning_log=None, ai_sem=None, ai_spacer=None, cached_baseline=None, ai_model=None, baseline_session=None, test_session=None, verify_client=None):
    """
    Worker function to verify a single endpoint for a single role.
    Uses a semaphore to limit concurrency.

    `baseline_session` and `test_session` are RoleSession instances supplying a
    persistent BrowserContext per role. When provided, fetch_page_metrics reuses
    the context (no per-call new_context/close), and Set-Cookie rotations propagate
    across calls naturally. They fall back to per-call contexts when None.
    """
    async with sem:
        try:
            role_name = test_role['name']
            baseline_lock = baseline_session.reauth_lock if baseline_session is not None else None
            test_lock = test_session.reauth_lock if test_session is not None else None
            is_unauthed_role = (role_name == 'Unauthenticated')

            # Auth/session endpoints are not IDOR targets. Skip before any
            # fetch/reauth work so login handlers like /login/ceklogin cannot
            # churn sessions or enter the reauth path.
            endpoint_lower = endpoint.lower().rstrip('/')
            _auth_path_terms = ('login', 'logout', 'signin', 'signout', 'ceklogin', 'wp-login', 'wp_login')
            if any(endpoint_lower == t or endpoint_lower.endswith('/' + t) for t in _auth_path_terms):
                results_container['safe'].add((endpoint, role_name))
                if reasoning_log:
                    with open(reasoning_log, 'a', encoding='utf-8') as _rf:
                        _rf.write(f"[SKIP-AUTH-ENDPOINT] [{role_name}] {endpoint}\n\n")
                return

            # 1. Baseline Metrics — prefer the response captured during crawl (no re-fetch =
            # no race with concurrent workers, no stale cookie problem). Fall back to a live
            # fetch when the endpoint wasn't actually visited during crawl (link-only).
            if cached_baseline is not None:
                base_status, base_body, base_url, base_req, base_resp = cached_baseline
            else:
                async def _baseline_fetch():
                    return await fetch_page_metrics(
                        browser, baseline_role, target_url, endpoint,
                        page_username=page_username, page_password=page_password,
                        persist_cookies_lock=None,
                        shared_context=(baseline_session.context if baseline_session is not None else None),
                    )

                base_status, base_body, base_url, base_req, base_resp = await _baseline_fetch()
                if base_status is None:
                    base_status, base_body, base_url, base_req, base_resp = await _baseline_fetch()
                if base_status is None:
                    logger.warning(f"Baseline fetch failed twice for {endpoint}, skipping.")
                    return

                # Session-expired recovery: if baseline ended on a login page, the session may
                # have been rotated server-side. Retry once after a short delay to clear
                # transient races; if still stuck, re-authenticate using stored creds and try
                # one final time. Re-auth is serialized per role so parallel workers don't
                # trigger N concurrent re-logins.
                if _is_login_url(base_url):
                    logger.info(f"[{role_name}] Baseline redirected to login for {endpoint} — retrying...")
                    await asyncio.sleep(1.5)
                    base_status, base_body, base_url, base_req, base_resp = await _baseline_fetch()

                if _is_login_url(base_url) and ai_client and ai_model and baseline_role.get('_login'):
                    if baseline_session is not None:
                        async with baseline_session.reauth_lock:
                            # Re-check inside the lock — another worker may have already refreshed
                            base_status, base_body, base_url, base_req, base_resp = await _baseline_fetch()
                            if _is_login_url(base_url):
                                logger.warning(f"[{role_name}] Baseline still on login page — re-authenticating '{baseline_role.get('name', '?')}'.")
                                refreshed = await baseline_session.reauth(ai_client, ai_model)
                                if refreshed:
                                    base_status, base_body, base_url, base_req, base_resp = await _baseline_fetch()
                    elif baseline_lock is not None:
                        async with baseline_lock:
                            if _is_login_url(base_url):
                                logger.warning(f"[{role_name}] Baseline still on login page — re-authenticating '{baseline_role.get('name', '?')}'.")
                                refreshed = await _refresh_role_session(browser, baseline_role, ai_client, ai_model)
                                if refreshed:
                                    base_status, base_body, base_url, base_req, base_resp = await _baseline_fetch()
                    else:
                        refreshed = await _refresh_role_session(browser, baseline_role, ai_client, ai_model)
                        if refreshed:
                            base_status, base_body, base_url, base_req, base_resp = await _baseline_fetch()

                if _is_login_url(base_url):
                    logger.warning(f"[SESSION-EXPIRED] Baseline ('{baseline_role.get('name', '?')}') still redirected to login for {endpoint} after retry+reauth — skipping.")
                    if reasoning_log:
                        with open(reasoning_log, 'a', encoding='utf-8') as _rf:
                            _rf.write(f"[SKIP-BASELINE-SESSION-EXPIRED] [{role_name}] {endpoint}\n  base_url: {base_url}\n\n")
                    return

            base_len = len(base_body) if base_body else 0

            # 2. Fetch Test Metrics (retry once on failure)
            async def _test_fetch():
                return await fetch_page_metrics(
                    browser, test_role, target_url, endpoint,
                    page_username=page_username, page_password=page_password,
                    persist_cookies_lock=None,
                    shared_context=(test_session.context if test_session is not None else None),
                )

            test_status, test_body, test_url, test_req, test_resp = await _test_fetch()
            if test_status is None:
                test_status, test_body, test_url, test_req, test_resp = await _test_fetch()
            if test_status is None:
                logger.warning(f"Test fetch failed twice for {endpoint} [{role_name}], skipping.")
                return

            if not is_unauthed_role and _is_login_url(test_url):
                logger.info(f"[{role_name}] Test role redirected to login for {endpoint} - retrying before verdict...")
                await asyncio.sleep(1.5)
                test_status, test_body, test_url, test_req, test_resp = await _test_fetch()

            if (not is_unauthed_role and _is_login_url(test_url) and
                    ai_client and ai_model and test_role.get('_login')):
                if test_session is not None:
                    async with test_session.reauth_lock:
                        test_status, test_body, test_url, test_req, test_resp = await _test_fetch()
                        if _is_login_url(test_url):
                            logger.warning(f"[{role_name}] Test role still on login page - re-authenticating '{test_role.get('name', '?')}'.")
                            refreshed = await test_session.reauth(ai_client, ai_model)
                            if refreshed:
                                test_status, test_body, test_url, test_req, test_resp = await _test_fetch()
                elif test_lock is not None:
                    async with test_lock:
                        if _is_login_url(test_url):
                            logger.warning(f"[{role_name}] Test role still on login page - re-authenticating '{test_role.get('name', '?')}'.")
                            refreshed = await _refresh_role_session(browser, test_role, ai_client, ai_model)
                            if refreshed:
                                test_status, test_body, test_url, test_req, test_resp = await _test_fetch()
                else:
                    refreshed = await _refresh_role_session(browser, test_role, ai_client, ai_model)
                    if refreshed:
                        test_status, test_body, test_url, test_req, test_resp = await _test_fetch()

            test_len = len(test_body) if test_body else 0

            # 3. Heuristics (Stage 1)
            is_suspicious = False

            # Skip auth/session endpoints entirely — these are not IDOR targets and generate
            high_risk_hit, high_risk_reason, high_risk_severity = _looks_like_high_risk_bac(
                endpoint, base_status, base_body, base_url, test_status, test_body, test_url
            )
            if high_risk_hit:
                logger.warning(f"[{role_name}] HEURISTIC BAC: {endpoint}")
                results_container['vuln'].append({
                    "endpoint": endpoint,
                    "role": role_name,
                    "baseline_role": baseline_role['name'],
                    "severity": high_risk_severity,
                    "confidence": "MEDIUM",
                    "description": f"Broken Access Control (IDOR/BOLA) likely. Role '{role_name}' can access high-risk route '{endpoint}' which should be restricted to '{baseline_role['name']}'.",
                    "reason": high_risk_reason,
                    "evidence": {
                        "baseline_request": base_req,
                        "baseline_response": base_resp,
                        "test_request": test_req,
                        "test_response": test_resp
                    }
                })
                if reasoning_log:
                    with open(reasoning_log, 'a', encoding='utf-8') as _rf:
                        _rf.write(f"[HEURISTIC-HIGH-RISK-BAC] [{role_name}] {endpoint}\n  Reason: {high_risk_reason}\n\n")
                return

            # Normalize for redirect comparison
            full_target_url = urljoin(target_url, endpoint)
            def norm_url(u): return u.split('?')[0].rstrip('/')

            test_url_lower = test_url.lower() if test_url else ""

            # Authenticated roles (not Unauthenticated) bypass redirect/soft-403 heuristics.
            # The app uses the login page as a catch-all access denied redirect, so heuristics
            # cannot distinguish "not logged in" from "logged in but not authorized" for these roles.
            # Let the AI decide instead.
            # Note: baseline session-expired handling is performed earlier (during the
            # baseline fetch) with retry + re-auth. By this point base_url should not be a
            # login URL — if cached_baseline was used, the crawl-time baseline can't be
            # a login page either (the crawler skipped login redirects).

            # A. Redirects to Login
            if _is_login_url(test_url):
                if is_unauthed_role:
                    is_suspicious = False
                    if reasoning_log:
                        with open(reasoning_log, 'a', encoding='utf-8') as _rf:
                            _rf.write(f"[HEURISTIC-LOGIN-REDIRECT] [{role_name}] {endpoint}\n  test_url: {test_url}\n\n")
                else:
                    # Authenticated role redirected to login — could be "access denied" redirect
                    is_suspicious = True
                    if reasoning_log:
                        with open(reasoning_log, 'a', encoding='utf-8') as _rf:
                            _rf.write(f"[AI-CHECK-LOGIN-REDIRECT] [{role_name}] {endpoint}\n  base_url: {base_url} | test_url: {test_url}\n\n")

            # B. Redirected to a DIFFERENT page (Safety Redirect)
            # Logic: If Baseline stayed on the target, but Test was redirected elsewhere -> possibly safe
            elif (norm_url(base_url) == norm_url(full_target_url) and
                  norm_url(test_url) != norm_url(full_target_url)):
                if is_unauthed_role:
                    is_suspicious = False
                    logger.info(f"[{role_name}] Redirected from {endpoint} to {test_url} (Likely Safe)")
                    if reasoning_log:
                        with open(reasoning_log, 'a', encoding='utf-8') as _rf:
                            _rf.write(f"[HEURISTIC-REDIRECT] [{role_name}] {endpoint}\n  base_url: {base_url} | test_url: {test_url}\n\n")
                else:
                    # Authenticated role redirected away — let AI decide
                    is_suspicious = True
                    if reasoning_log:
                        with open(reasoning_log, 'a', encoding='utf-8') as _rf:
                            _rf.write(f"[AI-CHECK-REDIRECT] [{role_name}] {endpoint}\n  base_url: {base_url} | test_url: {test_url}\n\n")

            # C. Status Code Match (e.g. both 200)
            elif test_status == base_status:
                # Check for Soft 403
                if is_soft_403(test_body):
                    if is_unauthed_role:
                        is_suspicious = False
                        if reasoning_log:
                            with open(reasoning_log, 'a', encoding='utf-8') as _rf:
                                _rf.write(f"[HEURISTIC-SOFT403] [{role_name}] {endpoint}\n  status: {test_status} | snippet: {test_body[:200]}\n\n")
                    else:
                        # Authenticated role with soft-403 body — let AI decide
                        is_suspicious = True
                        if reasoning_log:
                            with open(reasoning_log, 'a', encoding='utf-8') as _rf:
                                _rf.write(f"[AI-CHECK-SOFT403] [{role_name}] {endpoint}\n  status: {test_status} | snippet: {test_body[:200]}\n\n")
                elif test_status == 200:
                    is_suspicious = True
                else:
                    # Non-200 match (e.g. both 500), check length
                    if base_len == 0 and test_len == 0:
                        is_suspicious = True
                    elif base_len > 0 or test_len > 0:
                        diff = abs(base_len - test_len)
                        ratio = diff / max(base_len, test_len)
                        if ratio < 0.60:
                            is_suspicious = True

            # D. Status code mismatch (test ≠ base, not caught above)
            # is_suspicious stays False — log it so the user can see the drop
            if not is_suspicious and test_status != base_status and \
               not _is_login_url(test_url) and \
               not (norm_url(base_url) == norm_url(full_target_url) and norm_url(test_url) != norm_url(full_target_url)):
                if reasoning_log:
                    with open(reasoning_log, 'a', encoding='utf-8') as _rf:
                        _rf.write(f"[HEURISTIC-STATUS-MISMATCH] [{role_name}] {endpoint}\n  base_status: {base_status} | test_status: {test_status}\n\n")

            # 4. AI Verification (Stage 2)
            if is_suspicious:
                llm_client = verify_client if verify_client is not None else ai_client
                if llm_client and auth_prompt:
                    logger.info(f"[{role_name}] Suspicious: {endpoint}. Verifying with AI...")
                    verifier_metadata = build_verifier_metadata(
                        endpoint, base_status, base_url, base_body,
                        test_status, test_url, test_body,
                        base_resp=base_resp, test_resp=test_resp, kind="page"
                    )
                    async with (ai_sem if ai_sem else asyncio.Lock()):
                        verdict, confidence, reason, severity = await verify_with_llm(
                            llm_client,
                            verify_model_name(config),
                            auth_prompt,
                            urljoin(target_url, endpoint),
                            baseline_role['name'],
                            base_status,
                            base_body,
                            role_name,
                            test_status,
                            test_body,
                            all_role_names=all_role_names,
                            request_spacer=ai_spacer,
                            metadata=verifier_metadata,
                        )

                        if verdict == "VULNERABLE":
                            logger.warning(f"[{role_name}] AI CONFIRMED VULNERABILITY: {endpoint}")
                            results_container['vuln'].append({
                                "endpoint": endpoint,
                                "role": role_name,
                                "baseline_role": baseline_role['name'],
                                "severity": severity,
                                "confidence": confidence,
                                "description": f"Broken Access Control (IDOR/BOLA) detected. Role '{role_name}' can access '{endpoint}' which should be restricted to '{baseline_role['name']}'.",
                                "reason": reason,
                                "evidence": {
                                    "baseline_request": base_req,
                                    "baseline_response": base_resp,
                                    "test_request": test_req,
                                    "test_response": test_resp
                                }
                            })
                        elif verdict == "SAFE":
                            keep_suspicious, keep_reason = _safe_llm_result_should_stay_suspicious(
                                endpoint, confidence, test_status, test_body, test_url
                            )
                            if keep_suspicious:
                                logger.info(f"[{role_name}] AI marked SAFE but guardrail kept SUSPICIOUS: {endpoint}")
                                if reasoning_log:
                                    with open(reasoning_log, 'a', encoding='utf-8') as _rf:
                                        _rf.write(f"[SAFE-GUARDRAIL-SUSPICIOUS] [{role_name}] {endpoint}\n  Baseline: {baseline_role['name']} | Confidence: {confidence}\n  AI Reason: {reason}\n  Guardrail: {keep_reason}\n\n")
                                record_suspicious(
                                    results_container, endpoint, role_name, baseline_role['name'],
                                    f"{keep_reason} AI reason: {reason}",
                                    {
                                        "baseline_request": base_req,
                                        "baseline_response": base_resp,
                                        "test_request": test_req,
                                        "test_response": test_resp
                                    },
                                    confidence=confidence,
                                    severity=severity
                                )
                            else:
                                logger.info(f"[{role_name}] AI marked as SAFE: {endpoint}")
                                if reasoning_log:
                                    with open(reasoning_log, 'a', encoding='utf-8') as _rf:
                                        _rf.write(f"[SAFE] [{role_name}] {endpoint}\n  Baseline: {baseline_role['name']} | Confidence: {confidence}\n  Reason: {reason}\n\n")
                                results_container['safe'].add((endpoint, role_name))
                        else:
                            verdict_label = "SUSPICIOUS" if verdict == "SUSPICIOUS" else "UNKNOWN"
                            promote_hit, promote_reason, promote_severity = _should_promote_suspicious_to_vuln(
                                endpoint, test_status, test_body, test_url
                            )
                            if promote_hit:
                                logger.warning(f"[{role_name}] PROMOTED {verdict_label} TO VULNERABLE: {endpoint}")
                                results_container['vuln'].append({
                                    "endpoint": endpoint,
                                    "role": role_name,
                                    "baseline_role": baseline_role['name'],
                                    "severity": promote_severity,
                                    "confidence": "MEDIUM",
                                    "description": f"Broken Access Control (IDOR/BOLA) likely. Role '{role_name}' can access high-risk route '{endpoint}' which should be restricted to '{baseline_role['name']}'.",
                                    "reason": f"{promote_reason} AI reason: {reason}",
                                    "evidence": {
                                        "baseline_request": base_req,
                                        "baseline_response": base_resp,
                                        "test_request": test_req,
                                        "test_response": test_resp
                                    }
                                })
                                if reasoning_log:
                                    with open(reasoning_log, 'a', encoding='utf-8') as _rf:
                                        _rf.write(f"[PROMOTED-{verdict_label}-TO-VULN] [{role_name}] {endpoint}\n  Baseline: {baseline_role['name']} | AI Confidence: {confidence}\n  AI Reason: {reason}\n  Promotion: {promote_reason}\n\n")
                                return
                            logger.info(f"[{role_name}] AI returned {verdict_label}: {endpoint}")
                            if reasoning_log:
                                with open(reasoning_log, 'a', encoding='utf-8') as _rf:
                                    _rf.write(f"[{verdict_label}] [{role_name}] {endpoint}\n  Baseline: {baseline_role['name']} | Confidence: {confidence}\n  Reason: {reason}\n\n")
                            record_suspicious(
                                results_container, endpoint, role_name, baseline_role['name'],
                                reason,
                                {
                                    "baseline_request": base_req,
                                    "baseline_response": base_resp,
                                    "test_request": test_req,
                                    "test_response": test_resp
                                },
                                confidence=confidence,
                                severity=(severity if verdict == "SUSPICIOUS" else "Information")
                            )

                else:
                    logger.info(f"[{role_name}] Suspicious (No AI): {endpoint}")
                    record_suspicious(
                        results_container, endpoint, role_name, baseline_role['name'],
                        "Heuristic marked this endpoint suspicious, but no verifier AI client was available.",
                        {
                            "baseline_request": base_req,
                            "baseline_response": base_resp,
                            "test_request": test_req,
                            "test_response": test_resp
                        },
                        confidence="LOW",
                        severity="Information"
                    )
            else:
                results_container['safe'].add((endpoint, role_name))
                
        except Exception as e:
            logger.error(f"Worker Error [{endpoint}]: {e}")


async def verify_api_call_worker(sem, target_url, call: "ApiCall", baseline_role, test_role, ai_client, config, auth_prompt, results_container, all_role_names=None, ai_sem=None, ai_spacer=None):
    """Replay a captured API call with a different role's credentials and check for broken access control."""
    async with sem:
        try:
            role_name = test_role['name']

            try:
                import httpx
            except ImportError:
                httpx = None

            if httpx:
                async with httpx.AsyncClient(follow_redirects=False, timeout=15) as api_client:
                    base_status, base_body, base_final_url = await replay_api_call(baseline_role, call, target_url, client=api_client)
                    if base_status is None:
                        logger.debug(f"[API] Baseline replay failed for {call.method} {call.path}: {base_body}")
                        return

                    api_client.cookies.clear()
                    test_status, test_body, test_final_url = await replay_api_call(test_role, call, target_url, client=api_client)
                    if test_status is None:
                        logger.debug(f"[API][{role_name}] Test replay failed for {call.method} {call.path}: {test_body}")
                        return
            else:
                base_status, base_body, base_final_url = await replay_api_call(baseline_role, call, target_url)
                if base_status is None:
                    logger.debug(f"[API] Baseline replay failed for {call.method} {call.path}: {base_body}")
                    return

                test_status, test_body, test_final_url = await replay_api_call(test_role, call, target_url)
                if test_status is None:
                    logger.debug(f"[API][{role_name}] Test replay failed for {call.method} {call.path}: {test_body}")
                    return

            base_len = len(base_body) if base_body else 0
            test_len = len(test_body) if test_body else 0

            # Heuristics
            is_suspicious = False

            # Baseline must have succeeded for this to be meaningful
            if base_status not in (200, 201, 204):
                return

            if test_status in (401, 403):
                is_suspicious = False
            elif test_status == base_status:
                if is_soft_403(test_body):
                    is_suspicious = False
                else:
                    if base_len == 0 and test_len == 0:
                        is_suspicious = True
                    elif base_len > 0:
                        ratio = abs(base_len - test_len) / max(base_len, test_len)
                        if ratio < 0.60:
                            is_suspicious = True

            call_id = build_api_call_id(call)

            if is_suspicious:
                if ai_client and auth_prompt:
                    logger.info(f"[API][{role_name}] Suspicious: {call_id}. Verifying with AI...")
                    verifier_metadata = build_verifier_metadata(
                        call_id, base_status, base_final_url, base_body,
                        test_status, test_final_url, test_body,
                        kind="api"
                    )
                    async with (ai_sem if ai_sem else asyncio.Lock()):
                        verdict, confidence, reason, severity = await verify_with_llm(
                            ai_client,
                            verify_model_name(config),
                            auth_prompt,
                            call.url if call.url.startswith(("http://", "https://")) else urljoin(target_url, call.path),
                            baseline_role['name'],
                            base_status,
                            base_body,
                            role_name,
                            test_status,
                            test_body,
                            all_role_names=all_role_names,
                            request_spacer=ai_spacer,
                            metadata=verifier_metadata,
                        )
                    if verdict == "VULNERABLE":
                        logger.warning(f"[API][{role_name}] AI CONFIRMED VULNERABILITY: {call_id}")
                        results_container['vuln'].append({
                            "endpoint": call_id,
                            "role": role_name,
                            "baseline_role": baseline_role['name'],
                            "severity": severity,
                            "confidence": confidence,
                            "description": f"Broken Access Control on API call. Role '{role_name}' can invoke '{call_id}' which should be restricted to '{baseline_role['name']}'.",
                            "reason": reason,
                            "evidence": {
                                "baseline_request": f"{call.method} {call.url}",
                                "baseline_response": f"HTTP {base_status} ({base_len} bytes)",
                                "test_request": f"{call.method} {call.url}",
                                "test_response": f"HTTP {test_status} ({test_len} bytes)",
                            }
                        })
                    elif verdict == "SAFE":
                        keep_suspicious, keep_reason = _safe_llm_result_should_stay_suspicious(
                            call_id, confidence, test_status, test_body, call.url
                        )
                        if keep_suspicious:
                            logger.info(f"[API][{role_name}] AI marked SAFE but guardrail kept SUSPICIOUS: {call_id} ({keep_reason})")
                            record_suspicious(
                                results_container, call_id, role_name, baseline_role['name'],
                                f"{keep_reason} AI reason: {reason}",
                                {
                                    "baseline_request": f"{call.method} {call.url}",
                                    "baseline_response": f"HTTP {base_status}\n\n{base_body[:2000]}",
                                    "test_request": f"{call.method} {call.url}",
                                    "test_response": f"HTTP {test_status}\n\n{test_body[:2000]}",
                                },
                                confidence=confidence,
                                severity=severity
                            )
                        else:
                            logger.info(f"[API][{role_name}] AI marked as SAFE: {call_id}")
                            results_container['safe'].add((call_id, role_name))
                    else:
                        verdict_label = "SUSPICIOUS" if verdict == "SUSPICIOUS" else "UNKNOWN"
                        promote_hit, promote_reason, promote_severity = _should_promote_suspicious_to_vuln(
                            call_id, test_status, test_body, call.url
                        )
                        if promote_hit:
                            logger.warning(f"[API][{role_name}] PROMOTED {verdict_label} TO VULNERABLE: {call_id}")
                            results_container['vuln'].append({
                                "endpoint": call_id,
                                "role": role_name,
                                "baseline_role": baseline_role['name'],
                                "severity": promote_severity,
                                "confidence": "MEDIUM",
                                "description": f"Broken Access Control on API call. Role '{role_name}' can invoke '{call_id}' which should be restricted to '{baseline_role['name']}'.",
                                "reason": f"{promote_reason} AI reason: {reason}",
                                "evidence": {
                                    "baseline_request": f"{call.method} {call.url}",
                                    "baseline_response": f"HTTP {base_status} ({base_len} bytes)",
                                    "test_request": f"{call.method} {call.url}",
                                    "test_response": f"HTTP {test_status} ({test_len} bytes)",
                                }
                            })
                            return
                        logger.info(f"[API][{role_name}] AI returned {verdict_label}: {call_id}")
                        record_suspicious(
                            results_container, call_id, role_name, baseline_role['name'],
                            reason,
                            {
                                "baseline_request": f"{call.method} {call.url}",
                                "baseline_response": f"HTTP {base_status}\n\n{base_body[:2000]}",
                                "test_request": f"{call.method} {call.url}",
                                "test_response": f"HTTP {test_status}\n\n{test_body[:2000]}",
                            },
                            confidence=confidence,
                            severity=(severity if verdict == "SUSPICIOUS" else "Information")
                        )
                else:
                    logger.info(f"[API][{role_name}] Suspicious (No AI): {call_id}")
                    record_suspicious(
                        results_container, call_id, role_name, baseline_role['name'],
                        "API replay heuristic marked this call suspicious, but no verifier AI client was available.",
                        {
                            "baseline_request": f"{call.method} {call.url}",
                            "baseline_response": f"HTTP {base_status}\n\n{base_body[:2000]}",
                            "test_request": f"{call.method} {call.url}",
                            "test_response": f"HTTP {test_status}\n\n{test_body[:2000]}",
                        },
                        confidence="LOW",
                        severity="Information"
                    )
            else:
                results_container['safe'].add((call_id, role_name))

        except Exception as e:
            logger.error(f"API Worker Error [{call.method} {call.path}]: {e}")


async def gemini_risk_check(client, model, text: str, aria_label: str, title: str,
                            el_role: str, el_tag: str, page_url: str, page_title: str):
    """Ask Gemini whether clicking a flagged element is safe in an automated crawl.

    Returns (verdict, reason) where verdict is 'SAFE' or 'SKIP'.
    Results are cached by (text, aria-label, title, url-path) to avoid redundant API calls.
    """
    if not client:
        return "SAFE", "No AI client available — defaulting to safe."

    parsed = urlparse(page_url)
    cache_key = (
        (text or "").lower().strip(),
        (aria_label or "").lower().strip(),
        (title or "").lower().strip(),
        parsed.netloc + parsed.path,
    )
    if cache_key in _gemini_risk_cache:
        cached = _gemini_risk_cache[cache_key]
        logger.debug(f"Gemini risk check (cached) → {cached[0]}: '{text or aria_label}'")
        return cached

    prompt = (
        "You are a security test automation assistant evaluating whether clicking a UI element "
        "during an automated read-only security audit would cause a harmful or irreversible "
        "side-effect.\n\n"
        f"Page URL: {page_url}\n"
        f"Page Title: {page_title}\n"
        f"Element Tag: {el_tag}\n"
        f"Element Role: {el_role}\n"
        f"Element Text: \"{text}\"\n"
        f"Element aria-label: \"{aria_label}\"\n"
        f"Element title attribute: \"{title}\"\n\n"
        "TASK: Would clicking this element likely cause a harmful or irreversible side-effect "
        "such as: sending data to a third party, deleting or modifying records, making purchases, "
        "revoking access, triggering notifications or emails, engaging a live support agent, "
        "or any other server-side state change that cannot be easily undone?\n\n"
        "SAFE = navigation, expanding menus, sorting, filtering, viewing/reading data, "
        "opening read-only modals.\n"
        "SKIP = writes, sends, deletes, charges, or modifies server-side state.\n\n"
        "Respond ONLY with valid JSON (no markdown fences):\n"
        "{\"verdict\": \"SAFE\" | \"SKIP\", \"reason\": \"one sentence\"}"
    )

    try:
        response = await asyncio.wait_for(
            asyncio.to_thread(
                client.models.generate_content,
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type='application/json',
                    temperature=0.0
                )
            ),
            timeout=30
        )
        result = _json_from_llm_text(getattr(response, "text", "") or "")
        verdict = result.get("verdict", "SAFE").upper()
        if verdict not in ("SAFE", "SKIP"):
            verdict = "SAFE"
        reason = result.get("reason", "")
        _gemini_risk_cache[cache_key] = (verdict, reason)
        return verdict, reason
    except Exception as e:
        logger.warning(f"Gemini risk check failed for '{text or aria_label}': {e}. Defaulting to SAFE.")
        return "SAFE", f"Error: {e}"


async def _submit_or_enter(page, submit_sel, fallback_selector, name=""):
    """Submit a login form, preferring a submit-button click but falling back to Enter.

    Angular/ng-disabled forms commonly render the submit button disabled until
    form validation fires. page.fill() doesn't always trigger that validation,
    so page.click() on a disabled button eats the full 30s timeout. Instead,
    check is_disabled() first and press Enter on the last-filled field if the
    button isn't clickable. Pressing Enter triggers native form submit, which
    works even when the visual button is gated.
    """
    if submit_sel:
        try:
            disabled = await page.is_disabled(submit_sel, timeout=TIMEOUT_SHORT)
        except Exception:
            disabled = True  # treat unresolved / errored as disabled
        if not disabled:
            try:
                await page.click(submit_sel, timeout=TIMEOUT_LONG)
                return
            except Exception as e:
                logger.debug(f"[{name}] Submit click failed ({e}); falling back to Enter.")
        else:
            logger.info(f"[{name}] Submit '{submit_sel}' disabled/unreachable — pressing Enter instead.")
    if fallback_selector:
        try:
            await page.press(fallback_selector, "Enter", timeout=TIMEOUT_LONG)
        except Exception as e:
            logger.warning(f"[{name}] Enter-press fallback failed: {e}")


async def _selector_resolves(page, selector, timeout_ms=3000):
    """Confirm a CSS selector actually matches a live element before calling page.fill().

    Guards against AI-hallucinated selectors or stale DOM analysis (e.g. the page
    was still loading when analyzed). Returns True if the element attaches within
    timeout_ms, False otherwise. Uses a short timeout so the caller can retry
    quickly instead of eating the default 30s page.fill() timeout.
    """
    if not selector:
        return False
    try:
        await page.wait_for_selector(selector, state='attached', timeout=timeout_ms)
        return True
    except Exception:
        return False


async def _inspect_fill_target(page, selector, expected_value=None, timeout_ms=3000):
    """Inspect whether an input is actually fillable, or already satisfied.

    This avoids Playwright's default 30s fill timeout on disabled/read-only
    inputs and handles IdP flows that pre-populate the username field.
    """
    result = {
        "selector": selector,
        "status": "missing",
        "visible": False,
        "enabled": False,
        "editable": False,
        "disabled": False,
        "readonly": False,
        "current_value": None,
        "can_press_enter": False,
    }

    if not selector:
        return result

    try:
        await page.wait_for_selector(selector, state='attached', timeout=timeout_ms)
    except Exception:
        result["status"] = "unresolved"
        return result

    locator = page.locator(selector).first

    try:
        result["visible"] = await locator.is_visible()
    except Exception:
        result["visible"] = False

    try:
        result["enabled"] = await locator.is_enabled()
    except Exception:
        result["enabled"] = False

    try:
        result["editable"] = await locator.is_editable()
    except Exception:
        result["editable"] = False

    try:
        result["disabled"] = (await locator.get_attribute("disabled")) is not None
    except Exception:
        result["disabled"] = False

    try:
        result["readonly"] = (await locator.get_attribute("readonly")) is not None
    except Exception:
        result["readonly"] = False

    try:
        result["current_value"] = await locator.input_value()
    except Exception:
        result["current_value"] = None

    result["can_press_enter"] = result["visible"] and result["enabled"]

    if result["visible"] and result["enabled"] and result["editable"] and not result["disabled"] and not result["readonly"]:
        result["status"] = "fillable"
        return result

    expected_norm = None if expected_value is None else str(expected_value).strip()
    current_norm = None if result["current_value"] is None else str(result["current_value"]).strip()
    if expected_norm is not None and current_norm == expected_norm and (result["disabled"] or result["readonly"] or not result["editable"]):
        result["status"] = "prefilled"
        return result

    result["status"] = "blocked"
    return result


async def _fill_or_reuse_prefilled(page, selector, value, *, name="", field_name="Field", timeout_ms=3000, allow_prefilled_match=True):
    """Fill an input when possible, or reuse a matching prefilled value."""
    state = await _inspect_fill_target(page, selector, expected_value=value if allow_prefilled_match else None, timeout_ms=timeout_ms)

    if state["status"] == "fillable":
        await page.fill(selector, value)
        return {
            "status": "filled",
            "selector": selector,
            "enter_fallback_selector": selector if state["can_press_enter"] else None,
            "state": state,
        }

    if state["status"] == "prefilled":
        logger.info(f"[{name}] {field_name} field '{selector}' is already set and not editable; reusing the prefilled value.")
        return {
            "status": "prefilled",
            "selector": selector,
            "enter_fallback_selector": selector if state["can_press_enter"] else None,
            "state": state,
        }

    if state["status"] == "unresolved":
        logger.warning(f"[{name}] {field_name} selector '{selector}' did not resolve; page may still be loading.")
        return {"status": "retry", "selector": selector, "state": state}

    display_value = state["current_value"]
    if field_name.lower() == "password" and display_value:
        display_value = "<redacted>"
    logger.warning(
        f"[{name}] {field_name} field '{selector}' is present but not fillable "
        f"(visible={state['visible']}, enabled={state['enabled']}, editable={state['editable']}, "
        f"disabled={state['disabled']}, readonly={state['readonly']}, current_value={display_value!r})."
    )
    return {"status": "blocked", "selector": selector, "state": state}


async def capture_auth_state(page, context) -> dict:
    """Capture browser signals used to decide whether a login actually succeeded."""
    try:
        cookies = await context.cookies()
    except Exception:
        cookies = []

    cookie_map = {
        (c.get("name"), c.get("domain", ""), c.get("path", "/")): c.get("value", "")
        for c in cookies
    }
    auth_cookie_names = [
        c.get("name", "")
        for c in cookies
        if AUTH_COOKIE_RE.search(c.get("name", ""))
    ]

    try:
        storage = await page.evaluate("""() => {
            const dump = (store) => {
                const out = {};
                for (let i = 0; i < store.length; i++) {
                    const key = store.key(i);
                    out[key] = store.getItem(key);
                }
                return out;
            };
            return {localStorage: dump(localStorage), sessionStorage: dump(sessionStorage)};
        }""")
    except Exception:
        storage = {"localStorage": {}, "sessionStorage": {}}

    storage_auth_keys = []
    for bucket, values in (storage or {}).items():
        if isinstance(values, dict):
            for key, value in values.items():
                value_text = str(value or "")
                if AUTH_STORAGE_RE.search(str(key)) or (
                    len(value_text) > 20 and re.search(r"\beyJ[A-Za-z0-9_-]{10,}", value_text)
                ):
                    storage_auth_keys.append(f"{bucket}.{key}")

    try:
        dom = await page.evaluate("""() => {
            const visible = (el) => {
                const r = el.getBoundingClientRect();
                const s = window.getComputedStyle(el);
                return r.width > 0 && r.height > 0 &&
                       s.display !== 'none' && s.visibility !== 'hidden' &&
                       parseFloat(s.opacity || '1') > 0.05;
            };
            const inputs = [...document.querySelectorAll('input')].filter((el) => {
                if (!visible(el)) return false;
                const type = (el.type || '').toLowerCase();
                return !['hidden', 'submit', 'button', 'reset', 'image'].includes(type);
            });
            const describe = (el) => {
                const form = el.closest('form');
                return {
                    type: (el.type || '').toLowerCase(),
                    meta: [
                        el.type, el.name, el.id, el.placeholder, el.getAttribute('aria-label'),
                        el.getAttribute('autocomplete'), el.getAttribute('data-testid'),
                        form ? (form.getAttribute('aria-label') || form.getAttribute('name') || form.getAttribute('id') || '') : ''
                    ].join(' ').toLowerCase(),
                };
            };
            const describedInputs = inputs.map(describe);
            const passwordInputs = describedInputs.filter((info) =>
                info.type === 'password' || info.meta.includes('current-password') || info.meta.includes('new-password')
            ).length;
            const identifierInputs = describedInputs.filter((info) => {
                if (/(search|filter|lookup|find|query|criteria|keyword)/.test(info.meta)) return false;
                if (info.type === 'password') return false;
                return /(username|user name|userid|user id|email|e-mail|login|identifier)/.test(info.meta);
            }).length;
            const text = (document.body ? document.body.innerText : '').replace(/\\s+/g, ' ').trim().slice(0, 8000);
            const buttons = [...document.querySelectorAll('button, [role="button"], a[href], input[type="submit"], input[type="button"]')]
                .filter(visible)
                .map((el) => (el.innerText || el.value || el.getAttribute('aria-label') || '').trim().toLowerCase())
                .filter(Boolean)
                .slice(0, 40);
            const formActions = [...document.querySelectorAll('form[action]')]
                .map((form) => (form.getAttribute('action') || '').trim())
                .filter(Boolean)
                .slice(0, 20);
            return {passwordInputs, identifierInputs, text, buttons, formActions, title: document.title || ''};
        }""")
    except Exception:
        dom = {"passwordInputs": 0, "identifierInputs": 0, "text": "", "buttons": [], "formActions": [], "title": ""}

    text = " ".join([dom.get("text", ""), dom.get("title", ""), " ".join(dom.get("buttons", []))])
    buttons = dom.get("buttons", []) or []
    login_cta_visible = any(re.search(r"\b(login again|log\s*in|sign\s*in)\b", btn or "", re.I) for btn in buttons)
    public_cta_visible = any(PUBLIC_LANDING_CTA_RE.search(btn or "") for btn in buttons)
    password_inputs = int(dom.get("passwordInputs") or 0)
    identifier_inputs = int(dom.get("identifierInputs") or 0)
    form_actions = dom.get("formActions", []) or []
    current_url = page.url
    auth_form_action = False
    for action in form_actions:
        try:
            resolved = urljoin(current_url, str(action))
        except Exception:
            resolved = str(action)
        if _is_login_url(resolved) or is_auth_exit_url(resolved):
            auth_form_action = True
            break
    auth_context = bool(
        _is_login_url(current_url) or
        is_auth_exit_url(current_url) or
        auth_form_action or
        (AUTH_WALL_TEXT_RE.search(text or "") and login_cta_visible)
    )
    has_login_form = bool(
        (password_inputs > 0 and (identifier_inputs > 0 or auth_context)) or
        (identifier_inputs > 0 and auth_context)
    )
    auth_material_present = bool(auth_cookie_names or storage_auth_keys)
    return {
        "url": current_url,
        "cookies": cookie_map,
        "auth_cookie_names": auth_cookie_names,
        "storage": storage or {},
        "storage_auth_keys": storage_auth_keys,
        "password_inputs": password_inputs,
        "identifier_inputs": identifier_inputs,
        "login_inputs": identifier_inputs,
        "buttons": buttons,
        "form_actions": form_actions,
        "auth_form_action": auth_form_action,
        "auth_material_present": auth_material_present,
        "login_cta_visible": login_cta_visible,
        "public_cta_visible": public_cta_visible,
        "has_login_form": has_login_form,
        "auth_wall_text": bool(AUTH_WALL_TEXT_RE.search(text or "")),
        "failure_text": bool(LOGIN_FAILURE_RE.search(text or "")),
        "success_text": bool(re.search(r"\b(log\s*out|sign\s*out|dashboard|profile|account|settings|admin|home)\b", text or "", re.I)),
    }


def is_probable_logged_out_state(state: dict, expected_url: str = "") -> bool:
    """Best-effort signal that an authenticated crawl landed on an auth wall/public shell."""
    if not state:
        return False

    current_url = state.get("url") or ""
    if is_auth_exit_url(current_url) or _is_login_url(current_url):
        return True

    try:
        current = urlparse(current_url)
        expected = urlparse(expected_url) if expected_url else None
    except Exception:
        return False

    current_path = (current.path or "/").rstrip("/") or "/"
    if state.get("has_login_form"):
        if current_path in ("/", "") or state.get("auth_form_action") or state.get("auth_wall_text"):
            return True
        return False

    if current_path not in ("/", ""):
        return False

    if state.get("public_cta_visible") and state.get("login_cta_visible"):
        return True

    if state.get("auth_wall_text") and state.get("login_cta_visible") and not state.get("success_text"):
        return True

    if state.get("login_cta_visible") and not state.get("auth_material_present"):
        return True

    if state.get("success_text") and not state.get("auth_wall_text") and state.get("auth_material_present"):
        return False

    if not expected:
        return bool(
            (state.get("auth_wall_text") or state.get("login_cta_visible")) and
            not state.get("auth_material_present")
        )

    expected_path = (expected.path or "/").rstrip("/") or "/"
    landed_on_public_root = expected_path not in ("/", "") and current_path in ("/", "")
    if not landed_on_public_root:
        return False

    return bool(
        state.get("auth_wall_text") or
        (state.get("login_cta_visible") and not state.get("auth_material_present")) or
        (not state.get("success_text") and not state.get("auth_material_present"))
    )


def _changed_auth_cookies(initial_state: dict, current_state: dict) -> list:
    before = initial_state.get("cookies") or {}
    after = current_state.get("cookies") or {}
    changed = []
    for key, value in after.items():
        name = key[0] or ""
        if not AUTH_COOKIE_RE.search(name):
            continue
        if key not in before or before.get(key) != value:
            changed.append(name)
    return changed


async def assess_login_success(page, context, initial_state: dict, actions_taken: int = 0) -> dict:
    """Return confidence that the browser is now in an authenticated state."""
    current = await capture_auth_state(page, context)
    changed_auth_cookies = _changed_auth_cookies(initial_state or {}, current)
    initial_storage_keys = set((initial_state or {}).get("storage_auth_keys") or [])
    current_storage_keys = set(current.get("storage_auth_keys") or [])
    new_storage_keys = sorted(current_storage_keys - initial_storage_keys)

    reasons = []
    score = 0

    if changed_auth_cookies:
        score += 3
        reasons.append(f"auth cookies changed/set: {', '.join(sorted(set(changed_auth_cookies))[:5])}")
    elif current.get("auth_cookie_names"):
        score += 1
        reasons.append(f"auth-looking cookies present: {', '.join(sorted(set(current['auth_cookie_names']))[:5])}")

    if new_storage_keys:
        score += 3
        reasons.append(f"auth storage keys appeared: {', '.join(new_storage_keys[:5])}")
    elif current_storage_keys:
        score += 1
        reasons.append(f"auth storage keys present: {', '.join(sorted(current_storage_keys)[:5])}")

    if actions_taken > 0 and not _is_login_url(current.get("url")):
        score += 2
        reasons.append(f"current URL is not login-like: {current.get('url')}")
    if not current.get("has_login_form"):
        score += 2
        reasons.append("no visible login/password form")
    if current.get("success_text"):
        score += 1
        reasons.append("post-login UI text/buttons detected")

    if current.get("failure_text"):
        return {
            "confidence": "LOW",
            "score": score,
            "reasons": reasons + ["login failure/challenge text visible"],
            "state": current,
        }
    if current.get("has_login_form") and _is_login_url(current.get("url")) and score < 5:
        return {
            "confidence": "LOW",
            "score": score,
            "reasons": reasons + ["still on login-like page with visible login form"],
            "state": current,
        }

    has_auth_material = bool(changed_auth_cookies or current.get("auth_cookie_names") or current_storage_keys)
    if actions_taken > 0 and not has_auth_material and not current.get("success_text") and score < 5:
        return {
            "confidence": "LOW",
            "score": score,
            "reasons": reasons + ["no auth cookie/storage/token signal after login action"],
            "state": current,
        }

    confidence = "HIGH" if score >= 6 else "MEDIUM" if score >= 3 else "LOW"
    return {
        "confidence": confidence,
        "score": score,
        "reasons": reasons or ["no strong authenticated-state signal"],
        "state": current,
    }


async def get_login_selectors(client, model, html_content, name="", attempts=2, backoff=1.5):
    """
    Asks Gemini to identify login fields and the current login state from HTML.

    Retries up to `attempts` times on transient failures (network, timeout,
    malformed JSON). Errors are logged with the `[{name}]` prefix when name is
    provided so parallel logins are distinguishable.
    """
    tag = f"[{name}] " if name else ""
    if not client:
        logger.error(f"{tag}AI Selector Analysis: no AI client configured (missing google_api_key?).")
        return None
        
    prompt = f"""
    You are a browser automation expert.
    Analyze the provided HTML of a login page or authentication step.
    Determine the 'state' of the login flow and identify the relevant CSS selectors.
    
    CRITICAL: Look for modern framework inputs (Angular Material, React MUI, etc.).
    - Inputs are often nested deep within 'mat-form-field' or similar wrappers.
    - Look for 'input[id="email"]', 'input[id="password"]', 'input[type="email"]', 'input[type="password"]'.
    - Look for 'aria-label' or 'placeholder' attributes like "Email", "Password", "Login".
    - If you see a "Login" button but no inputs, the state might be "UNKNOWN" (or requires clicking a button to show the form).
    - IMPORTANT: An input is REAL if it has tabindex="0", does NOT have aria-hidden="true",
      and is not disabled or readonly.
      Ignore container-level attributes like data-is-visible="false" on wrapper divs — only
      the input element's own tabindex/aria-hidden matter. A password input with tabindex="0"
      is always a real, interactive field regardless of its parent container's attributes.
    - If a username/email field is disabled or readonly but already pre-populated, do NOT use it
      as the selector to fill. If a password field is editable on the same step, prefer
      PASSWORD_ONLY. If the page is a locked/pre-filled identity step with only a Next/Continue
      action, you may still classify it as USERNAME_ONLY, but avoid choosing disabled inputs
      when an editable alternative exists.

    Possible States:
    - "USERNAME_ONLY": Only a username/email field is visible.
    - "PASSWORD_ONLY": Only a password field is visible.
    - "BOTH": Both username and password fields are visible.
    - "MFA": One or more 2FA/OTP/Security Question fields are visible.
    - "CAPTCHA": A CAPTCHA challenge is visible and must be solved before proceeding.
      Detect this state by ANY of the following signals — the word "captcha" need NOT appear:
        * Named CAPTCHA widgets: reCAPTCHA (iframe[src*='recaptcha'], .g-recaptcha, #recaptcha),
          hCaptcha (iframe[src*='hcaptcha'], .h-captcha), Cloudflare Turnstile
          (.cf-turnstile, iframe[src*='challenges.cloudflare.com']).
        * Image CAPTCHA — requires a CAPTCHA image to be present AND loaded. The image is
          identified by ALL of the following: it has alt text containing 'captcha' OR
          id="captchaimg", AND it has a non-empty src attribute (e.g. src="/Captcha?...").
          An <img id="captchaimg"> with NO src attribute means the CAPTCHA is not yet active
          — do NOT treat this as a CAPTCHA signal.
          When a CAPTCHA image is confirmed present, ALSO look for these corroborating signals:
            - A text input with aria-label containing "hear or see", "type the text you", or "characters you see"
            - Text on page: "enter the characters you see", "type the text you hear or see", "listen and type the numbers you hear"
            - A button with aria-label containing "Listen and type"
          CRITICAL: A text input alone (even with an unusual name/id) is NOT a CAPTCHA signal.
          The CAPTCHA image must be present. If no CAPTCHA image exists, do not return CAPTCHA state.
          If a CAPTCHA image IS present, the nearby text input is the answer field — do NOT
          classify the page as USERNAME_ONLY or BOTH even if the input looks like a text field.
        * Human-verification text anywhere on the page: "distinguish humans from robots",
          "verify you are human", "prove you're not a robot", "I'm not a robot", "bot detection",
          "complete the challenge". These alone (without login fields) indicate CAPTCHA state.
        * Attributes on inputs/containers: input[name*='captcha'], input[id*='captcha'],
          button[aria-label*='Listen and type'].
    - "USERNAME_AND_CAPTCHA": A username/email field AND a CAPTCHA challenge are both visible
      on the same page at the same time. Use this when a confirmed CAPTCHA image (see signals
      above) is present alongside a real email/username input (type="email", type="text" with
      aria-label like "Email", "Username", "Email or phone", name="identifier", etc.).
      NOTE: ignore hidden or aria-hidden password fields (tabindex="-1", aria-hidden="true") —
      those are not real password fields.
    - "PASSWORD_AND_CAPTCHA": A password field AND a CAPTCHA challenge are both visible on
      the same page at the same time. Use this when a confirmed CAPTCHA image is present
      alongside a real password input (type="password", tabindex="0", NOT aria-hidden,
      e.g. aria-label="Enter your password", name="Passwd"). This often appears after too
      many failed login attempts. The CAPTCHA answer input (name="ca", aria-label containing
      "hear or see") is separate from the password input — do not confuse them.
      NOTE: ignore hidden inputs (tabindex="-1", aria-hidden="true") like name="identifier"
      or name="hiddenPassword" — those are pre-filled hidden fields, not real inputs.
    - "UNKNOWN": No clear login fields found.

    Return ONLY a JSON object with the following keys:
    - "state": "USERNAME_ONLY" | "PASSWORD_ONLY" | "BOTH" | "MFA" | "CAPTCHA" | "USERNAME_AND_CAPTCHA" | "PASSWORD_AND_CAPTCHA" | "UNKNOWN"
    - "username_selector": str (if applicable, else null)
    - "password_selector": str (if applicable, else null)
    - "mfa_fields": list of objects (if state is MFA, else empty list). Each object must have:
        - "selector": str (CSS selector for the input field)
        - "label": str (The text of the question or label associated with the input)
    - "submit_selector": str (The 'Next', 'Continue', 'Verify', or 'Login' button)

    Page Context (structured JSON extracted from the live DOM):
    {html_content[:60000]}

    The JSON contains:
    - "inputs": list of all <input> elements with type, id, name, ariaLabel, placeholder,
      autocomplete, maxlength, tabIndex, ariaHidden, disabled, readOnly, hasValue,
      nearbyText (label text near the input)
    - "buttons": list of all interactive buttons/[role=button] elements with tag, id, name,
      type, ariaLabel, text (button label), jsname
    - "headings": visible h1/h2/h3 text on the page
    - "alerts": aria-live / role=alert text (error messages, status notices)
    - "visibleText": other visible text snippets

    Use "ariaLabel", "nearbyText", "headings", "alerts", and "visibleText" as your primary
    signal for classifying MFA / CAPTCHA / login state. For MFA specifically: look for
    headings or visible text like "2-Step Verification", "Verify your identity",
    "Enter the code", "Enter verification code", "Enter your OTP", "Security code",
    "Check your phone", or inputs with maxlength <= 8 or type="tel"/"number" near such text.
    An input is real (interactive) if tabIndex >= 0, ariaHidden is not "true", and both
    disabled/readOnly are false.

    For "submit_selector": choose the button whose text/ariaLabel best matches "Next",
    "Continue", "Sign in", "Log in", "Verify", or similar forward-progress actions.
    NEVER return a selector for "Forgot password", "Forgot email", "Create account",
    "Guest mode", or any other secondary/helper link — those are not submit buttons.
    """
    
    last_err = None
    for attempt in range(1, attempts + 1):
        try:
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    client.models.generate_content,
                    model=model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type='application/json',
                        temperature=0.0
                    )
                ),
                timeout=30
            )
            return _json_from_llm_text(getattr(response, "text", "") or "")
        except Exception as e:
            last_err = e
            if attempt < attempts:
                logger.warning(f"{tag}AI Selector Analysis attempt {attempt}/{attempts} failed: {e}. Retrying in {backoff}s...")
                await asyncio.sleep(backoff)
            else:
                logger.error(f"{tag}AI Selector Analysis failed after {attempts} attempts: {e}")
    return None


async def dismiss_popups(page):
    """
    Attempts to dismiss common overlays, cookie consents, or welcome dialogs.
    """
    try:
        # 1. Try generic Escape key (often closes modals)
        await page.keyboard.press("Escape")
        await page.wait_for_timeout(300)

        # 2. Specific selectors for dismiss/accept buttons
        selectors = [
            # Juice Shop / Angular Material specific
            'button[aria-label="Close Welcome Banner"]',
            'button[aria-label="Dismiss cookie message"]',
            '.mat-mdc-dialog-container .close-dialog',
            '.mat-mdc-dialog-container button:has-text("Dismiss")',
            '.cdk-overlay-backdrop', # Click the background to close
            
            # MUI dialog close button (aria-label="close" lowercase — MUI convention)
            'button[aria-label="close"]',
            '[role="button"][aria-label="close"]',

            # General <button> variants
            'a.cc-dismiss',
            'button.cc-dismiss',
            'button:has-text("Acknowledge")',
            'button:has-text("Acknowledged")',
            'button:has-text("OK")',
            'button:has-text("Got it")',
            'button:has-text("Dismiss")',
            'button:has-text("Close")',
            'button:has-text("Close Preferences")',
            'button:has-text("Cancel")',
            'button:has-text("No thanks")',
            'button:has-text("Accept all")',
            'button:has-text("I understand")',
            'button[aria-label="Close Preferences"]',

            # MUI / role="button" div variants (same labels but rendered as divs)
            '[role="button"]:has-text("Close")',
            '[role="button"]:has-text("Cancel")',
            '[role="button"]:has-text("Dismiss")',
            '[role="button"]:has-text("OK")',
            '[role="button"]:has-text("Close Preferences")',

            '.close-dialog',
            '.modal-close',

            # Any button/role=button whose aria-label starts with "close" or "Close"
            # Catches: "close-info-drawer", "close-modal", "Close dialog", etc.
            'button[aria-label^="close"]',
            'button[aria-label^="Close"]',
            '[role="button"][aria-label^="close"]',
            '[role="button"][aria-label^="Close"]',

            # Live chat / chatbot close/minimize buttons
            'button[aria-label="Close conversation"]',
            'button[aria-label="Close chat"]',
            'button[aria-label="Minimize chat"]',
            'button[aria-label="Hide chat"]',
            '[aria-label="Close messenger"]',       # Intercom
            '[data-testid="close-button"]',         # Intercom / generic
            '[data-testid="minimize-button"]',
            'button.intercom-space-between',        # Intercom header close
            '.drift-close-button',
            '#drift-widget button[aria-label="Close"]',
        ]
        
        for sel in selectors:
            try:
                # Check visibility first to avoid waiting
                if await page.is_visible(sel, timeout=TIMEOUT_BRIEF):
                    logger.info(f"Dismissing popup with selector: {sel}")
                    await page.click(sel, force=True) # Force click in case of overlay issues
                    await page.wait_for_timeout(500) # Wait for animation
            except Exception: pass
            
    except Exception as e:
        logger.debug(f"Popup dismissal error: {e}")


async def _harvest_api_log(page, base_url, allowed_domains):
    """Read window.__skApiLog, normalise, return list[ApiCall], then clear the log."""
    try:
        raw = await page.evaluate("(window.__skApiLog || []).splice(0)")  # read + clear atomically
    except Exception:
        return []

    calls = []
    seen = set()

    for entry in raw:
        try:
            url_str = entry.get("url", "")
            if not url_str or url_str.startswith("data:") or url_str.startswith("blob:"):
                continue
            parsed = urlparse(url_str)
            if parsed.netloc and parsed.netloc not in allowed_domains:
                continue   # cross-domain — skip
            if is_static_resource(url_str):
                continue

            path = endpoint_from_url(url_str)

            method  = (entry.get("method") or "GET").upper()
            body    = entry.get("body") or None
            headers = entry.get("headers") or {}

            key = (method, path)
            if key in seen:
                continue
            seen.add(key)

            abs_url = url_str if url_str.startswith(("http://", "https://")) else urljoin(base_url, url_str)
            calls.append(ApiCall(method=method, url=abs_url, path=path,
                                 body=body, headers=headers))
        except Exception:
            pass

    return calls


async def _fill_page_password(page, username: Optional[str], password: str):
    """Detect and fill an HTML password overlay on the current page.

    Covers single-password gates (no username field) and basic username+password forms.
    Does nothing if no visible password input is found.
    """
    try:
        # Give the overlay a moment to appear after navigation
        pw_input = page.locator("input[type='password']:visible").first
        if not await pw_input.is_visible(timeout=TIMEOUT_MEDIUM):
            return

        logger.info("Page password prompt detected — filling credentials.")

        # Fill username if a visible text/email input exists alongside the password field
        if username:
            for user_sel in ["input[type='text']:visible", "input[type='email']:visible",
                             "input[name*='user']:visible", "input[name*='login']:visible"]:
                user_fill = await _fill_or_reuse_prefilled(
                    page,
                    user_sel,
                    username,
                    field_name="Username",
                )
                if user_fill["status"] in ("filled", "prefilled"):
                    break

        pass_fill = await _fill_or_reuse_prefilled(
            page,
            "input[type='password']:visible",
            password,
            field_name="Password",
            allow_prefilled_match=False,
        )
        if pass_fill["status"] != "filled":
            return

        # Record URL before submitting so we can detect when navigation completes.
        # NOTE: page.wait_for_load_state("domcontentloaded") returns immediately if the
        # page is already at that state — which it always is right after page.goto.
        # We must detect the navigation ourselves.
        pre_submit_url = page.url

        # Submit: prefer an explicit submit button, fall back to Enter
        submitted = False
        for submit_sel in ["input[type='submit']:visible", "button[type='submit']:visible",
                           "button:has-text('Login'):visible", "button:has-text('Sign in'):visible",
                           "button:has-text('Submit'):visible", "button:has-text('OK'):visible",
                           "button:has-text('Enter'):visible"]:
            try:
                btn = page.locator(submit_sel).first
                if await btn.is_visible(timeout=TIMEOUT_BRIEF):
                    await btn.click()
                    submitted = True
                    break
            except Exception:
                pass

        if not submitted:
            await pw_input.press("Enter")

        # Wait for actual navigation away from the gate page (URL change).
        # Falls through gracefully for AJAX-based gates that don't change URL.
        try:
            await page.wait_for_url(lambda url: url != pre_submit_url, timeout=8000)
        except Exception:
            pass

        # Now wait for the destination page to settle.
        try:
            await page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=8000)
            except Exception:
                pass

        logger.info(f"Page password submitted — now at: {page.url}")
    except Exception:
        pass  # No overlay present or already dismissed


AUTH_FLOW_PATH_RE = re.compile(
    r"(login|auth|signin|sign-in|token|sso|saml|oauth|callback|authorize|"
    r"acs|idp|sp|session|password|csrf)",
    re.IGNORECASE,
)
AUTH_FLOW_PARAM_RE = re.compile(
    r"(username|password|grant_type|client_id|samlresponse|code|assertion|"
    r"credential|state|nonce|id_token|access_token|refresh_token)",
    re.IGNORECASE,
)


def _request_param_keys(req: dict) -> set:
    keys = set()
    parsed = urlparse(req.get("url", ""))
    for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
        keys.add(key)
    body = req.get("post_data") or ""
    if isinstance(body, str) and body:
        if body.strip().startswith("{"):
            try:
                parsed_body = json.loads(body)
                if isinstance(parsed_body, dict):
                    keys.update(str(k) for k in parsed_body.keys())
            except Exception:
                pass
        else:
            for key, _ in parse_qsl(body, keep_blank_values=True):
                keys.add(key)
    return keys


def _response_cookie_names(req: dict) -> list:
    sc = (req.get("response_headers") or {}).get("set-cookie", "")
    names = []
    for line in sc.split("\n"):
        part = line.split(";", 1)[0]
        if "=" in part:
            names.append(part.split("=", 1)[0].strip())
    return [n for n in names if n]


def deterministic_auth_keep_indices(traffic_list: list) -> set:
    """Conservative auth-flow filter that preserves strong causal-chain evidence."""
    keep = set()
    last_auth_redirect_idx = None

    for i, req in enumerate(traffic_list):
        if req.get("type") == "marker":
            keep.add(i)
            continue
        if i == 0:
            keep.add(i)

        url = req.get("url", "")
        parsed = urlparse(url)
        path = parsed.path or "/"
        method = (req.get("method") or "GET").upper()
        try:
            status = int(req.get("status") or 0)
        except (TypeError, ValueError):
            status = 0
        resp_headers = req.get("response_headers") or {}
        content_type = resp_headers.get("content-type", "")
        location = resp_headers.get("location", "")
        cookie_names = _response_cookie_names(req)
        param_keys = _request_param_keys(req)
        resp_keys = set(req.get("response_body_keys") or [])

        if any(ct in content_type for ct in ("image/", "video/", "audio/")) and not cookie_names:
            continue
        if is_static_resource(url) and not cookie_names:
            continue

        auth_signal = False
        if cookie_names:
            auth_signal = True
        if method == "POST" and AUTH_FLOW_PATH_RE.search(path):
            auth_signal = True
        if AUTH_FLOW_PATH_RE.search(path):
            auth_signal = True
        if any(AUTH_FLOW_PARAM_RE.search(k) for k in param_keys):
            auth_signal = True
        if any(AUTH_FLOW_PARAM_RE.search(k) for k in resp_keys):
            auth_signal = True
        if 300 <= status < 400 and location and (
            AUTH_FLOW_PATH_RE.search(location) or AUTH_FLOW_PARAM_RE.search(location)
        ):
            auth_signal = True
            last_auth_redirect_idx = i

        if auth_signal:
            keep.add(i)

    if last_auth_redirect_idx is not None:
        keep.add(last_auth_redirect_idx)
        for idx in range(max(0, last_auth_redirect_idx - 2), last_auth_redirect_idx):
            if idx < len(traffic_list):
                candidate = traffic_list[idx]
                if candidate.get("type") == "marker" or _response_cookie_names(candidate) or not is_static_resource(candidate.get("url", "")):
                    keep.add(idx)

    return keep


def is_obvious_auth_flow_noise(req: dict) -> bool:
    if req.get("type") == "marker":
        return False
    url = req.get("url", "")
    parsed = urlparse(url)
    path = parsed.path or "/"
    method = (req.get("method") or "GET").upper()
    try:
        status = int(req.get("status") or 0)
    except (TypeError, ValueError):
        status = 0
    resp_headers = req.get("response_headers") or {}
    content_type = resp_headers.get("content-type", "")
    cookie_names = _response_cookie_names(req)
    location = resp_headers.get("location", "")
    param_keys = _request_param_keys(req)
    resp_keys = set(req.get("response_body_keys") or [])

    if cookie_names:
        return False
    if is_static_resource(url):
        return True
    if any(ct in content_type for ct in ("image/", "video/", "audio/")):
        return True
    if AUTH_FLOW_PATH_RE.search(path):
        return False
    if any(AUTH_FLOW_PARAM_RE.search(k) for k in param_keys):
        return False
    if any(AUTH_FLOW_PARAM_RE.search(k) for k in resp_keys):
        return False
    if 300 <= status < 400 and location and (
        AUTH_FLOW_PATH_RE.search(location) or AUTH_FLOW_PARAM_RE.search(location)
    ):
        return False
    noise_path = re.search(
        r"(/api/(feed|news|events|notifications|home|weather|metrics|telemetry)|"
        r"/dashboard$|/home$|/main$|/app$|socket\.io|heartbeat|/ping$|/health$)",
        path,
        re.IGNORECASE,
    )
    if method == "GET" and 200 <= status < 300 and noise_path:
        return True
    return False


async def filter_traffic_with_ai(client, model, traffic_list):
    """
    Uses Gemini to filter out noise from the captured traffic, keeping only 
    authentication-relevant requests (Login, Token Exchange, SSO Redirects, Session Set).
    """
    if not traffic_list:
        return traffic_list

    deterministic_keep = deterministic_auth_keep_indices(traffic_list)
    if not client:
        return [req for i, req in enumerate(traffic_list) if i in deterministic_keep]

    # Prepare enriched summary for AI — surface every signal that distinguishes auth from noise
    summary = []
    for i, req in enumerate(traffic_list):
        if req.get('type') == 'marker':
            summary.append(f"{i} | [MARKER] {req.get('label')}")
        else:
            url = req['url']
            parsed = urlparse(url)
            host = parsed.netloc
            path = parsed.path
            method = req['method']
            status = req['status']
            resp_headers = req.get('response_headers', {})
            ctype = resp_headers.get('content-type', '')

            hints = []

            # Cookies set by this response (strongest auth signal)
            sc = resp_headers.get('set-cookie', '')
            if sc:
                names = []
                for line in sc.split('\n'):
                    part = line.split(';')[0]
                    if '=' in part:
                        names.append(part.split('=')[0].strip())
                if names:
                    hints.append(f"sets-cookies:{','.join(names)}")

            # Location header (redirect destination — critical for OAuth chains)
            loc = resp_headers.get('location', '')
            if loc:
                parsed_loc = urlparse(loc)
                loc_summary = parsed_loc.path
                if parsed_loc.query:
                    qkeys = [p.split('=')[0] for p in parsed_loc.query.split('&') if '=' in p]
                    loc_summary += f"?{','.join(qkeys[:6])}"
                hints.append(f"→{loc_summary}")

            # Request body / query param keys
            body_keys = []
            body = req.get('post_data', '') or ''
            if body.startswith('{'):
                try:
                    body_keys = list(json.loads(body).keys())
                except Exception:
                    pass
            elif '=' in body:
                body_keys = [p.split('=')[0] for p in body.split('&') if '=' in p]
            if not body_keys and parsed.query:
                body_keys = [p.split('=')[0] for p in parsed.query.split('&') if '=' in p]
            if body_keys:
                hints.append(f"params:{','.join(body_keys[:8])}")

            # Response JSON keys (e.g. access_token, id_token signal token endpoint)
            resp_body_keys = req.get('response_body_keys', [])
            if resp_body_keys:
                hints.append(f"resp-keys:{','.join(resp_body_keys[:8])}")

            # NOTE: js_cookies is deliberately NOT included here.
            # It is a post-login browser diff attached to the last traffic entry —
            # not a signal that THIS specific request set those cookies.
            # Including it causes Gemini to falsely classify the last API call as
            # auth-relevant (e.g. GET /api/agents/solution kept because token cookie appeared on it).

            hint_str = "  [" + " | ".join(hints) + "]" if hints else ""
            summary.append(f"{i} | {method} {host}{path} ({status}){hint_str}")

    summary_text = "\n".join(summary)
    deterministic_hint = ", ".join(str(i) for i in sorted(deterministic_keep))
    if len(summary) > 120 and deterministic_keep:
        focus = set(deterministic_keep)
        for idx in list(deterministic_keep):
            focus.update({idx - 1, idx + 1})
        focus = {idx for idx in focus if 0 <= idx < len(summary)}
        summary_text = "\n".join(summary[i] for i in sorted(focus))
        logger.info(f"Auth map cleanup: long log reduced from {len(summary)} to {len(focus)} focused lines before AI review.")

    prompt = f"""You are a Security Analyst building a clean authentication flow diagram.
Your task: given a raw HTTP request log captured during a login/SSO session, return the indices of ONLY the requests that are part of the authentication chain.

=== ABSOLUTE RULE ===
ALWAYS keep every [MARKER] line. They mark SSO phase boundaries and must never be removed.
ALWAYS keep these deterministic must-keep indices unless the line is obviously malformed: [{deterministic_hint}]

=== AUTHENTICATION IS A CAUSAL CHAIN (with a clear end boundary) ===
Treat the auth flow as a linked sequence. If request A triggers a redirect to B, and B triggers token exchange C, then A, B, and C are ALL part of the chain — even if B or C look like generic pages in isolation. Never break the chain by dropping a middle link.
HOWEVER, the chain has a definite END: it ends at the LAST redirect that completes the auth handshake (e.g. GET /callback → 302 → /dashboard). The destination of that final redirect (/dashboard, /home, /main, /app) is the first post-auth app page — it is NOT part of the authentication chain itself and should be EXCLUDED.

=== KEEP (authentication-relevant signals, in order of priority) ===
1. Any response that sets a session or auth cookie  (sets-cookies: hint present)
2. Any POST to a path containing: login, auth, signin, token, sso, saml, oauth, callback, authorize, acs, idp, sp, session, password
3. Any redirect (3xx) whose Location contains: code=, token=, SAMLResponse=, state=, session, callback, authorize
4. Any response with resp-keys containing: access_token, id_token, refresh_token, token_type, session_token, assertion
5. Any request carrying auth body params: username, password, grant_type, client_id, SAMLResponse, code, assertion, credential
6. The very first GET request of the flow (the initial navigation to the login page)
7. Any GET whose path contains the auth keywords from rule 2

=== EXCLUDE (noise signals) ===
1. Static assets: .js, .css, .woff, .png, .svg, .ico — unless they set a cookie
2. Any GET with status 200 that loads business/app data and sets no cookie: /api/feed, /api/news, /api/events, /api/notifications, /api/home, /dashboard, /api/weather, telemetry, analytics, metrics, health, heartbeat, ping, socket.io
3. The same path repeated 3+ times with no cookie change (polling/keep-alive)
4. Any response whose content-type is image/*, video/*, audio/*

=== TIEBREAKER ===
When uncertain, KEEP the request. A slightly verbose clean map is better than a broken chain.

=== EXAMPLE (OIDC flow) ===
KEEP: GET /login (200) — start of chain
KEEP: POST /login (302) sets-cookies:session → /authorize  — credential submit + session
KEEP: GET /authorize (302) → /idp/authorize?code=,state=  — OIDC start
KEEP: GET /idp/authorize (302) → /callback?code=,state=   — IdP redirect
KEEP: GET /callback (302) sets-cookies:access_token → /dashboard  — final auth redirect (CHAIN ENDS HERE)
KEEP: POST /token (200) resp-keys:access_token,id_token   — token endpoint response
EXCLUDE: GET /dashboard (200)                             — first post-auth app page, chain already complete
EXCLUDE: GET /api/user/notifications (200)                — post-auth data load
EXCLUDE: GET /static/app.js (200)                         — static asset

=== LOG ===
{summary_text}

Return JSON only: {{ "keep_indices": [0, 1, 5, ...] }}"""

    try:
        response = await asyncio.wait_for(
            asyncio.to_thread(
                client.models.generate_content,
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type='application/json',
                    temperature=0.0
                )
            ),
            timeout=30
        )
        result = _json_from_llm_text(getattr(response, "text", "") or "")
        keep_indices = set(deterministic_keep)
        for idx in result.get("keep_indices", []):
            try:
                idx_int = int(idx)
            except (TypeError, ValueError):
                pass
            else:
                if idx_int in deterministic_keep or (
                    0 <= idx_int < len(traffic_list) and not is_obvious_auth_flow_noise(traffic_list[idx_int])
                ):
                    keep_indices.add(idx_int)
        
        # Filter list
        filtered = [req for i, req in enumerate(traffic_list) if i in keep_indices]
        logger.info(f"AI Filtered Traffic: Kept {len(filtered)}/{len(traffic_list)} requests ({len(deterministic_keep)} deterministic).")
        return filtered

    except Exception as e:
        filtered = [req for i, req in enumerate(traffic_list) if i in deterministic_keep]
        logger.warning(f"AI Traffic Filtering failed: {e}. Returning deterministic auth-chain filter ({len(filtered)}/{len(traffic_list)} requests).")
        return filtered

async def _handle_captcha_block(name, input_lock, lines):
    """Display a CAPTCHA prompt and wait for the user to solve it in the browser.

    ``lines`` is a list of strings to print inside the banner.
    """
    if input_lock:
        async with input_lock:
            root_logger = logging.getLogger()
            original_level = root_logger.getEffectiveLevel()
            root_logger.setLevel(logging.ERROR)
            try:
                print(f"\n{'='*60}")
                for line in lines:
                    print(line)
                print(f"{'='*60}")
                await asyncio.to_thread(input, "")
            finally:
                root_logger.setLevel(original_level)
    else:
        print(f"\n{'='*60}")
        for line in lines:
            print(line)
        print(f"{'='*60}")
        input("")


async def perform_manual_login(browser, url, username, input_lock=None, sso_selector=None):
    """
    Opens a browser for manual login — the user completes the login flow manually.
    Returns a role object with captured cookies and auth state, or None if login failed.
    """
    name = username
    logger.info(f"Opening browser for manual login: {name}")

    # A browser reached through CDP has a persistent default context. Reuse it
    # so login and crawl retain the exact browser/TLS/session state that passed
    # an upstream bot or WAF challenge.
    existing_contexts = browser.contexts
    reuse_context = bool(existing_contexts)
    if reuse_context:
        context = existing_contexts[0]
    else:
        context = await browser.new_context(
            ignore_https_errors=True,
            viewport={'width': 1920, 'height': 1080}
        )

    # Do not alter browser globals in a user-driven CDP session. Some bot
    # managers detect the synthetic property descriptor itself.
    if not reuse_context:
        await context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
            });
        """)

    page = context.pages[0] if reuse_context and context.pages else await context.new_page()

    try:
        if not reuse_context and page.url.rstrip('/') != url.rstrip('/'):
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)

        # Capture initial auth state (pre-login)
        initial_auth_state = await capture_auth_state(page, context)

        # Display instructions to the user
        if input_lock:
            async with input_lock:
                root_logger = logging.getLogger()
                original_level = root_logger.getEffectiveLevel()
                root_logger.setLevel(logging.ERROR)
                try:
                    print(f"\n{'='*60}")
                    print(f"[MANUAL LOGIN] User: {name}")
                    print(f"  Browser window is open at: {url}")
                    print(f"  Complete the login flow manually in the browser window.")
                    print(f"  - Enter credentials")
                    print(f"  - Handle any MFA/CAPTCHA prompts")
                    print(f"  - Navigate to the post-login dashboard/page")
                    print(f"  When login is complete, press Enter here to continue...")
                    print(f"{'='*60}")
                    await asyncio.to_thread(input, "")
                finally:
                    root_logger.setLevel(original_level)
        else:
            print(f"\n{'='*60}")
            print(f"[MANUAL LOGIN] User: {name}")
            print(f"  Browser window is open at: {url}")
            print(f"  Complete the login flow manually in the browser window.")
            print(f"  - Enter credentials")
            print(f"  - Handle any MFA/CAPTCHA prompts")
            print(f"  - Navigate to the post-login dashboard/page")
            print(f"  When login is complete, press Enter here to continue...")
            print(f"{'='*60}")
            input("")

        # After user signals completion, wait a moment for any final page transitions
        await page.wait_for_timeout(3000)

        # --- SSO / Portal Launch Logic ---
        if sso_selector:
            logger.info(f"[{name}] SSO Mode: Looking for launch selector '{sso_selector}'...")
            try:
                await page.wait_for_selector(sso_selector, timeout=10000)
                logger.info(f"[{name}] Found launch button. Clicking...")

                portal_url = page.url

                try:
                    async with context.expect_page(timeout=5000) as new_page_info:
                        await page.click(sso_selector)

                    new_page = await new_page_info.value
                    await new_page.wait_for_load_state('domcontentloaded')
                    page = new_page

                    logger.info(f"[{name}] Switched to new tab/window: {page.url}")
                except Exception:
                    try:
                        await page.wait_for_url(lambda u: u != portal_url, timeout=15000)
                        logger.info(f"[{name}] Navigated in-place to: {page.url}")
                    except Exception:
                        logger.warning(f"[{name}] URL did not change after SSO click. Continuing anyway.")

                await page.wait_for_timeout(5000)

            except Exception as e:
                logger.error(f"[{name}] SSO Launch Failed: {e}")

        # Assess login success
        login_assessment = await assess_login_success(page, context, initial_auth_state, actions_taken=1)
        reason_summary = "; ".join(login_assessment.get("reasons", [])[:4])
        if login_assessment["confidence"] == "LOW":
            logger.error(f"[{name}] Login did not produce enough authenticated-state evidence (score={login_assessment['score']}: {reason_summary}).")
            return None
        if login_assessment["confidence"] == "MEDIUM":
            logger.warning(f"[{name}] Login confidence MEDIUM (score={login_assessment['score']}: {reason_summary}). Continuing, but results may need review.")
        else:
            logger.info(f"[{name}] Login confidence HIGH (score={login_assessment['score']}: {reason_summary}).")

        # Capture Cookies & Final URL
        cookies = await context.cookies()
        final_url = page.url

        # Capture Local/Session Storage
        storage_state = await page.evaluate("""() => {
            return {
                localStorage: JSON.stringify(localStorage),
                sessionStorage: JSON.stringify(sessionStorage)
            }
        }""")

        if not cookies:
            logger.warning(f"[{name}] No cookies captured after manual login.")

        return {
            "name": name,
            "cookies": cookies,
            "storage": storage_state,
            "headers": {},
            "history": [],
            "start_url": final_url,
            "auth_confidence": login_assessment["confidence"],
            "auth_confidence_reasons": login_assessment.get("reasons", []),
        }

    except Exception as e:
        logger.error(f"[{name}] Manual login process failed: {e}")
        return None
    finally:
        if not reuse_context:
            await context.close()


async def perform_login(browser, url, username, password, ai_client, model, capture_traffic=False, input_lock=None, sso_selector=None):
    """
    Performs an AI-assisted multi-step login action and returns a role object with captured cookies.
    """
    name = username
    logger.info(f"Attempting AI-driven login for: {name}")
    
    context = await browser.new_context(
        ignore_https_errors=True,
        viewport={'width': 1920, 'height': 1080}
    )
    
    traffic_history = []

    if capture_traffic:
        async def on_response(response):
            try:
                # Filter static
                if is_static_resource(response.url): return
                # We want the request that triggered this response
                req = response.request

                # Capture body safely
                post_data = req.post_data

                # Capture response body JSON keys (e.g. access_token, id_token, token_type)
                # Must be read here while the response is still live.
                resp_headers = await response.all_headers()
                resp_body_keys = []
                if 'application/json' in resp_headers.get('content-type', ''):
                    try:
                        body_text = await response.text()
                        body_data = json.loads(body_text)
                        if isinstance(body_data, dict):
                            resp_body_keys = list(body_data.keys())[:20]
                    except Exception:
                        pass

                # Store
                traffic_history.append({
                    "url": response.url,
                    "method": req.method,
                    "status": response.status,
                    "request_headers": await req.all_headers(),
                    "response_headers": resp_headers,
                    "post_data": post_data,
                    "response_body_keys": resp_body_keys,
                    "time": asyncio.get_event_loop().time()
                })
            except Exception as e:
                pass # Ignore errors during capture
        
        context.on("response", on_response)
    
    # Bypass common bot detection
    await context.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined
        });
    """)

    page = await context.new_page()
    
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        
        # Initial cleanup
        await dismiss_popups(page)
        initial_auth_state = await capture_auth_state(page, context)
        
        # Max steps to prevent infinite loops
        max_steps = 8
        actions_taken = 0
        consecutive_unknowns = 0
        _sso_pre_clicked = False  # track if we've already used the SSO selector as a pre-login gate

        for step in range(max_steps):
            logger.info(f"[{name}] Analyzing Login Step {step + 1}...")

            # Ensure view is clear
            await dismiss_popups(page)
            
            # Wait a moment for dynamic forms to appear
            await page.wait_for_timeout(3000)
            
            # Try to wait for inputs specifically (helps with SPAs)
            try:
                await page.wait_for_selector('input', timeout=TIMEOUT_MEDIUM)
            except Exception: pass

            # Build a compact structured summary of the page for the AI.
            # Sending raw inner_html is unreliable — important text can be buried
            # thousands of characters in, past the model's effective attention window.
            try:
                form_context = await page.evaluate("""() => {
                    function isReal(el) {
                        return el.tabIndex >= 0 && el.getAttribute('aria-hidden') !== 'true';
                    }
                    function nearbyLabel(el) {
                        // Walk up to find associated label text
                        let node = el;
                        for (let i = 0; i < 5; i++) {
                            node = node.parentElement;
                            if (!node) break;
                            const text = Array.from(node.childNodes)
                                .filter(n => n.nodeType === 3)
                                .map(n => n.textContent.trim())
                                .filter(Boolean)
                                .join(' ');
                            if (text) return text.slice(0, 120);
                        }
                        return '';
                    }
                    const inputs = Array.from(document.querySelectorAll('input')).map(inp => ({
                        type: inp.type,
                        id: inp.id || null,
                        name: inp.name || null,
                        ariaLabel: inp.getAttribute('aria-label') || null,
                        placeholder: inp.placeholder || null,
                        autocomplete: inp.getAttribute('autocomplete') || null,
                        maxlength: inp.maxLength > 0 ? inp.maxLength : null,
                        tabIndex: inp.tabIndex,
                        ariaHidden: inp.getAttribute('aria-hidden') || null,
                        disabled: !!inp.disabled,
                        readOnly: !!inp.readOnly,
                        hasValue: !!inp.value,
                        nearbyText: nearbyLabel(inp)
                    }));
                    const headings = Array.from(document.querySelectorAll('h1,h2,h3'))
                        .map(h => h.textContent.trim()).filter(Boolean).slice(0, 5);
                    const alerts = Array.from(document.querySelectorAll('[aria-live],[role="alert"],[role="status"]'))
                        .map(el => el.textContent.trim()).filter(Boolean).slice(0, 5);
                    const visibleText = Array.from(document.querySelectorAll(
                        'div[jsslot], span[jsslot], label, p, .subTitle, .subtitle'
                    )).map(el => el.textContent.trim()).filter(t => t.length > 3 && t.length < 200)
                      .slice(0, 15);
                    const buttons = Array.from(document.querySelectorAll(
                        'button, [role="button"], input[type="submit"]'
                    )).filter(el => el.tabIndex >= 0 && el.getAttribute('aria-hidden') !== 'true')
                      .map(el => ({
                          tag: el.tagName.toLowerCase(),
                          id: el.id || null,
                          name: el.name || null,
                          type: el.type || null,
                          ariaLabel: el.getAttribute('aria-label') || null,
                          text: el.textContent.trim().slice(0, 80) || null,
                          jsname: el.getAttribute('jsname') || null
                      })).slice(0, 20);
                    return { inputs, buttons, headings, alerts, visibleText };
                }""")
                content = json.dumps(form_context, ensure_ascii=False)
            except Exception:
                # Fallback to raw HTML if JS extraction fails
                try:
                    content = await page.inner_html('body')
                except Exception:
                    content = await page.content()

            selectors = await get_login_selectors(ai_client, model, content, name=name)

            if not selectors:
                logger.warning(f"[{name}] AI analysis failed after retries — see ERROR above for reason. Aborting login.")
                break

            state = selectors.get('state', 'UNKNOWN')
            logger.info(f"[{name}] Detected State: {state}")

            submit_sel = selectors.get('submit_selector')

            # DOM fallback: if Gemini returns UNKNOWN, query the live DOM directly.
            # This handles cases where complex page structure confuses the AI.
            if state == "UNKNOWN" and actions_taken > 0:
                try:
                    dom_result = await page.evaluate("""() => {
                        function getSelector(el) {
                            if (el.id) return '#' + el.id;
                            if (el.name) return 'input[name="' + el.name + '"]';
                            return 'input[type="' + el.type + '"]';
                        }
                        function isReal(el) {
                            return el.tabIndex >= 0 &&
                                el.getAttribute('aria-hidden') !== 'true' &&
                                !el.disabled &&
                                !el.readOnly;
                        }
                        function isLoginField(el) {
                            if (!isReal(el)) return false;
                            // type=email is always a strong login signal
                            if (el.type === 'email') return true;
                            // autocomplete attribute explicitly marks login fields
                            const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
                            if (/^(email|username|user)$/.test(ac)) return true;
                            // name or id must match common login field names exactly
                            const nm = (el.name || '').toLowerCase();
                            const id = (el.id || '').toLowerCase();
                            if (/^(email|username|user|login|userid|user_id|user-id|account)$/.test(nm)) return true;
                            if (/^(email|username|user|login|userid|user_id|user-id|account)$/.test(id)) return true;
                            // placeholder contains clear login language
                            const ph = (el.placeholder || '').toLowerCase();
                            if (/(e[\\s-]?mail|user[\\s-]?name|log[\\s-]?in)/.test(ph)) return true;
                            return false;
                        }
                        const passEl = Array.from(document.querySelectorAll('input[type="password"]')).find(isReal);
                        const userEl = Array.from(document.querySelectorAll(
                            'input[type="email"], input[type="text"]'
                        )).find(isLoginField);
                        return {
                            password: passEl ? getSelector(passEl) : null,
                            username: userEl ? getSelector(userEl) : null
                        };
                    }""")
                    if dom_result.get('password') and dom_result.get('username'):
                        state = 'BOTH'
                        selectors['state'] = 'BOTH'
                        selectors['username_selector'] = dom_result['username']
                        selectors['password_selector'] = dom_result['password']
                        logger.info(f"[{name}] DOM fallback: BOTH ({dom_result['username']}, {dom_result['password']})")
                    elif dom_result.get('password'):
                        state = 'PASSWORD_ONLY'
                        selectors['state'] = 'PASSWORD_ONLY'
                        selectors['password_selector'] = dom_result['password']
                        logger.info(f"[{name}] DOM fallback: PASSWORD_ONLY ({dom_result['password']})")
                    elif dom_result.get('username'):
                        state = 'USERNAME_ONLY'
                        selectors['state'] = 'USERNAME_ONLY'
                        selectors['username_selector'] = dom_result['username']
                        logger.info(f"[{name}] DOM fallback: USERNAME_ONLY ({dom_result['username']})")
                except Exception as e:
                    logger.debug(f"[{name}] DOM fallback failed: {e}")

            if state != "UNKNOWN":
                consecutive_unknowns = 0

            if state == "UNKNOWN":
                consecutive_unknowns += 1
                if actions_taken == 0:
                    # Before giving up, try clicking the SSO selector if it's visible —
                    # it may be a gateway button that reveals the login form.
                    if sso_selector and not _sso_pre_clicked:
                        try:
                            await page.wait_for_selector(sso_selector, timeout=5000)
                            logger.info(f"[{name}] No login fields yet — clicking SSO selector '{sso_selector}' as pre-login gate.")
                            if capture_traffic:
                                traffic_history.append({"type": "marker", "label": "SSO Pre-Login Gate"})
                            await page.click(sso_selector)
                            _sso_pre_clicked = True
                            await page.wait_for_timeout(3000)
                            await dismiss_popups(page)
                            continue  # re-analyse the page now that the gate was clicked
                        except Exception as _sso_e:
                            logger.warning(f"[{name}] SSO pre-login click failed: {_sso_e}")
                    logger.warning(f"[{name}] No login fields found on initial load.")
                    break
                elif consecutive_unknowns >= 2:
                    login_check = await assess_login_success(page, context, initial_auth_state, actions_taken)
                    if login_check["confidence"] in ("HIGH", "MEDIUM"):
                        logger.info(f"[{name}] No login fields found and authenticated-state confidence is {login_check['confidence']} ({'; '.join(login_check['reasons'][:3])}).")
                    else:
                        logger.warning(f"[{name}] No login fields found, but authenticated-state confidence is LOW ({'; '.join(login_check['reasons'][:3])}). Final validation will decide.")
                    break
                else:
                    logger.info(f"[{name}] Transient UNKNOWN (attempt {consecutive_unknowns}/2) — waiting for page to settle...")
                    await page.wait_for_timeout(2000)
                    continue
                
            elif state == "USERNAME_ONLY":
                user_sel = selectors.get('username_selector')
                if user_sel:
                    if not await _selector_resolves(page, user_sel):
                        logger.warning(f"[{name}] USERNAME_ONLY: selector '{user_sel}' did not resolve — page likely still loading. Retrying analysis...")
                        await page.wait_for_timeout(2000)
                        continue
                    user_fill = await _fill_or_reuse_prefilled(
                        page,
                        user_sel,
                        username,
                        name=name,
                        field_name="Username",
                    )
                    if user_fill["status"] in ("retry", "blocked"):
                        logger.warning(f"[{name}] USERNAME_ONLY: selector '{user_sel}' is not ready for use. Retrying analysis...")
                        await page.wait_for_timeout(2000)
                        continue
                    await _submit_or_enter(page, submit_sel, user_fill.get("enter_fallback_selector"), name=name)
                    actions_taken += 1
                else:
                    logger.warning(f"[{name}] State is USERNAME_ONLY but no selector found.")

            elif state == "PASSWORD_ONLY":
                pass_sel = selectors.get('password_selector')
                if pass_sel:
                    if not await _selector_resolves(page, pass_sel):
                        logger.warning(f"[{name}] PASSWORD_ONLY: selector '{pass_sel}' did not resolve — page likely still loading. Retrying analysis...")
                        await page.wait_for_timeout(2000)
                        continue
                    pass_fill = await _fill_or_reuse_prefilled(
                        page,
                        pass_sel,
                        password,
                        name=name,
                        field_name="Password",
                        allow_prefilled_match=False,
                    )
                    if pass_fill["status"] in ("retry", "blocked"):
                        logger.warning(f"[{name}] PASSWORD_ONLY: selector '{pass_sel}' is not ready for use. Retrying analysis...")
                        await page.wait_for_timeout(2000)
                        continue
                    await _submit_or_enter(page, submit_sel, pass_fill.get("enter_fallback_selector"), name=name)
                    actions_taken += 1
                else:
                    logger.warning(f"[{name}] State is PASSWORD_ONLY but no selector found.")

            elif state == "BOTH":
                user_sel = selectors.get('username_selector')
                pass_sel = selectors.get('password_selector')
                if user_sel and pass_sel:
                    user_ok = await _selector_resolves(page, user_sel)
                    pass_ok = await _selector_resolves(page, pass_sel)
                    if not (user_ok and pass_ok):
                        logger.warning(f"[{name}] BOTH: selector validation failed (user_ok={user_ok}, pass_ok={pass_ok}) — page likely still loading. Retrying analysis...")
                        await page.wait_for_timeout(2000)
                        continue
                    user_fill = await _fill_or_reuse_prefilled(
                        page,
                        user_sel,
                        username,
                        name=name,
                        field_name="Username",
                    )
                    pass_fill = await _fill_or_reuse_prefilled(
                        page,
                        pass_sel,
                        password,
                        name=name,
                        field_name="Password",
                        allow_prefilled_match=False,
                    )
                    if user_fill["status"] in ("retry", "blocked") or pass_fill["status"] in ("retry", "blocked"):
                        logger.warning(
                            f"[{name}] BOTH: selector validation failed "
                            f"(user_status={user_fill['status']}, pass_status={pass_fill['status']}) â€” page likely still loading."
                        )
                        await page.wait_for_timeout(2000)
                        continue
                    fallback_sel = pass_fill.get("enter_fallback_selector") or user_fill.get("enter_fallback_selector")
                    await _submit_or_enter(page, submit_sel, fallback_sel, name=name)
                    actions_taken += 1
                else:
                    logger.warning(f"[{name}] State is BOTH but missing selectors.")

            elif state == "MFA":
                mfa_fields = selectors.get('mfa_fields', [])
                
                # Backwards compatibility / AI fallback
                if not mfa_fields:
                    sel = selectors.get('mfa_selector')
                    lbl = selectors.get('mfa_question') or "Please enter the code"
                    if sel: mfa_fields = [{"selector": sel, "label": lbl}]
                
                if mfa_fields:
                    input_success = True
                    
                    # --- Input Block ---
                    if input_lock:
                        async with input_lock:
                            # Silence other threads temporarily
                            root_logger = logging.getLogger()
                            original_level = root_logger.getEffectiveLevel()
                            root_logger.setLevel(logging.ERROR)
                            
                            try:
                                print(f"\n{'-'*60}")
                                print(f"[!!!] ACTION REQUIRED FOR USER: {name} [!!!]")
                                
                                for field in mfa_fields:
                                    prompt_str = f"Prompt: {field.get('label', 'Enter Value')}\n[{name}] Answer > "
                                    ans = await asyncio.to_thread(input, prompt_str)
                                    field['value'] = ans.strip()
                                    if not field['value']:
                                        print("Warning: Empty answer provided.")
                                        input_success = False
                                        break
                                print(f"{'-'*60}\n")
                            except Exception as e:
                                print(f"Error during input: {e}")
                                input_success = False
                            finally:
                                root_logger.setLevel(original_level)
                    else:
                        # Non-threaded fallback
                        print(f"\n{'-'*60}")
                        print(f"[!!!] ACTION REQUIRED FOR USER: {name} [!!!]")
                        for field in mfa_fields:
                            ans = input(f"Prompt: {field.get('label', 'Enter Value')}\n[{name}] Answer > ")
                            field['value'] = ans.strip()
                            if not field['value']:
                                input_success = False
                                break
                        print(f"{'-'*60}\n")
                    
                    # --- Execution Block ---
                    if input_success:
                        for field in mfa_fields:
                            if 'value' in field:
                                await page.fill(field['selector'], field['value'])
                        
                        if submit_sel:
                            await page.click(submit_sel)
                        elif mfa_fields:
                             await page.press(mfa_fields[0]['selector'], "Enter")
                             
                        actions_taken += 1
                    else:
                        logger.warning(f"[{name}] MFA input aborted or empty.")
                        break
                else:
                    logger.warning(f"[{name}] MFA state detected but no input fields found.")

            elif state == "CAPTCHA":
                # --- CAPTCHA: pause and let the human solve it ---
                await _handle_captcha_block(name, input_lock, [
                    f"[!!!] CAPTCHA DETECTED FOR USER: {name} [!!!]",
                    f"  A CAPTCHA challenge is blocking the login flow.",
                    f"  If the browser is not visible, re-run with --visible.",
                    f"  Please solve the CAPTCHA in the browser window,",
                    f"  then press Enter here to continue...",
                ])
                actions_taken += 1

            elif state == "USERNAME_AND_CAPTCHA":
                # --- Fill username first, then pause for CAPTCHA ---
                user_sel = selectors.get('username_selector')
                captcha_intro = f"  Username '{name}' has been filled automatically."
                if user_sel:
                    user_fill = await _fill_or_reuse_prefilled(
                        page,
                        user_sel,
                        username,
                        name=name,
                        field_name="Username",
                    )
                    if user_fill["status"] in ("retry", "blocked"):
                        logger.warning(f"[{name}] USERNAME_AND_CAPTCHA: selector '{user_sel}' is not ready for use. Retrying analysis...")
                        await page.wait_for_timeout(2000)
                        continue
                    if user_fill["status"] == "prefilled":
                        captcha_intro = f"  Username '{name}' is already present in a locked field."
                        logger.info(f"[{name}] Username already present. Now waiting for CAPTCHA solve...")
                    else:
                        logger.info(f"[{name}] Filled username. Now waiting for CAPTCHA solve...")

                await _handle_captcha_block(name, input_lock, [
                    f"[!!!] CAPTCHA + LOGIN DETECTED FOR USER: {name} [!!!]",
                    captcha_intro,
                    f"  If the browser is not visible, re-run with --visible.",
                    f"  1. Find the browser window/tab for: {name}",
                    f"  2. Solve the CAPTCHA and submit the form in the browser.",
                    f"  3. THEN press Enter here to continue.",
                ])

                # After user confirms, check if the page already moved (user submitted in browser).
                # If not, try clicking submit ourselves.
                _url_after_captcha = page.url
                _page_moved = False
                try:
                    await page.wait_for_url(lambda u: u != _url_after_captcha, timeout=TIMEOUT_MEDIUM)
                    _page_moved = True
                except Exception:
                    pass

                if not _page_moved:
                    # Page hasn't navigated yet — try to submit
                    if submit_sel:
                        try:
                            await page.click(submit_sel, timeout=TIMEOUT_LONG)
                        except Exception:
                            pass
                    elif user_sel:
                        try:
                            await page.press(user_sel, "Enter", timeout=TIMEOUT_LONG)
                        except Exception:
                            pass

                actions_taken += 1

            elif state == "PASSWORD_AND_CAPTCHA":
                # --- Fill password first, then pause for CAPTCHA ---
                pass_sel = selectors.get('password_selector')
                if pass_sel:
                    pass_fill = await _fill_or_reuse_prefilled(
                        page,
                        pass_sel,
                        password,
                        name=name,
                        field_name="Password",
                        allow_prefilled_match=False,
                    )
                    if pass_fill["status"] in ("retry", "blocked"):
                        logger.warning(f"[{name}] PASSWORD_AND_CAPTCHA: selector '{pass_sel}' is not ready for use. Retrying analysis...")
                        await page.wait_for_timeout(2000)
                        continue
                    logger.info(f"[{name}] Filled password. Now waiting for CAPTCHA solve...")

                await _handle_captcha_block(name, input_lock, [
                    f"[!!!] CAPTCHA + PASSWORD DETECTED FOR USER: {name} [!!!]",
                    f"  Password for '{name}' has been filled automatically.",
                    f"  If the browser is not visible, re-run with --visible.",
                    f"  1. Find the browser window/tab for: {name}",
                    f"  2. Solve the CAPTCHA and submit the form in the browser.",
                    f"  3. THEN press Enter here to continue.",
                ])

                # After user confirms, check if page already moved (user submitted in browser).
                _url_after_captcha2 = page.url
                _page_moved2 = False
                try:
                    await page.wait_for_url(lambda u: u != _url_after_captcha2, timeout=TIMEOUT_MEDIUM)
                    _page_moved2 = True
                except Exception:
                    pass

                if not _page_moved2:
                    if submit_sel:
                        try:
                            await page.click(submit_sel, timeout=TIMEOUT_LONG)
                        except Exception:
                            pass
                    elif pass_sel:
                        try:
                            await page.press(pass_sel, "Enter", timeout=TIMEOUT_LONG)
                        except Exception:
                            pass
                actions_taken += 1

            # Wait for navigation/update before next loop iteration
            try:
                await page.wait_for_load_state('domcontentloaded', timeout=5000)
            except Exception: pass

        # 4. Wait for final login completion
        logger.info(f"[{name}] Waiting for final navigation/update...")
        start_url = page.url
        try:
            # Primary check: Wait for URL to change (most reliable login indicator)
            await page.wait_for_url(lambda u: u != start_url, timeout=15000)
            # Wait for the new page to load
            await page.wait_for_load_state('domcontentloaded')
        except Exception:
            pass # Maybe valid (SPA or already on dashboard)

        # Extra safety buffer
        await page.wait_for_timeout(3000)

        # --- SSO / Portal Launch Logic ---
        # Skip if the selector was already used as a pre-login gate (it was the entry point,
        # not a post-login launcher — clicking it again would be wrong).
        if sso_selector and _sso_pre_clicked:
            logger.info(f"[{name}] SSO selector was used as pre-login gate — skipping post-login launch click.")
        elif sso_selector:
            logger.info(f"[{name}] SSO Mode: Looking for launch selector '{sso_selector}'...")
            try:
                # Wait for the launch button (it might be on a portal dashboard)
                await page.wait_for_selector(sso_selector, timeout=10000)
                logger.info(f"[{name}] Found launch button. Clicking...")
                
                # Mark the transition in traffic history
                if capture_traffic:
                    traffic_history.append({"type": "marker", "label": "SSO Launch Phase"})
                
                # Capture current URL to detect navigation
                portal_url = page.url
                
                # Handle new tab or in-place navigation
                try:
                    async with context.expect_page(timeout=5000) as new_page_info:
                        await page.click(sso_selector)
                    
                    # If we get here, a new page opened
                    new_page = await new_page_info.value
                    await new_page.wait_for_load_state('domcontentloaded')
                    page = new_page
                    
                    # Ensure we capture traffic on the new page too
                    if capture_traffic:
                        new_page.on("response", on_response)
                        
                    logger.info(f"[{name}] Switched to new tab/window: {page.url}")
                except Exception:
                    # Timeout means likely in-place navigation or no new tab
                    try:
                        await page.wait_for_url(lambda u: u != portal_url, timeout=15000)
                        logger.info(f"[{name}] Navigated in-place to: {page.url}")
                    except Exception:
                        logger.warning(f"[{name}] URL did not change after SSO click. Continuing anyway.")
                
                await page.wait_for_timeout(5000) # Wait for target app to init
                
            except Exception as e:
                logger.error(f"[{name}] SSO Launch Failed: {e}")
                # Don't abort, try to capture what we have
            
        login_assessment = await assess_login_success(page, context, initial_auth_state, actions_taken)
        reason_summary = "; ".join(login_assessment.get("reasons", [])[:4])
        if login_assessment["confidence"] == "LOW":
            logger.error(f"[{name}] Login did not produce enough authenticated-state evidence (score={login_assessment['score']}: {reason_summary}).")
            return None
        if login_assessment["confidence"] == "MEDIUM":
            logger.warning(f"[{name}] Login confidence MEDIUM (score={login_assessment['score']}: {reason_summary}). Continuing, but results may need review.")
        else:
            logger.info(f"[{name}] Login confidence HIGH (score={login_assessment['score']}: {reason_summary}).")

        # 5. Capture Cookies & Final URL
        cookies = await context.cookies()
        final_url = page.url

        # Identify cookies set by JavaScript (not via Set-Cookie headers).
        # Diff the full browser cookie jar against every set-cookie header we captured.
        header_cookie_names = set()
        for entry in traffic_history:
            sc_val = entry.get('response_headers', {}).get('set-cookie', '')
            for line in sc_val.split('\n'):
                part = line.split(';')[0]
                if '=' in part:
                    header_cookie_names.add(part.split('=')[0].strip())
        js_only_cookies = [c['name'] for c in cookies if c['name'] not in header_cookie_names]
        if js_only_cookies:
            # Attach to the last non-marker traffic entry so it surfaces in the Mermaid node
            for entry in reversed(traffic_history):
                if entry.get('type') != 'marker':
                    entry['js_cookies'] = js_only_cookies
                    break

        # Capture Local/Session Storage (Critical for SPAs like Juice Shop)
        storage_state = await page.evaluate("""() => {
            return {
                localStorage: JSON.stringify(localStorage),
                sessionStorage: JSON.stringify(sessionStorage)
            }
        }""")
        
        if not cookies:
             logger.warning(f"[{name}] No cookies captured after login attempt.")
        
        return {
            "name": name,
            "cookies": cookies,
            "storage": storage_state, # Save storage state
            "headers": {},
            "history": traffic_history,
            "start_url": final_url,
            "auth_confidence": login_assessment["confidence"],
            "auth_confidence_reasons": login_assessment.get("reasons", []),
        }

    except Exception as e:
        logger.error(f"[{name}] Login process failed: {e}")
        return None
    finally:
        await context.close()

def _validate_inputs(args, config):
    """Validate CLI args + config.json upfront. Aborts with a clear message on failure.

    Surfaces problems (bad target URL, unreadable creds files, missing API key for
    AI-dependent features) before any browser launches or crawl work starts.
    """
    errors = []
    warnings = []

    # Target URL
    parsed = urlparse(args.target or "")
    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        errors.append(f"--target must be an http(s) URL (got: {args.target!r}).")
    elif not parsed.netloc:
        errors.append(f"--target is missing a host (got: {args.target!r}).")

    # Roles / logins file presence + parseability
    if args.roles:
        if not os.path.isfile(args.roles):
            errors.append(f"--roles file not found: {args.roles}")
        else:
            try:
                with open(args.roles, 'r', encoding='utf-8') as _f:
                    parsed_roles = json.load(_f)
                if not isinstance(parsed_roles, list) or not parsed_roles:
                    errors.append(f"--roles must be a non-empty JSON list (got {type(parsed_roles).__name__}).")
                else:
                    for i, r in enumerate(parsed_roles):
                        if not isinstance(r, dict) or 'name' not in r:
                            errors.append(f"--roles[{i}] missing required 'name' field.")
                        elif 'cookies' not in r and 'headers' not in r and 'storage' not in r:
                            warnings.append(f"--roles[{i}] '{r.get('name')}' has no cookies/headers/storage — will act as unauthenticated.")
            except json.JSONDecodeError as e:
                errors.append(f"--roles file is not valid JSON: {e}")
            except Exception as e:
                errors.append(f"--roles file unreadable: {e}")

    if args.logins:
        if not os.path.isfile(args.logins):
            errors.append(f"--logins file not found: {args.logins}")
        else:
            try:
                with open(args.logins, 'r', encoding='utf-8') as _f:
                    raw = _f.read()
                cred_count = 0
                try:
                    parsed_logins = json.loads(raw)
                    if not isinstance(parsed_logins, list):
                        raise ValueError("not a list")
                    for i, entry in enumerate(parsed_logins):
                        if not isinstance(entry, dict):
                            errors.append(f"--logins[{i}] must be a JSON object.")
                        elif 'username' not in entry or 'password' not in entry:
                            errors.append(f"--logins[{i}] missing 'username' or 'password'.")
                        else:
                            cred_count += 1
                except (json.JSONDecodeError, ValueError):
                    # plain user:pass text format
                    for line_no, line in enumerate(raw.splitlines(), start=1):
                        s = line.strip()
                        if not s:
                            continue
                        if ':' not in s:
                            errors.append(f"--logins line {line_no} has no ':' separator: {s[:60]!r}")
                        else:
                            cred_count += 1
                if cred_count == 0:
                    errors.append(f"--logins file contains no usable credentials.")
            except Exception as e:
                errors.append(f"--logins file unreadable: {e}")

    # Import-map
    if args.import_map and not os.path.isfile(args.import_map):
        errors.append(f"--import-map file not found: {args.import_map}")
    for import_path in getattr(args, "import_traffic", None) or []:
        if not os.path.isfile(import_path):
            errors.append(f"--import-traffic file not found: {import_path}")

    # Cross-flag dependencies
    needs_logins = args.authn_map or (args.alohomora and not args.roles) or (args.mockingbird and args.authn_map)
    if needs_logins and not args.logins:
        warnings.append("--authn-map / --mockingbird (with authn-map) need --logins to capture login traffic; flowchart will be empty otherwise.")

    if not args.roles and not args.logins and not args.import_map:
        warnings.append("No --roles, --logins, or --import-map provided. Only an Unauthenticated role will be created.")
    if getattr(args, "recon_only", False) and getattr(args, "alohomora", False):
        warnings.append("--recon-only overrides the verification behavior enabled by --alohomora.")

    # AI is required for automated login/auth-flow analysis, unless using --manual-override.
    # Verification can still run without AI; suspicious heuristic hits are reported for manual review.
    needs_ai = bool((args.logins or args.authn_map) and not args.manual_override)
    if needs_ai:
        if not config.get("google_api_key"):
            errors.append("config.json is missing 'google_api_key' but you requested --logins/--authn-map (without --manual-override). Add the key or remove the flag.")
        if not config.get("gemini_model"):
            warnings.append("config.json has no 'gemini_model' set - defaulting to 'gemini-1.5-flash'.")

    if args.test:
        verify_provider = str(config.get("verify_provider", "gemini")).lower().strip()
        if verify_provider == "google":
            verify_provider = "gemini"
        if verify_provider == "claude":
            verify_provider = "anthropic"

        if verify_provider == "openai":
            if not config.get("openai_api_key"):
                if config.get("google_api_key"):
                    warnings.append("verify_provider=openai but openai_api_key is missing; verification will fall back to Gemini.")
                else:
                    warnings.append("verify_provider=openai but openai_api_key is missing; verification will use heuristics and SUSPICIOUS guardrails only.")
        elif verify_provider == "anthropic":
            if not config.get("anthropic_api_key"):
                if config.get("google_api_key"):
                    warnings.append("verify_provider=anthropic but anthropic_api_key is missing; verification will fall back to Gemini.")
                else:
                    warnings.append("verify_provider=anthropic but anthropic_api_key is missing; verification will use heuristics and SUSPICIOUS guardrails only.")
        elif verify_provider not in ("", "gemini"):
            warnings.append(f"Unknown verify_provider={verify_provider!r}; verification will fall back to Gemini if google_api_key exists.")
        elif not config.get("google_api_key"):
            warnings.append("No verifier API key configured; verification will use heuristics only and mark ambiguous access as SUSPICIOUS.")

    # Proxy
    if args.proxy:
        proxy_parsed = urlparse(args.proxy)
        if not proxy_parsed.scheme or not proxy_parsed.netloc:
            errors.append(f"--proxy must be a full URL like http://127.0.0.1:8080 (got: {args.proxy!r}).")

    # Threads sanity
    if args.threads is not None and args.threads < 1:
        errors.append(f"--threads must be >= 1 (got {args.threads}).")
    if args.max_pages is not None and args.max_pages < 0:
        errors.append(f"--max-pages must be >= 0 (got {args.max_pages}).")
    if args.delay is not None and args.delay < 0:
        errors.append(f"--delay must be >= 0 (got {args.delay}).")
    if getattr(args, "crawl_role_timeout", None) is not None and args.crawl_role_timeout < 0:
        errors.append(f"--crawl-role-timeout must be >= 0 (got {args.crawl_role_timeout}).")
    if args.spa_max_clicks is not None and args.spa_max_clicks < 0:
        errors.append(f"--spa-max-clicks must be >= 0 (got {args.spa_max_clicks}).")
    if getattr(args, "recon_max_assets", 1) < 1:
        errors.append(f"--recon-max-assets must be >= 1 (got {args.recon_max_assets}).")
    if getattr(args, "recon_max_mb", 1) < 1:
        errors.append(f"--recon-max-mb must be >= 1 (got {args.recon_max_mb}).")
    if getattr(args, "allow_risky_recon_actions", False):
        warnings.append("--allow-risky-recon-actions can trigger application state changes; use only in a controlled environment.")
    if getattr(args, "recon_validation_limit", 1) < 1:
        errors.append(f"--recon-validation-limit must be >= 1 (got {args.recon_validation_limit}).")
    if getattr(args, "validate_static_get", False):
        warnings.append("--validate-static-get performs active requests; HTTP GET semantics do not guarantee a side-effect-free endpoint.")
    if getattr(args, "verify_ai_concurrency", None) is not None and args.verify_ai_concurrency < 1:
        errors.append(f"--verify-ai-concurrency must be >= 1 (got {args.verify_ai_concurrency}).")
    if getattr(args, "verify_ai_delay_ms", None) is not None and args.verify_ai_delay_ms < 0:
        errors.append(f"--verify-ai-delay-ms must be >= 0 (got {args.verify_ai_delay_ms}).")

    for w in warnings:
        logger.warning(f"[input check] {w}")
    if errors:
        for e in errors:
            logger.error(f"[input check] {e}")
        logger.error("Input validation failed. Exiting before any work is performed.")
        sys.exit(1)


async def main():
    parser = argparse.ArgumentParser(description="SkeletonKey Browser: Browser-Based Authorization Mapper")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--roles", help="Path to JSON roles file (with pre-filled cookies)")
    parser.add_argument("--logins", help="Path to JSON logins file or user:pass text file (for automated login)")
    parser.add_argument("--name", required=True, help="Project Name (used for output files: name.xlsx, name.json)")
    parser.add_argument("--ignore", help="Ignore patterns (comma-separated)")
    parser.add_argument("--max-pages", type=int, default=0, help="Max pages to crawl per role (0 for no limit)")
    parser.add_argument("--threads", type=int, default=3, help="Number of concurrent roles to crawl (default: 3)")
    parser.add_argument("--delay", type=int, default=5000, help="Delay in ms to wait for page load (SPA handling, default: 5000)")
    parser.add_argument("--crawl-role-timeout", type=int, default=0, help="Max seconds to crawl one role before continuing (0 disables, default: 0)")
    parser.add_argument("--authn-map", action="store_true", help="Generate a Mermaid.js flowchart of the authentication flow (requires --logins)")
    parser.add_argument("--import-map", help="Path to existing .xlsx/.csv map to skip crawling")
    parser.add_argument("--alohomora", action="store_true", help="Enable all features: crawl, test, and authn-map (if using --logins)")
    parser.add_argument("--mockingbird", action="store_true", help="Crawl, build authn-map (if using --logins), and take screenshots — no vulnerability testing")
    parser.add_argument("--recon-only", action="store_true", help="Run endpoint and coverage reconnaissance only; do not run vulnerability verification")
    
    # Headless toggle
    parser.add_argument("--visible", action="store_true", help="Run browser in visible mode (not headless)")

    # Manual login override
    parser.add_argument("--manual-override", action="store_true", help="Bypass AI-driven login; open browser for manual login completion")

    # Verification Mode
    parser.add_argument("--test", action="store_true", help="Run verification: check if roles can access endpoints they didn't discover")
    parser.add_argument("--verify-provider", choices=["gemini", "openai", "anthropic"], help="LLM provider for vulnerability verification (overrides config.json)")
    parser.add_argument("--verify-model", help="LLM model for vulnerability verification (overrides provider-specific config)")
    parser.add_argument("--verify-ai-concurrency", type=int, help="Max concurrent verifier LLM calls (overrides config.json)")
    parser.add_argument("--verify-ai-delay-ms", type=int, help="Minimum delay between verifier LLM calls in milliseconds (overrides config.json)")
    
    # Crawler Tweaks
    parser.add_argument("--follow-redirects", action="store_true", help="Follow external redirects during crawl")
    parser.add_argument("--sso", help="SSO/Portal Mode: CSS selector to click after login to launch the target app (e.g., 'text=Launch')")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--debug", action="store_true", help="Write DEBUG-level logs to <name>/<name>_DEBUG.log")
    parser.add_argument("--spa-max-clicks", type=int, default=0, help="Max click interactions per page for SPA/JS-heavy apps (0 = unlimited with --spa; adaptive mode defaults to 45)")
    parser.add_argument("--password", help="Password for pages that prompt on each visit "
                        "(handles HTTP Basic Auth and HTML password overlays).")
    parser.add_argument("--username", default="", help="Username to pair with --password "
                        "(required for HTTP Basic Auth; optional for single-password HTML gates).")
    parser.add_argument("--ss", action="store_true", help="Take a screenshot of each crawled page (saved to <name>/screenshots/<role>/)")
    parser.add_argument("--spa", action="store_true", help="Force SPA discovery; adaptive JS/SPA detection runs without this flag")
    parser.add_argument("--reasoning", action="store_true", help="Log AI reasoning for SAFE verdicts during verification (useful for prompt debugging)")
    parser.add_argument("--no-static-js-recon", action="store_true", help="Disable passive first-party JavaScript/chunk endpoint discovery")
    parser.add_argument("--no-js-template-resolution", action="store_true", help="Disable passive JavaScript template/constant-map reconstruction")
    parser.add_argument("--recon-max-assets", type=int, default=150, help="Maximum additional JS chunks/source maps fetched per role (default: 150)")
    parser.add_argument("--recon-max-mb", type=int, default=50, help="Maximum total retained JS/source-map data per role in MiB (default: 50)")
    parser.add_argument("--allow-risky-recon-actions", action="store_true", help="Allow AI-approved risky controls and synthetic batch clicks; unsafe and disabled by default")
    parser.add_argument("--validate-static-get", action="store_true", help="Actively request read-like static GET/HEAD candidates; disabled by default")
    parser.add_argument("--recon-validation-limit", type=int, default=100, help="Maximum static GET/HEAD candidates validated per role (default: 100)")
    parser.add_argument("--import-traffic", action="append", help="Import recon evidence from HAR, Burp XML, SkeletonLock traffic JSON, or a METHOD/URL text file; repeatable")

    args = parser.parse_args()

    # Master toggle logic
    if args.alohomora:
        args.test = True
        if args.logins:
            args.authn_map = True

    if args.mockingbird:
        args.ss = True
        if args.logins:
            args.authn_map = True

    if args.recon_only:
        args.test = False
        args.authn_map = False

    if os.environ.get("SK_DISABLE_SCREENSHOTS", "").lower() in {"1", "true", "yes", "on"}:
        args.ss = False

    # Define output directory and paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    projects_dir = os.path.join(script_dir, "Projects")
    output_dir = os.path.join(projects_dir, args.name)
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            logger.info(f"Created output directory: {output_dir}")
        except OSError as e:
            logger.error(f"Failed to create output directory {output_dir}: {e}")
            sys.exit(1)

    output_xlsx = os.path.join(output_dir, f"{args.name}.xlsx")
    output_json = os.path.join(output_dir, f"{args.name}.json")
    output_recon_json = os.path.join(output_dir, f"{args.name}_recon.json")

    # Debug file handler — activated by --debug flag
    if args.debug:
        debug_log_path = os.path.join(output_dir, f"{args.name}_DEBUG.log")
        _fh = logging.FileHandler(debug_log_path, mode='w', encoding='utf-8')
        _fh.setLevel(logging.DEBUG)
        _fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(_fh)
        logging.getLogger().setLevel(logging.DEBUG)
        logger.info(f"Debug logging enabled → {debug_log_path}")

    # Reasoning log file — activated by --reasoning flag
    reasoning_log_path = None
    if args.reasoning:
        reasoning_log_path = os.path.join(output_dir, f"{args.name}_reasoning.log")
        logger.info(f"Reasoning log enabled → {reasoning_log_path}")

    # Load config first to get API key
    try:
        with open('config.json', 'r', encoding='utf-8') as f:
            config = json.load(f)
    except Exception: config = {}

    if args.verify_provider:
        config["verify_provider"] = args.verify_provider
    if args.verify_model:
        provider = str(config.get("verify_provider", "gemini")).lower().strip()
        if provider == "openai":
            config["openai_verify_model"] = args.verify_model
        elif provider in ("anthropic", "claude"):
            config["anthropic_verify_model"] = args.verify_model
        else:
            config["gemini_verify_model"] = args.verify_model
    if args.verify_ai_concurrency is not None:
        config["verify_ai_concurrency"] = args.verify_ai_concurrency
    if args.verify_ai_delay_ms is not None:
        config["verify_ai_delay_ms"] = args.verify_ai_delay_ms

    # Fail fast on bad CLI args / unreadable creds / missing API key for AI features.
    _validate_inputs(args, config)

    # Initialize ignore patterns early
    ignore_patterns = config.get('default_ignore_patterns', [])
    blacklist_patterns = config.get('blacklist_patterns', [])
    
    if args.ignore:
        ignore_patterns.extend([p.strip() for p in args.ignore.split(',')])

    roles = []

    # 1. Load Pre-defined Roles
    if args.roles:
        try:
            with open(args.roles, 'r', encoding='utf-8') as f:
                roles.extend(json.load(f))
        except Exception as e:
            logger.error(f"Failed to load roles from {args.roles}: {e}")

    # 2. Perform Automated Logins
    captured_workflows = {}

    if args.logins:
        try:
            with open(args.logins, 'r', encoding='utf-8') as f:
                raw = f.read()

            credentials = []  # list of dicts: {username, password, target?, sso?}
            try:
                parsed_json = json.loads(raw)
                if isinstance(parsed_json, list):
                    for entry in parsed_json:
                        if isinstance(entry, dict) and 'username' in entry and 'password' in entry:
                            credentials.append(entry)
                    logger.info("Loaded logins from JSON format.")
                else:
                    raise ValueError("Not a list")
            except (json.JSONDecodeError, ValueError):
                # Fall back to plain username:password text format
                for line in raw.splitlines():
                    if ':' in line.strip():
                        parts = line.strip().split(':', 1)
                        credentials.append({"username": parts[0], "password": parts[1]})
            
            if credentials:
                login_mode = "manual override" if args.manual_override else "AI-driven"
                logger.info(f"Loaded {len(credentials)} credentials. Attempting {login_mode} logins...")

                # Init AI (only needed if not using manual override)
                ai_client = None
                if not args.manual_override and config.get("google_api_key") and genai:
                    try:
                        ai_client = genai.Client(api_key=config["google_api_key"])
                    except Exception: pass

                async with async_playwright() as p:
                    # Launch browser for logins
                    login_args = ["--disable-blink-features=AutomationControlled"]
                    if not args.proxy:
                        login_args.append("--no-proxy-server")

                    cdp_url = os.environ.get("SK_CDP_URL")
                    if cdp_url:
                        logger.info(f"Attaching to existing Chrome over CDP: {cdp_url}")
                        browser = await p.chromium.connect_over_cdp(cdp_url)
                    else:
                        # For manual override, always show browser during login
                        login_headless = not (args.visible or args.manual_override)
                        browser = await p.chromium.launch(
                            headless=login_headless,
                            channel="chrome" if (args.visible or args.manual_override) else None,
                            args=login_args,
                            proxy={"server": args.proxy} if args.proxy else None
                        )

                    # Lock for console input (MFA)
                    input_lock = asyncio.Lock()

                    # Concurrency control for logins
                    login_sem = asyncio.Semaphore(args.threads)

                    async def login_worker(cred):
                        async with login_sem:
                            if args.manual_override:
                                return await perform_manual_login(
                                    browser,
                                    cred.get("target") or args.target,
                                    cred["username"],
                                    input_lock=input_lock,
                                    sso_selector=cred.get("sso") or args.sso
                                )
                            else:
                                return await perform_login(
                                    browser,
                                    cred.get("target") or args.target,
                                    cred["username"],
                                    cred["password"],
                                    ai_client,
                                    config.get("gemini_model", "gemini-1.5-flash"),
                                    capture_traffic=args.authn_map,
                                    input_lock=input_lock,
                                    sso_selector=cred.get("sso") or args.sso
                                )

                    logger.info(f"Starting parallel logins with {args.threads} threads...")
                    login_tasks = [login_worker(cred) for cred in credentials]
                    results = await asyncio.gather(*login_tasks)

                    for cred, role in zip(credentials, results):
                        if role:
                            # Stash credentials on the role so the verification phase can
                            # re-authenticate if the captured session expires server-side.
                            role['_login'] = {
                                'username': cred['username'],
                                'password': cred['password'],
                                'target': cred.get('target') or args.target,
                                'sso': cred.get('sso') or args.sso,
                            }
                            roles.append(role)
                            if args.authn_map and 'history' in role:
                                captured_workflows[role['name']] = role['history']
                            logger.info(f"Successfully logged in as: {role['name']}")
                        # Errors are logged inside perform_login
                    
                    if not cdp_url:
                        await browser.close()

        except Exception as e:
            logger.error(f"Failed to process logins from {args.logins}: {e}")

    _authn_ai_tasks = {}  # role_name → asyncio.Task for filter_traffic_with_ai

    if args.authn_map and captured_workflows:
        logger.info("Generating Authentication Flowchart...")
        
        # 1. Generate and save the ORIGINAL (Full) Flowchart
        try:
            mermaid_code_raw = MermaidGenerator.generate_flowchart(captured_workflows, custom_ignore_patterns=ignore_patterns)

            _panzoom_head = """
                <script src="https://cdn.jsdelivr.net/npm/svg-pan-zoom/dist/svg-pan-zoom.min.js"></script>
                <script>
                (function() {
                    function initPanZoom() {
                        var svg = document.querySelector('.mermaid svg');
                        if (!svg) { setTimeout(initPanZoom, 200); return; }
                        if (typeof svgPanZoom === 'undefined') { setTimeout(initPanZoom, 200); return; }
                        svg.removeAttribute('width');
                        svg.removeAttribute('height');
                        svg.style.width  = '100%';
                        svg.style.height = '100%';
                        svgPanZoom(svg, {
                            zoomEnabled: true,
                            controlIconsEnabled: true,
                            fit: true,
                            center: true,
                            minZoom: 0.05,
                            maxZoom: 20,
                            zoomScaleSensitivity: 0.4
                        });
                    }
                    window.addEventListener('load', function() { setTimeout(initPanZoom, 300); });
                    if (document.readyState === 'complete') { setTimeout(initPanZoom, 300); }
                })();
                </script>"""

            html_content_raw = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Authentication Map (RAW) - {args.name}</title>
                <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
                <script>mermaid.initialize({{startOnLoad:true, maxEdges:2000, maxNodes:2000, maxTextSize:500000, flowchart:{{maxEdges:2000, htmlLabels:true}}}});</script>
                {_panzoom_head}
                <style>
                    body {{ font-family: sans-serif; padding: 20px; }}
                    h1 {{ margin-bottom: 20px; }}
                    .mermaid {{ width: 100%; height: 85vh; overflow: hidden; border: 1px solid #ddd; border-radius: 6px; }}
                </style>
            </head>
            <body>
                <h1>Authentication Flow (RAW) - {args.name}</h1>
                <div class="mermaid">
                {mermaid_code_raw}
                </div>
            </body>
            </html>
            """
            raw_map_file = os.path.join(output_dir, f"{args.name}_auth_map.html")
            with open(raw_map_file, "w", encoding="utf-8") as f:
                f.write(html_content_raw)
            logger.info(f"Raw Auth Map saved to: {raw_map_file}")
        except Exception as e:
            logger.error(f"Failed to generate Raw Auth Map: {e}")

        # 2. Start AI filtering as background tasks — run concurrently with the crawl.
        #    Results are collected and the CLEAN map is written after the crawl finishes.
        if ai_client:
            logger.info("AI auth map refinement started in background (runs concurrently with crawl)...")
            for role_name, history in captured_workflows.items():
                _authn_ai_tasks[role_name] = asyncio.create_task(
                    filter_traffic_with_ai(
                        ai_client,
                        config.get("gemini_model", "gemini-1.5-flash"),
                        history
                    )
                )

    # 3. Add Default 'Unauthenticated' Role
    skip_unauthenticated_role = os.environ.get("SK_SKIP_UNAUTHENTICATED_ROLE", "").lower() in {
        "1", "true", "yes", "on"
    }
    if skip_unauthenticated_role:
        logger.info("Skipping default 'Unauthenticated' role by environment request.")
    elif not any(r.get('name') == 'Unauthenticated' for r in roles):
        logger.info("Adding default 'Unauthenticated' role.")
        roles.append({
            'name': 'Unauthenticated',
            'cookies': [],
            'headers': {}
        })

    if not roles:
        logger.error("No roles defined (via --roles or --logins). Exiting.")
        sys.exit(1)

    # Initialize AI (Optional)
    ai_client = None
    prompts = load_prompts()
    auth_prompt = prompts.get("AUTH_ANALYSIS_PROMPT", "")
    
    if config.get("google_api_key") and genai:
        try:
            ai_client = genai.Client(api_key=config["google_api_key"])
            logger.info("Gemini AI Client initialized.")
        except Exception as e:
            logger.warning(f"Failed to initialize AI: {e}")
    verify_client = build_verify_client(config, ai_client)
    if isinstance(verify_client, dict):
        logger.info(f"Verifier AI provider: {verify_client['provider']} ({verify_model_name(config)})")
    elif verify_client:
        logger.info(f"Verifier AI provider: gemini ({verify_model_name(config)})")

    role_findings = {}
    all_endpoints = set()
    role_ui_elements = {} # {role_name: set("Button: Admin", "Link: Settings")}
    all_api_calls_by_role = {}
    all_recon_by_role = {}
    role_responses = {}  # {role_name: {endpoint_path: (status, body, final_url, req_str, resp_str)}}

    if args.import_map:
        logger.info(f"Importing existing map from {args.import_map}...")
        all_endpoints, role_findings = load_existing_map(args.import_map)
        logger.info(f"Imported {len(all_endpoints)} unique endpoints.")
        
        # Validate roles
        active_role_names = [r['name'] for r in roles]
        map_role_names = list(role_findings.keys())
        
        missing_in_map = [r for r in active_role_names if r not in map_role_names]
        missing_in_session = [r for r in map_role_names if r not in active_role_names]
        
        if missing_in_map:
            logger.warning(f"Active roles missing in map: {missing_in_map} (Will crawl if not careful, but crawl is skipped!)")
        if missing_in_session:
            logger.warning(f"Map contains roles with no active session: {missing_in_session} (Cannot verify findings for these)")

    else:
        # CRAWL PHASE
        async with async_playwright() as p:
            crawl_tasks = []
            # Limit concurrent browser instances to args.threads
            crawl_sem = asyncio.Semaphore(args.threads)
            
            all_traffic = [] if args.mockingbird else None

            for role in roles:
                # Create a task for each role
                # For manual override: crawl in headless mode. Otherwise respect --visible
                crawl_headless = True if args.manual_override else not args.visible
                # Use post-login URL as start if available, else target
                start_url = role.get("start_url", args.target)

                role_ss_dir = None
                if args.ss:
                    role_ss_dir = os.path.join(output_dir, "screenshots", role['name'])
                    os.makedirs(role_ss_dir, exist_ok=True)
                task = crawl_role_with_timeout(
                    args.crawl_role_timeout, p, role, start_url, args.max_pages,
                    ignore_patterns, crawl_headless, crawl_sem, args.delay,
                    args.follow_redirects, args.spa, role_ui_elements,
                    proxy=args.proxy, blacklist=blacklist_patterns,
                    ai_client=ai_client,
                    ai_model=config.get("gemini_model", "gemini-1.5-flash"),
                    spa_max_clicks=args.spa_max_clicks,
                    api_harvest_mode=True,
                    page_username=args.username,
                    page_password=args.password,
                    screenshot_dir=role_ss_dir,
                    traffic_log=all_traffic,
                    static_js_recon=not args.no_static_js_recon,
                    js_template_resolution=not args.no_js_template_resolution,
                    recon_max_assets=args.recon_max_assets,
                    recon_max_bytes=args.recon_max_mb * 1024 * 1024,
                    allow_risky_recon_actions=args.allow_risky_recon_actions,
                    validate_static_get=args.validate_static_get,
                    recon_validation_limit=args.recon_validation_limit,
                )
                crawl_tasks.append(task)

            if crawl_tasks:
                logger.info(f"Starting concurrent crawl for {len(crawl_tasks)} roles (Threads: {args.threads})...")
                results = await asyncio.gather(*crawl_tasks, return_exceptions=True)

                # Collect API calls from all roles for harvest mode
                all_api_calls_by_role = {}

                # Process results — crawl_role now returns (endpoints, api_calls, endpoint_responses)
                for i, result in enumerate(results):
                    role_name = roles[i]['name']
                    if isinstance(result, BaseException):
                        logger.error(
                            f"[{role_name}] Crawl task failed; continuing with other roles: {result}",
                            exc_info=(type(result), result, result.__traceback__)
                        )
                        role_findings[role_name] = set()
                        all_api_calls_by_role[role_name] = []
                        role_responses[role_name] = {}
                        all_recon_by_role[role_name] = ReconInventory(role=role_name)
                        continue
                    if not result:
                        logger.error(f"[{role_name}] Crawl task returned no result; continuing with other roles.")
                        role_findings[role_name] = set()
                        all_api_calls_by_role[role_name] = []
                        role_responses[role_name] = {}
                        all_recon_by_role[role_name] = ReconInventory(role=role_name)
                        continue
                    endpoints, api_calls, endpoint_resp_cache, recon_inventory = result
                    role_findings[role_name] = set(endpoints)
                    all_endpoints.update(endpoints)
                    all_api_calls_by_role[role_name] = api_calls
                    role_responses[role_name] = endpoint_resp_cache or {}
                    all_recon_by_role[role_name] = recon_inventory or ReconInventory(role=role_name)
                    logger.info(f"[{role_name}] Crawl finished. Found {len(endpoints)} endpoints, {len(api_calls)} API calls, {len(endpoint_resp_cache or {})} cached baselines.")

                if all_traffic is not None:
                    traffic_path = os.path.join(output_dir, f"{args.name}_traffic.json")
                    try:
                        scanner_asset_urls = set()
                        for inventory in all_recon_by_role.values():
                            scanner_asset_urls.update(inventory.assets_fetched_by_scanner)
                        for traffic_entry in all_traffic:
                            if traffic_entry.get("url") in scanner_asset_urls:
                                traffic_entry["tags"] = sorted(set((traffic_entry.get("tags") or []) + ["scanner-generated", "passive-asset"]))
                        with open(traffic_path, 'w', encoding='utf-8') as _tf:
                            json.dump(all_traffic, _tf, indent=2)
                        logger.info(f"Traffic log saved: {traffic_path} ({len(all_traffic)} requests)")
                    except Exception as _te:
                        logger.error(f"Failed to write traffic log: {_te}")

    for import_path in args.import_traffic or []:
        try:
            import_name = f"Imported:{os.path.basename(import_path)}"
            all_recon_by_role[import_name] = load_recon_import(import_path, role=import_name)
            logger.info(f"Imported {len(all_recon_by_role[import_name].candidates)} recon candidates from {import_path}")
        except Exception as import_error:
            logger.error(f"Failed to import recon evidence from {import_path}: {import_error}")

    if all_recon_by_role:
        try:
            previous_recon = None
            if os.path.isfile(output_recon_json):
                try:
                    with open(output_recon_json, "r", encoding="utf-8") as previous_file:
                        previous_recon = json.load(previous_file)
                except Exception:
                    previous_recon = None
            combined_recon = ReconInventory(role="ALL")
            for inventory in all_recon_by_role.values():
                combined_recon.merge(inventory)
            recon_payload = {
                "generated_at": datetime.now().astimezone().isoformat(),
                "target": redact_url(args.target),
                "roles": {name: inventory.to_dict() for name, inventory in sorted(all_recon_by_role.items())},
                "combined": combined_recon.to_dict(),
            }
            if isinstance(previous_recon, dict):
                previous_candidates = previous_recon.get("combined", {}).get("candidates", [])
                current_candidates = recon_payload["combined"]["candidates"]
                def _candidate_key(item):
                    return f"{item.get('method') or 'UNKNOWN'} {item.get('canonical_path')} [{item.get('source')}]"
                previous_keys = {_candidate_key(item) for item in previous_candidates if isinstance(item, dict)}
                current_keys = {_candidate_key(item) for item in current_candidates if isinstance(item, dict)}
                recon_payload["diff_from_previous"] = {
                    "added": sorted(current_keys - previous_keys),
                    "removed": sorted(previous_keys - current_keys),
                    "unchanged": len(current_keys & previous_keys),
                }
            recon_payload = redact_structure(recon_payload)
            with open(output_recon_json, "w", encoding="utf-8") as recon_file:
                json.dump(recon_payload, recon_file, indent=2)
            logger.info(f"Recon evidence saved: {output_recon_json} ({len(combined_recon.candidates)} candidates)")
        except Exception as recon_error:
            logger.error(f"Failed to write recon evidence: {recon_error}")

    # Collect AI-refined auth map results and write CLEAN flowchart.
    # The tasks were started before the crawl; by now they are likely already done.
    if _authn_ai_tasks:
        logger.info("Collecting AI auth map results...")
        cleaned_workflows = {}
        for role_name, task in _authn_ai_tasks.items():
            try:
                cleaned_workflows[role_name] = await task
            except Exception as e:
                logger.error(f"AI auth map filtering failed for {role_name}: {e}")

        if cleaned_workflows:
            try:
                mermaid_code_clean = MermaidGenerator.generate_flowchart(cleaned_workflows, custom_ignore_patterns=ignore_patterns)
                html_content_clean = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Authentication Map (CLEAN) - {args.name}</title>
                    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
                    <script>mermaid.initialize({{startOnLoad:true, maxEdges:2000, maxNodes:2000, maxTextSize:500000, flowchart:{{maxEdges:2000, htmlLabels:true}}}});</script>
                    {_panzoom_head}
                    <style>
                        body {{ font-family: sans-serif; padding: 20px; }}
                        h1 {{ margin-bottom: 20px; }}
                        .mermaid {{ width: 100%; height: 85vh; overflow: hidden; border: 1px solid #ddd; border-radius: 6px; }}
                    </style>
                </head>
                <body>
                    <h1>Authentication Flow (CLEAN) - {args.name}</h1>
                    <div class="mermaid">
                    {mermaid_code_clean}
                    </div>
                </body>
                </html>
                """
                clean_map_file = os.path.join(output_dir, f"{args.name}_auth_map_CLEAN.html")
                with open(clean_map_file, "w", encoding="utf-8") as f:
                    f.write(html_content_clean)
                logger.info(f"Clean Auth Map saved to: {clean_map_file}")
            except Exception as e:
                logger.error(f"Failed to generate Clean Auth Map: {e}")

    # Verification Mode (Optional)
    results = {
        'safe': set(),
        'suspicious': set(),
        'suspicious_detail': [],
        'vuln': []
    }

    if args.test:
        logger.info("Starting verification phase (Heuristic + LLM Analysis)...")
        # Use at least 8 threads for verification, or more if requested
        verify_threads = max(8, args.threads)
        logger.info(f"Concurrency Limit: {verify_threads}")

        sem = asyncio.Semaphore(verify_threads)
        # Separate cap for AI calls — Pro model rate-limits under high concurrency,
        # causing random UNKNOWN verdicts that make results non-deterministic.
        verify_ai_limit = verifier_ai_concurrency(config, verify_client)
        verify_ai_delay = verifier_ai_delay_ms(config, verify_client)
        logger.info(f"Verifier AI throttle: concurrency={verify_ai_limit}, delay_ms={verify_ai_delay}")
        ai_sem = asyncio.Semaphore(verify_ai_limit)
        ai_spacer = AsyncRequestSpacer(verify_ai_delay)
        tasks = []
        
        # Reuse the same browser args as the crawler for consistency
        browser_args = [
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-accelerated-2d-canvas",
            "--no-first-run",
            "--no-zygote",
            "--disable-gpu",
            "--hide-scrollbars",
            "--mute-audio",
            "--window-size=1920,1080"
        ]
        
        if not args.proxy:
            browser_args.append("--no-proxy-server")

        async with async_playwright() as p:
            # Launch a persistent browser for verification workers
            verification_browser = await p.chromium.launch(
                headless=not args.visible,
                channel="chrome" if args.visible else None,
                args=browser_args,
                proxy={"server": args.proxy} if args.proxy else None
            )

            # Pre-create one persistent context per role. Workers borrow these via
            # shared_context so we don't pay browser.new_context() / context.close()
            # on every fetch — and Set-Cookie rotations propagate across calls
            # within the same context naturally.
            role_sessions = {}
            try:
                for r in roles:
                    sess = RoleSession(verification_browser, r, args.target,
                                       page_username=args.username, page_password=args.password)
                    try:
                        await sess.init()
                        role_sessions[r['name']] = sess
                        logger.debug(f"Verify session initialized for role '{r['name']}'.")
                    except Exception as _se:
                        logger.warning(f"Could not initialize verify session for '{r['name']}': {_se}. Falling back to per-call contexts for this role.")

                for endpoint in all_endpoints:
                    # Skip ignored patterns during verification
                    if should_ignore(endpoint, ignore_patterns):
                        logger.debug(f"Skipping verification for ignored endpoint: {endpoint}")
                        continue

                    # 1. Identify a baseline role (one that successfully discovered the endpoint)
                    baseline_role = None
                    for r in roles:
                        if endpoint in role_findings.get(r['name'], set()):
                            baseline_role = r
                            break

                    if not baseline_role:
                        continue

                    # Look up the cached baseline response captured during the crawl.
                    # If the baseline role actually visited this endpoint, we reuse that
                    # response and avoid the racy concurrent re-fetch entirely.
                    cached = role_responses.get(baseline_role['name'], {}).get(endpoint)

                    baseline_sess = role_sessions.get(baseline_role['name'])

                    for role in roles:
                        role_name = role['name']
                        if endpoint not in role_findings.get(role_name, set()):
                            test_sess = role_sessions.get(role_name)
                            tasks.append(verify_endpoint_worker(
                                sem, verification_browser, args.target, endpoint, baseline_role, role,
                                ai_client, config, auth_prompt, results,
                                page_username=args.username, page_password=args.password,
                                all_role_names=[r['name'] for r in roles],
                                reasoning_log=reasoning_log_path,
                                ai_sem=ai_sem,
                                ai_spacer=ai_spacer,
                                cached_baseline=cached,
                                ai_model=config.get("gemini_model", "gemini-1.5-flash"),
                                baseline_session=baseline_sess,
                                test_session=test_sess,
                                verify_client=verify_client,
                            ))

                logger.info(f"Verification: {len(tasks)} endpoint/role combinations queued for testing.")
                if tasks:
                    await asyncio.gather(*tasks)
            finally:
                # Always tear down the per-role contexts before closing the browser
                for sess in role_sessions.values():
                    try:
                        await sess.close()
                    except Exception:
                        pass

            await verification_browser.close()

            # --- API Call Verification ---
            if all_api_calls_by_role and any(all_api_calls_by_role.values()):
                logger.info("Starting API call verification phase...")
                api_tasks = []

                # Build a deduplicated map: (method, path) -> (baseline_role, ApiCall)
                api_baseline_map = {}  # (method, path) -> (role, ApiCall)
                for rname, calls in all_api_calls_by_role.items():
                    baseline_role_obj = next((r for r in roles if r['name'] == rname), None)
                    if not baseline_role_obj:
                        continue
                    for call in calls:
                        key = (call.method, call.path)
                        if key not in api_baseline_map:
                            api_baseline_map[key] = (baseline_role_obj, call)

                for (method, path), (baseline_role_obj, call) in api_baseline_map.items():
                    for role in roles:
                        if role['name'] == baseline_role_obj['name']:
                            continue  # skip same role
                        api_tasks.append(verify_api_call_worker(
                            sem, args.target, call, baseline_role_obj, role,
                            verify_client, config, auth_prompt, results,
                            all_role_names=[r['name'] for r in roles],
                            ai_sem=ai_sem,
                            ai_spacer=ai_spacer,
                        ))

                if api_tasks:
                    logger.info(f"Replaying {len(api_tasks)} API call/role combinations...")
                    await asyncio.gather(*api_tasks)
                    logger.info("API call verification complete.")

            logger.info(f"Verification complete. Found {len(results['vuln'])} confirmed vulnerabilities.")

    # Generate Output
    endpoints = sorted(list(all_endpoints))
    if "/" not in endpoints: endpoints.insert(0, "/")

    role_names = [r['name'] for r in roles]

    if args.name:
        # 1. Generate Excel Report
        if not openpyxl:
            logger.error("Error: 'openpyxl' module not found. Please run: pip install openpyxl")
        else:
            try:
                wb = openpyxl.Workbook()
                ws = wb.active
                ws.title = "Authorization Map"
                
                # Headers
                headers = ["Endpoint"] + role_names
                ws.append(headers)
                
                # Styling
                green_fill = PatternFill(start_color="90EE90", end_color="90EE90", fill_type="solid")
                orange_fill = PatternFill(start_color="FFA500", end_color="FFA500", fill_type="solid")
                red_fill = PatternFill(start_color="FF0000", end_color="FF0000", fill_type="solid")
                thin_border = Border(left=Side(style='thin'), right=Side(style='thin'), top=Side(style='thin'), bottom=Side(style='thin'))
                
                current_row = 2
                count = 0
                
                verified_vuln_set = {(item['endpoint'], item['role']) for item in results['vuln']}
                
                for endpoint in endpoints:
                    has_any_visibility = False
                    
                    if args.test and endpoint in all_endpoints:
                         has_any_visibility = True
                    else:
                        for role_name in role_names:
                            if endpoint in role_findings.get(role_name, set()):
                                has_any_visibility = True
                                break
                    
                    if has_any_visibility:
                        cell_ep = ws.cell(row=current_row, column=1, value=endpoint)
                        cell_ep.border = thin_border
                        
                        for c_idx, role_name in enumerate(role_names, start=2):
                            cell_val = ''
                            cell_fill = None
                            
                            if endpoint in role_findings.get(role_name, set()):
                                cell_val = 'X'
                                cell_fill = green_fill
                            elif args.test:
                                if should_ignore(endpoint, ignore_patterns):
                                    cell_val = 'MANUAL CHECK'
                                    cell_fill = orange_fill
                                elif (endpoint, role_name) in verified_vuln_set:
                                    cell_val = 'VULNERABLE'
                                    cell_fill = red_fill
                                elif (endpoint, role_name) in results['suspicious']:
                                    cell_val = 'SUSPICIOUS'
                                    cell_fill = orange_fill
                                else:
                                    cell_val = '' 
                                    cell_fill = green_fill
                            else:
                                cell_val = ''
                                cell_fill = orange_fill
                            
                            cell = ws.cell(row=current_row, column=c_idx, value=cell_val)
                            if cell_fill: cell.fill = cell_fill
                            cell.border = thin_border
                        
                        current_row += 1
                        count += 1
                
                wb.save(output_xlsx)
                logger.info(f"Excel Report saved to: {output_xlsx} ({count} rows)")
                
                # --- UI Element Comparison Sheet (SPA Mode only) ---
                if role_ui_elements:
                    logger.info("Generating UI Element Comparison sheet...")
                    ws_ui = wb.create_sheet(title="UI Element Map")
                    
                    # Headers
                    ws_ui.append(["Interactive Element"] + role_names)
                    
                    # Get unique list of all elements found
                    all_ui_items = sorted(list(set().union(*role_ui_elements.values())))
                    
                    for item in all_ui_items:
                        row = [item]
                        cells_to_fill = []
                        for role_name in role_names:
                            if item in role_ui_elements.get(role_name, set()):
                                row.append("X")
                                cells_to_fill.append(True)
                            else:
                                row.append("")
                                cells_to_fill.append(False)
                        
                        ws_ui.append(row)
                        
                        # Style the new row
                        curr_row = ws_ui.max_row
                        ws_ui.cell(row=curr_row, column=1).border = thin_border
                        
                        for c_idx, seen in enumerate(cells_to_fill, start=2):
                            cell = ws_ui.cell(row=curr_row, column=c_idx)
                            cell.border = thin_border
                            if seen:
                                cell.fill = green_fill
                            else:
                                cell.fill = orange_fill
                                
                    # Auto-adjust column width for readability
                    ws_ui.column_dimensions['A'].width = 50
                    wb.save(output_xlsx)
                    logger.info(f"UI Element Map added to Excel report.")

                # --- API Calls Sheet ---
                if all_api_calls_by_role and any(all_api_calls_by_role.values()):
                    ws_api = wb.create_sheet(title="API Calls")
                    ws_api.append(["Method", "Path"] + role_names)
                    # Header styling
                    for cell in ws_api[1]:
                        cell.fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
                        cell.font = Font(bold=True, color="FFFFFF")
                        cell.border = thin_border

                    # Collect unique (method, path) across all roles
                    all_api_keys = {}  # (method, path) -> {role_name: ApiCall}
                    for rname, calls in all_api_calls_by_role.items():
                        for call in calls:
                            key = (call.method, call.path)
                            all_api_keys.setdefault(key, {})[rname] = call

                    api_vuln_set = {(item['endpoint'], item['role']) for item in results['vuln']}

                    for (method, path), role_map in sorted(all_api_keys.items()):
                        call_id = f"{method} {path}"
                        row_vals = [method, path]
                        row_fills = []
                        for rname in role_names:
                            if rname in role_map:
                                row_vals.append("X")
                                row_fills.append(green_fill)
                            elif args.test:
                                if (call_id, rname) in api_vuln_set:
                                    row_vals.append("VULNERABLE")
                                    row_fills.append(red_fill)
                                elif (call_id, rname) in results['suspicious']:
                                    row_vals.append("SUSPICIOUS")
                                    row_fills.append(orange_fill)
                                else:
                                    row_vals.append("")
                                    row_fills.append(green_fill)
                            else:
                                row_vals.append("")
                                row_fills.append(None)
                        ws_api.append(row_vals)
                        curr_row = ws_api.max_row
                        ws_api.cell(row=curr_row, column=1).border = thin_border
                        ws_api.cell(row=curr_row, column=2).border = thin_border
                        for c_idx, fill in enumerate(row_fills, start=3):
                            cell = ws_api.cell(row=curr_row, column=c_idx)
                            cell.border = thin_border
                            if fill:
                                cell.fill = fill

                    ws_api.column_dimensions['A'].width = 10
                    ws_api.column_dimensions['B'].width = 60
                    total_api = len(all_api_keys)
                    wb.save(output_xlsx)
                    logger.info(f"API Calls sheet added to Excel report ({total_api} unique calls).")

                # --- Provenance-aware recon sheets ---
                if all_recon_by_role:
                    ws_recon = wb.create_sheet(title="Recon Candidates")
                    ws_recon.append([
                        "Method", "Canonical Path", "Raw URL", "Source", "Role",
                        "Observed", "Validated", "Confidence", "Resolution", "Method Source",
                        "Classification", "Unresolved Expressions", "Discovered From", "Evidence",
                    ])
                    for cell in ws_recon[1]:
                        cell.fill = PatternFill(start_color="305496", end_color="305496", fill_type="solid")
                        cell.font = Font(bold=True, color="FFFFFF")
                        cell.border = thin_border

                    combined_sheet_inventory = ReconInventory(role="ALL")
                    for inventory in all_recon_by_role.values():
                        combined_sheet_inventory.merge(inventory)
                    for candidate in sorted(
                        combined_sheet_inventory.candidates,
                        key=lambda item: (item.canonical_path.lower(), item.method or "", item.source, item.role or ""),
                    ):
                        ws_recon.append([
                            candidate.method or "UNKNOWN",
                            candidate.canonical_path,
                            redact_url(candidate.raw_url),
                            candidate.source,
                            candidate.role or "",
                            "YES" if candidate.observed else "NO",
                            "YES" if candidate.validated else "NO",
                            candidate.confidence,
                            candidate.resolution or "",
                            candidate.method_source or "",
                            candidate.classification or "",
                            ", ".join(candidate.unresolved_expressions),
                            redact_url(candidate.discovered_from or ""),
                            redact_text(candidate.evidence),
                        ])
                    for row in ws_recon.iter_rows(min_row=2):
                        for cell in row:
                            cell.border = thin_border
                    for col, width in {
                        "A": 11, "B": 58, "C": 72, "D": 18, "E": 25, "F": 11, "G": 11,
                        "H": 12, "I": 20, "J": 18, "K": 20, "L": 40, "M": 72, "N": 80,
                    }.items():
                        ws_recon.column_dimensions[col].width = width
                    ws_recon.freeze_panes = "A2"
                    ws_recon.auto_filter.ref = ws_recon.dimensions

                    ws_coverage = wb.create_sheet(title="Recon Coverage")
                    ws_coverage.append([
                        "Role", "Assets Advertised", "Assets Downloaded", "Scanner-Fetched", "Assets Parsed",
                        "Source Maps", "Assets Skipped", "Candidates", "Observed", "Validated",
                        "Safe Actions", "Filter Options", "Lazy Scroll Steps", "Risky Skipped", "Destructive Skipped",
                    ])
                    for cell in ws_coverage[1]:
                        cell.fill = PatternFill(start_color="548235", end_color="548235", fill_type="solid")
                        cell.font = Font(bold=True, color="FFFFFF")
                        cell.border = thin_border
                    for role_name_key, inventory in sorted(all_recon_by_role.items()):
                        coverage = inventory.coverage()
                        ui = coverage.get("ui", {})
                        ws_coverage.append([
                            role_name_key,
                            coverage["assets_advertised"], coverage["assets_downloaded"],
                            coverage["assets_fetched_by_scanner"], coverage["assets_parsed"], coverage["source_maps_found"],
                            coverage["assets_skipped"], coverage["endpoint_candidates"],
                            coverage["observed_candidates"], coverage["validated_candidates"],
                            ui.get("safe_actions_explored", 0),
                            ui.get("safe_filter_options_explored", 0),
                            ui.get("lazy_scroll_steps", 0),
                            ui.get("risky_actions_skipped", 0),
                            ui.get("destructive_actions_skipped", 0),
                        ])
                    ws_coverage.column_dimensions["A"].width = 28
                    for row in ws_coverage.iter_rows():
                        for cell in row:
                            cell.border = thin_border

                    wb.save(output_xlsx)
                    logger.info(
                        f"Recon Candidates and Recon Coverage sheets added "
                        f"({len(combined_sheet_inventory.candidates)} candidates)."
                    )

            except Exception as e:
                logger.error(f"Error writing XLSX: {e}")

        # 2. Generate JSON Report
        report_findings = list(results.get('vuln', [])) + list(results.get('suspicious_detail', []))
        if args.test and report_findings:
            try:
                # Aggregate findings by endpoint
                consolidated_findings = {}

                confidence_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

                def _max_confidence(a, b):
                    a = _normalize_confidence(a)
                    b = _normalize_confidence(b)
                    return a if confidence_rank[a] >= confidence_rank[b] else b

                def _status_for_finding(finding):
                    if finding in results.get('vuln', []):
                        return "VULNERABLE"
                    return "SUSPICIOUS"

                for finding in report_findings:
                    finding_status = _status_for_finding(finding)
                    ep = finding['endpoint']
                    if ep not in consolidated_findings:
                        consolidated_findings[ep] = {
                            "endpoint": ep,
                            "finding_status": finding_status,
                            "severity": _normalize_severity(finding.get('severity', 'High' if finding_status == "VULNERABLE" else 'Information')),
                            "confidence": _normalize_confidence(finding.get('confidence', 'MEDIUM' if finding_status == "VULNERABLE" else 'LOW')),
                            "vulnerable_roles": [],
                            "suspicious_roles": [],
                            "baseline_role": finding['baseline_role'],
                            "reason": finding['reason'],
                            "evidence": []
                        }
                        
                        # Add Baseline Evidence (only once)
                        ev = finding.get('evidence') or {}
                        consolidated_findings[ep]['evidence'].append({
                            "role": finding['baseline_role'],
                            "type": "baseline",
                            "request": ev.get('baseline_request', ''),
                            "response": ev.get('baseline_response', '')
                        })
                    else:
                        data = consolidated_findings[ep]
                        data['confidence'] = _max_confidence(data.get('confidence'), finding.get('confidence'))
                        if finding_status == "VULNERABLE":
                            data['finding_status'] = "VULNERABLE"
                            data['severity'] = _normalize_severity(finding.get('severity', data.get('severity', 'High')))
                    
                    role_bucket = 'vulnerable_roles' if finding_status == "VULNERABLE" else 'suspicious_roles'
                    if finding['role'] not in consolidated_findings[ep][role_bucket]:
                        consolidated_findings[ep][role_bucket].append(finding['role'])

                    # Add Test User Evidence (Limit to 2 test users => Total 3 evidence items)
                    # We start with 1 (baseline). So we can add 2 more.
                    if len(consolidated_findings[ep]['evidence']) < 3:
                        ev = finding.get('evidence') or {}
                        consolidated_findings[ep]['evidence'].append({
                            "role": finding['role'],
                            "type": "vulnerable_test_user" if finding_status == "VULNERABLE" else "suspicious_test_user",
                            "request": ev.get('test_request', ''),
                            "response": ev.get('test_response', '')
                        })

                # Convert to List and Finalize Description
                final_report = []
                for ep, data in consolidated_findings.items():
                    vuln_roles = ", ".join(data['vulnerable_roles'])
                    suspicious_roles = ", ".join(data['suspicious_roles'])
                    if data['finding_status'] == "VULNERABLE":
                        desc = f"Broken Access Control (IDOR/BOLA) detected on {ep}.\n\n"
                        if vuln_roles:
                            desc += f"Confirmed vulnerable roles for baseline '{data['baseline_role']}': {vuln_roles}.\n\n"
                        if suspicious_roles:
                            desc += f"Additional suspicious roles requiring manual review: {suspicious_roles}.\n\n"
                    else:
                        desc = f"Potential Broken Access Control (IDOR/BOLA) requiring manual review on {ep}.\n\n"
                        desc += f"Suspicious roles for baseline '{data['baseline_role']}': {suspicious_roles}.\n\n"
                    desc += f"Finding Status: {data['finding_status']}\n"
                    desc += f"Confidence: {data['confidence']}\n\n"
                    desc += f"Analysis: {data['reason']}"
                    
                    final_report.append({
                        "endpoint": ep,
                        "finding_status": data['finding_status'],
                        "severity": data['severity'],
                        "confidence": data['confidence'],
                        "description": desc,
                        "vulnerable_roles": data['vulnerable_roles'],
                        "suspicious_roles": data['suspicious_roles'],
                        "evidence": data['evidence']
                    })

                with open(output_json, 'w', encoding='utf-8') as f:
                    json.dump(final_report, f, indent=4)
                vuln_count = sum(1 for item in final_report if item.get("finding_status") == "VULNERABLE")
                suspicious_count = sum(1 for item in final_report if item.get("finding_status") == "SUSPICIOUS")
                logger.info(f"JSON Report saved to: {output_json} ({len(final_report)} aggregated issues: {vuln_count} vulnerable, {suspicious_count} suspicious)")
            except Exception as e:
                logger.error(f"Error writing JSON: {e}")
        elif args.test:
            logger.info("No vulnerabilities found to report in JSON.")

if __name__ == "__main__":
    asyncio.run(main())
