"""Conservative, opt-in validation for passive recon candidates."""

from __future__ import annotations

import asyncio
import re
from typing import Iterable
from urllib.parse import urlparse

from .models import ReconInventory


MUTATION_PATH_RE = re.compile(
    r"(?:^|/)(?:delete|remove|destroy|purge|create|add|update|edit|set|save|submit|"
    r"send|invite|approve|reject|disable|enable|reset|migrate|execute|run|trigger)(?:/|$)",
    re.IGNORECASE,
)


async def validate_safe_get_candidates(
    request_context,
    inventory: ReconInventory,
    *,
    allowed_hosts: Iterable[str],
    limit: int = 100,
    concurrency: int = 4,
) -> int:
    """Validate clearly read-like static GET/HEAD candidates.

    This is opt-in because HTTP method semantics are not a guarantee that an
    application is side-effect free.
    """
    allowed = {str(host).lower() for host in allowed_hosts if host}
    candidates = []
    seen = set()
    for item in inventory.candidates:
        if item.source not in {"js_bundle", "source_map", "openapi"}:
            continue
        if item.method not in {"GET", "HEAD"}:
            continue
        parsed = urlparse(item.raw_url)
        if (parsed.hostname or "").lower() not in allowed:
            continue
        if MUTATION_PATH_RE.search(parsed.path or ""):
            continue
        key = (item.method, item.raw_url)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(item)
        if len(candidates) >= max(0, int(limit)):
            break

    semaphore = asyncio.Semaphore(max(1, int(concurrency)))

    async def validate(item):
        async with semaphore:
            try:
                response = await request_context.fetch(
                    item.raw_url,
                    method=item.method,
                    timeout=15000,
                    fail_on_status_code=False,
                    max_redirects=3,
                )
                item.validated = True
                item.status = response.status
                item.content_type = response.headers.get("content-type", "")
                return 1
            except Exception:
                return 0

    return sum(await asyncio.gather(*(validate(item) for item in candidates))) if candidates else 0
