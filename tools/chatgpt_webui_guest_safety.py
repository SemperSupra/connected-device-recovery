"""Bounded no-credential host and error-sanitization helpers for guest probes."""
from __future__ import annotations
from urllib.parse import urlsplit

MAX_ASSETS = 24
MAX_ASSET_BYTES = 512_000


def allowed_asset_url(url: str) -> bool:
    if not isinstance(url, str) or len(url) > 4096:
        return False
    try:
        u = urlsplit(url)
        host = (u.hostname or "").lower().rstrip(".")
        # Hostname suffix needs a label boundary; 'evilchatgpt.com' is NOT
        # first party. HTTPS-only, no alternate ports or username info.
        host_ok = any(host == base or host.endswith("." + base)
                      for base in ("chatgpt.com", "oaistatic.com"))
        return (u.scheme == "https" and host_ok and u.username is None
                and u.password is None and u.port in (None, 443))
    except (ValueError, AttributeError):
        return False


def error_kind(exc: Exception) -> str:
    # Never persist the exception message: HTTP errors sometimes echo a
    # redirected query string, request body, or transient token material.
    return type(exc).__name__
