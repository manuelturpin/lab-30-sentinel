"""Shared HTTP utilities: SSL context + SSRF-guarded urllib helpers.

Consolidates the SSL/certifi boilerplate previously duplicated across
cve-sync.py, anthropic-sync.py and project-rescan.py. Every outbound
request goes through ``url_guard.is_public_url`` before being sent,
closing the SSRF vectors flagged in audit 2026-04-21 (T3/T5).
"""
from __future__ import annotations

import json
import ssl
import sys
import urllib.error
import urllib.request
from typing import Any

from .url_guard import is_public_url


class SSRFGuardError(ValueError):
    """Raised when an outbound URL fails the public-address guard."""


def get_ssl_context() -> ssl.SSLContext:
    """Return a TLS context with certifi's CA bundle when available.

    Falls back to the system default if certifi is missing, logging a
    warning so the user can install it. Never disables verification —
    the previous scripts did, but that was a Mac-only footgun.
    """
    ctx = ssl.create_default_context()
    try:
        import certifi  # noqa: WPS433 — optional dep
    except ImportError:
        print(
            "WARNING: certifi not installed — using system CA bundle. "
            "Install with: pip install certifi",
            file=sys.stderr,
        )
        return ctx
    ctx.load_verify_locations(certifi.where())
    return ctx


_DEFAULT_CTX: ssl.SSLContext | None = None


def _ctx() -> ssl.SSLContext:
    global _DEFAULT_CTX
    if _DEFAULT_CTX is None:
        _DEFAULT_CTX = get_ssl_context()
    return _DEFAULT_CTX


def api_request(
    url: str,
    *,
    method: str = "GET",
    data: Any = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    user_agent: str = "sentinel/1.0",
) -> Any:
    """Send an HTTP(S) request and return parsed JSON, or ``None`` on failure.

    - Rejects private / loopback / link-local / metadata URLs up front.
    - Uses a shared SSL context (certifi when installed).
    - Returns ``None`` on HTTP / network errors; logs to stderr. This
      matches the behavior of the previous per-script helpers so callers
      don't need to change their error paths.
    """
    if not is_public_url(url):
        raise SSRFGuardError(f"Refusing to {method} private/local URL: {url}")

    req_headers = {"User-Agent": user_agent}
    if headers:
        req_headers.update(headers)

    body: bytes | None = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"  HTTP {e.code} from {url}", file=sys.stderr)
        return None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(f"  Request failed for {url}: {e}", file=sys.stderr)
        return None
