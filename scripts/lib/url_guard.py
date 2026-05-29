"""URL validation to prevent SSRF against private / link-local / metadata endpoints.

Reject: RFC 1918, loopback, link-local (incl. 169.254.169.254 AWS metadata),
unique-local IPv6 (fc00::/7), known metadata hostnames, non-http(s) schemes.
"""
from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse

_PRIVATE_HOSTNAMES = frozenset({
    "localhost",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
})

# Defense-in-depth deny-list for known-malicious / C2 domains, mirroring Claude Code's
# sandbox.network.deniedDomains (v2.1.113). Seeded from the SENTINEL_DENIED_DOMAINS env
# var (comma-separated domain suffixes), matched case-insensitively against the URL host.
# Empty by default, so existing behaviour is unchanged unless a deny-list is configured.
_DENIED_DOMAIN_SUFFIXES = frozenset(
    d.strip().lower().lstrip(".")
    for d in os.environ.get("SENTINEL_DENIED_DOMAINS", "").split(",")
    if d.strip()
)


def is_denied_domain(host: str) -> bool:
    """Return True iff host matches a configured denied-domain suffix (C2/malware deny-list)."""
    host = (host or "").lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in _DENIED_DOMAIN_SUFFIXES)


def is_public_url(url: str) -> bool:
    """Return True iff url is http(s) and resolves to a public, routable address.

    Host-name-only URLs are accepted (DNS is not resolved). Numeric IPs are
    matched against the RFC-defined private / reserved ranges.
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if host in _PRIVATE_HOSTNAMES:
        return False
    if is_denied_domain(host):
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True  # hostname — DNS not resolved here
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )
