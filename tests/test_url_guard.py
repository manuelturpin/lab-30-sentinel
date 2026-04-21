"""Tests for scripts/lib/url_guard — SSRF-safe URL validation."""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "scripts"))

from lib.url_guard import is_public_url  # noqa: E402

FIXTURES = pathlib.Path(__file__).parent / "fixtures/url-validator"


def test_private_urls_rejected() -> None:
    for url in (FIXTURES / "private.txt").read_text().strip().splitlines():
        assert is_public_url(url) is False, f"should reject: {url}"


def test_public_urls_accepted() -> None:
    for url in (FIXTURES / "public.txt").read_text().strip().splitlines():
        assert is_public_url(url) is True, f"should accept: {url}"


def test_rejects_non_http_schemes() -> None:
    for bad in ("file:///etc/passwd", "ftp://example.com", "gopher://x"):
        assert is_public_url(bad) is False, f"should reject scheme: {bad}"


def test_rejects_empty_and_malformed() -> None:
    assert is_public_url("") is False
    assert is_public_url("not-a-url") is False
