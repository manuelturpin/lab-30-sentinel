"""Tests for scripts/lib/http_client — SSL context + SSRF guard."""
from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "scripts"))

from lib.http_client import (  # noqa: E402
    SSRFGuardError,
    api_request,
    get_ssl_context,
)


def test_ssl_context_verifies() -> None:
    ctx = get_ssl_context()
    # Must never silently downgrade to CERT_NONE like the old scripts did.
    import ssl

    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_api_request_blocks_private_urls() -> None:
    for url in (
        "http://127.0.0.1:6379",
        "http://localhost/foo",
        "http://169.254.169.254/latest/meta-data/",
        "http://192.168.1.1",
    ):
        with pytest.raises(SSRFGuardError):
            api_request(url)


def test_api_request_blocks_non_http_schemes() -> None:
    with pytest.raises(SSRFGuardError):
        api_request("file:///etc/passwd")
