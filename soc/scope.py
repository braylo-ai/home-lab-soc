"""Scope enforcement.

This SOC is for a *home lab*. It must only ever ingest telemetry that
originates locally or from synthetic/replayed datasets. We never reach out
to, poll, or correlate against any external/third-party host.

The allowlist below is enforced by `assert_source_allowed`, which is called
by every ingest path. Hosts/IPs seen *inside* event data are fine (that is
the whole point of a SIEM); this guard governs where the SOC itself is
allowed to pull data *from*.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

# Data *sources* the SOC process is permitted to read telemetry from.
ALLOWED_SOURCE_HOSTS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "synthetic",  # pseudo-host for generated telemetry
        "file",  # local files / replayed datasets
    }
)

ALLOWED_SCHEMES = frozenset({"file", "synthetic", ""})


class ScopeError(RuntimeError):
    """Raised when the SOC is pointed at a source outside the lab allowlist."""


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_source_allowed(source: str) -> bool:
    """Return True if `source` is a permitted local/synthetic data source.

    Accepts bare hostnames ("localhost"), loopback IPs, `file://` paths,
    and the `synthetic:` pseudo-scheme.
    """
    if source in ALLOWED_SOURCE_HOSTS:
        return True

    parsed = urlparse(source)
    if parsed.scheme and parsed.scheme not in ALLOWED_SCHEMES:
        return False
    # Explicit local schemes (file://, synthetic:) are always in-scope.
    if parsed.scheme in ("file", "synthetic"):
        return True

    host = parsed.hostname or source
    if host in ALLOWED_SOURCE_HOSTS:
        return True
    if _is_loopback(host):
        return True
    # A local filesystem path (no scheme/host) is allowed. A bare token with
    # a dot and no path separator is treated as a hostname, not a path, so
    # external domains like "evil.net" are rejected.
    if not parsed.scheme and not parsed.netloc:
        looks_like_path = "/" in source or source.startswith((".", "~")) or source == ""
        if looks_like_path:
            return True
    return False


def assert_source_allowed(source: str) -> None:
    if not is_source_allowed(source):
        raise ScopeError(
            f"Refusing telemetry source {source!r}: outside the home-lab "
            f"allowlist (local/synthetic only)."
        )
