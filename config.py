"""Explicit setup validation for Airlock plugin settings.

Fail closed before any network call when required trust material is missing
or the endpoint is not a clean HTTPS origin. Demo hosts are never built-in defaults.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional
from urllib.parse import urlparse

# Demo endpoint (opt-in documentation only — never a code default).
DEMO_BASE_URL = "https://45-77-141-253.sslip.io"
# Demo signing key published by Airlock for that deployment (opt-in; obtain out-of-band).
DEMO_PUBLIC_KEY_HEX = (
    "d8c2acc2972692ee205a7e056d8ae2791906ba1e17f9bdf2cee14baf53377748"
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ConfigError(ValueError):
    """Plugin settings are missing or unsafe; do not contact Airlock."""


def normalize_base_url(raw: Optional[str]) -> str:
    """Return a stripped base URL or empty string if unset."""
    return (raw or "").strip().rstrip("/")


def _host_literal(hostname: str) -> str:
    """Return hostname for an origin URL; bracket IPv6 literals."""
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        return hostname
    if addr.version == 6:
        return f"[{hostname}]"
    return hostname


def require_https_base_url(raw: Optional[str]) -> str:
    """Require a clean ``https://host[:port]`` origin. Raises ConfigError otherwise.

    Rejects userinfo, query, fragment, empty hostname, and invalid ports so a
    mis-copied URL cannot smuggle credentials into logs or odd request targets.
    IPv6 literals are re-emitted with brackets (``https://[::1]:443``).
    Never echoes credential material from a rejected URL.
    """
    url = normalize_base_url(raw)
    if not url:
        raise ConfigError(
            "base_url is required; set plugins.entries.airlock-sandbox.settings.base_url "
            "to your Airlock HTTPS API origin (no built-in default)"
        )
    try:
        parsed = urlparse(url)
    except ValueError as e:
        # e.g. urllib.parse.ValueError: Invalid IPv6 URL — do not echo the input.
        raise ConfigError("base_url is not a valid HTTPS origin") from e
    if parsed.scheme.lower() != "https":
        raise ConfigError(
            "base_url must use HTTPS; refusing to send commands"
        )
    if parsed.username is not None or parsed.password is not None:
        raise ConfigError(
            "base_url must not contain userinfo (username/password); "
            "put credentials in AIRLOCK_API_TOKEN via Hermes secret scope instead"
        )
    if parsed.query or parsed.fragment:
        raise ConfigError(
            "base_url must be an origin only (no query string or fragment)"
        )
    path = parsed.path or ""
    if path not in ("", "/"):
        raise ConfigError(
            "base_url must be an origin only (no path); requests use /healthz and /api/..."
        )
    host = parsed.hostname
    if not host:
        raise ConfigError("base_url is missing a hostname")
    try:
        # urlparse raises ValueError for malformed ports (e.g. https://h:bad).
        port = parsed.port
    except ValueError as e:
        raise ConfigError("base_url has an invalid port") from e
    host_part = _host_literal(host)
    if port is not None:
        return f"https://{host_part}:{port}"
    return f"https://{host_part}"


def normalize_public_key_hex(raw: Optional[str]) -> str:
    return (raw or "").strip().lower()


def require_public_key_hex(raw: Optional[str]) -> str:
    """Require a locally configured Ed25519 public key (64 lowercase hex chars)."""
    key = normalize_public_key_hex(raw)
    if not key:
        raise ConfigError(
            "public_key_hex is required for receipt verification; set a trusted key "
            "obtained out-of-band from an operator you trust (not from the Airlock "
            "API at verify time)"
        )
    if not _HEX64.fullmatch(key):
        raise ConfigError(
            "public_key_hex must be exactly 64 lowercase hex characters (Ed25519 raw key)"
        )
    return key
