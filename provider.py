"""Airlock terminal environment provider for Hermes.

Registers as ``terminal.backend: airlock_sandbox``. Commands are evaluated by
Airlock's policy engine and, when allowed, run in Airlock's disposable sandbox.
Hermes approvals are NOT bypassed (``skip_container_guards = False``).
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from agent.terminal_env_provider import TerminalEnvironmentProvider

from .client import DEFAULT_BASE_URL
from .environment import AirlockEnvironment

logger = logging.getLogger(__name__)

BACKEND_NAME = "airlock_sandbox"
TOKEN_ENV = "AIRLOCK_API_TOKEN"


class AirlockSandboxProvider(TerminalEnvironmentProvider):
    """Route Hermes terminal / code / file-tool commands through Airlock."""

    name = BACKEND_NAME
    display_name = "Airlock Sandbox"
    is_remote = True
    is_container = True
    # Keep Hermes dangerous-command approvals on. Airlock is an extra gate, not a bypass.
    skip_container_guards = False
    session_isolated_when_nonpersistent = True
    supports_streams = False

    def __init__(
        self,
        get_config: Optional[Callable[..., Any]] = None,
        set_config: Optional[Callable[[str, Any], None]] = None,
    ) -> None:
        self._get_config = get_config
        self._set_config = set_config

    def _cfg(self, key: str, default: Any = None) -> Any:
        if self._get_config is None:
            return default
        try:
            value = self._get_config(key, default)
        except TypeError:
            value = self._get_config(key)
        return default if value is None else value

    @property
    def description(self) -> str:
        return (
            "Run commands through Airlock's policy engine and disposable Docker "
            "sandbox, with verifiable Ed25519 receipts (BLOCKED / ALLOWED / VERIFIED)."
        )

    @property
    def env_description(self) -> str:
        return "an Airlock-gated disposable sandbox (policy + gVisor where deployed)"

    @property
    def default_cwd(self) -> Optional[str]:
        return "/work"

    @property
    def strip_env_keys(self) -> frozenset:
        # Never let model-authored shell commands read the Airlock token.
        return frozenset({TOKEN_ENV})

    def cache_path_base(self) -> Optional[str]:
        return None

    def _secret(self) -> Optional[str]:
        try:
            from agent.secret_scope import get_secret
        except Exception:
            return None
        try:
            value = get_secret(TOKEN_ENV)
        except Exception:
            return None
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _base_url(self) -> str:
        raw = str(self._cfg("base_url", DEFAULT_BASE_URL) or DEFAULT_BASE_URL).strip()
        return raw.rstrip("/") or DEFAULT_BASE_URL

    def is_available(self) -> bool:
        # Cheap: no network. A configured base URL is enough to offer the backend.
        return bool(self._base_url())

    def probe(self) -> tuple[str, str]:
        if self.is_available():
            return ("ready", f"Will call Airlock at {self._base_url()}")
        return ("needs_setup", "Set plugins.entries.airlock-sandbox.settings.base_url")

    def setup_instructions(self) -> list[str]:
        return [
            f"Airlock API: {self._base_url()}",
            "Select this backend: hermes config set terminal.backend airlock_sandbox",
            "Optional private token: store AIRLOCK_API_TOKEN via Hermes (config_schema secret).",
            "Optional pinned pubkey: plugins.entries.airlock-sandbox.settings.public_key_hex",
            "Hermes approvals stay enabled; Airlock is an additional fail-closed gate.",
        ]

    def doctor_checks(self) -> list[tuple[bool, str, str]]:
        url = self._base_url()
        return [
            (bool(url), "Airlock base URL", f"({url})" if url else "(missing)"),
            (True, "Hermes approvals", "(not bypassed; skip_container_guards=false)"),
        ]

    def create_environment(
        self,
        *,
        cwd: str,
        timeout: int,
        task_id: str = "default",
        image: Optional[str] = None,
        container_config: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ):
        del image, container_config, kwargs
        verify = self._cfg("verify_receipts", True)
        if isinstance(verify, str):
            verify = verify.strip().lower() not in ("0", "false", "no", "off")
        language = str(self._cfg("language", "bash") or "bash").strip().lower()
        try:
            http_timeout = float(self._cfg("timeout_s", 60) or 60)
        except (TypeError, ValueError):
            http_timeout = 60.0
        return AirlockEnvironment(
            cwd=cwd,
            timeout=timeout,
            task_id=task_id,
            base_url=self._base_url(),
            api_token=self._secret(),
            public_key_hex=str(self._cfg("public_key_hex", "") or ""),
            verify_receipts=bool(verify),
            language=language if language in ("bash", "python") else "bash",
            http_timeout_s=http_timeout,
        )
