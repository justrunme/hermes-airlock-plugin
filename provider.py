"""Airlock terminal environment provider for Hermes.

Registers as ``terminal.backend: airlock_sandbox``. Commands are evaluated by
Airlock's policy engine and, when allowed, run in Airlock's disposable sandbox.
Hermes approvals are NOT bypassed (``skip_container_guards = False``).
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from agent.terminal_env_provider import TerminalEnvironmentProvider

from .config import (
    ConfigError,
    DEMO_BASE_URL,
    normalize_base_url,
    normalize_public_key_hex,
    require_https_base_url,
    require_public_key_hex,
)
from .environment import SANDBOX_CWD, AirlockEnvironment

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
        return SANDBOX_CWD

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
        return normalize_base_url(str(self._cfg("base_url", "") or ""))

    def _public_key_hex(self) -> str:
        return normalize_public_key_hex(str(self._cfg("public_key_hex", "") or ""))

    def _verify_receipts(self) -> bool:
        verify = self._cfg("verify_receipts", True)
        if isinstance(verify, str):
            return verify.strip().lower() not in ("0", "false", "no", "off")
        return bool(verify)

    def _configured(self) -> tuple[bool, str]:
        try:
            require_https_base_url(self._base_url())
        except ConfigError as e:
            return False, str(e)
        if self._verify_receipts():
            try:
                require_public_key_hex(self._public_key_hex())
            except ConfigError as e:
                return False, str(e)
        return True, ""

    def is_available(self) -> bool:
        # Cheap: no network. Require explicit HTTPS base_url (+ trusted key when verifying).
        ok, _ = self._configured()
        return ok

    def probe(self) -> tuple[str, str]:
        ok, detail = self._configured()
        if ok:
            return ("ready", f"Will call Airlock at {self._base_url()}")
        return ("needs_setup", detail)

    def setup_instructions(self) -> list[str]:
        return [
            "Required: set plugins.entries.airlock-sandbox.settings.base_url to an HTTPS Airlock API "
            "(no built-in default).",
            "Required for VERIFIED receipts: set public_key_hex to a trusted Ed25519 key obtained "
            "out-of-band from an operator you trust. Do not take the verifying key from the live "
            "Airlock API during verification (a host that can forge receipts can serve a matching key).",
            f"Opt-in demo only (not a default): base_url={DEMO_BASE_URL}; copy the demo public key "
            "from that deployment's published documentation or operator channel, then pin it locally.",
            "Select this backend: hermes config set terminal.backend airlock_sandbox",
            "Optional private token: store AIRLOCK_API_TOKEN via Hermes (config_schema secret).",
            "Hermes approvals stay enabled; Airlock is an additional fail-closed gate.",
            "Limitation: Airlock arena has no process-stdin and no cwd field; file-tool writes "
            "that pipe content on stdin are refused rather than faked.",
            "Limitation: signed receipts do not include command text; VERIFIED binds "
            "decision/execution digests, not which command string was sent.",
        ]

    def doctor_checks(self) -> list[tuple[bool, str, str]]:
        url_ok = False
        url_detail = "(missing)"
        try:
            url = require_https_base_url(self._base_url())
            url_ok, url_detail = True, f"({url})"
        except ConfigError as e:
            url_detail = f"({e})"
        key_ok = False
        key_detail = "(missing)"
        if not self._verify_receipts():
            key_ok, key_detail = True, "(verify_receipts=false; VERIFIED disabled)"
        else:
            try:
                require_public_key_hex(self._public_key_hex())
                key_ok, key_detail = True, "(locally configured)"
            except ConfigError as e:
                key_detail = f"({e})"
        return [
            (url_ok, "Airlock base URL", url_detail),
            (key_ok, "Airlock public_key_hex", key_detail),
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
            public_key_hex=self._public_key_hex(),
            verify_receipts=self._verify_receipts(),
            language=language if language in ("bash", "python") else "bash",
            http_timeout_s=http_timeout,
        )
