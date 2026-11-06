"""airlock-sandbox — Hermes terminal backend that executes via Airlock.

Select with ``hermes config set terminal.backend airlock_sandbox``. Commands go
through Airlock's public HTTP API (policy gate + disposable sandbox + signed
receipts). See README.md for disclosure of network calls and credentials.
"""

from __future__ import annotations

import logging

from .provider import AirlockSandboxProvider

logger = logging.getLogger(__name__)


def register(ctx) -> None:
    """Register the Airlock terminal environment provider on the public Hermes seam."""
    get_config = getattr(ctx, "get_config", None)
    set_config = getattr(ctx, "set_config", None)
    provider = AirlockSandboxProvider(get_config=get_config, set_config=set_config)
    ctx.register_terminal_environment_provider(provider)
    logger.info(
        "airlock-sandbox: registered terminal backend %r",
        provider.name,
    )
