"""Airlock-backed terminal environment (BaseEnvironment duck type).

``execute()`` sends the command to Airlock ``POST /api/arena``, verifies the
signed receipt when configured, and returns Hermes-shaped ``{output, exit_code}``
with BLOCKED / ALLOWED / VERIFIED status lines. Fail closed on transport errors,
policy deny, or invalid receipts.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Mapping, Optional

from .client import AirlockClient, AirlockError, DEFAULT_BASE_URL
from .receipts import (
    ReceiptError,
    status_from_step,
    verify_receipt,
)

logger = logging.getLogger(__name__)

# Non-zero codes Hermes can surface to the model for fail-closed outcomes.
EXIT_BLOCKED = 126
EXIT_UNAVAILABLE = 75
EXIT_INVALID_RECEIPT = 74


class AirlockEnvironment:
    """Duck-typed BaseEnvironment: execute commands via Airlock's public HTTP API."""

    uses_host_filesystem = False

    def __init__(
        self,
        *,
        cwd: str,
        timeout: int,
        task_id: str = "default",
        base_url: str = DEFAULT_BASE_URL,
        api_token: Optional[str] = None,
        public_key_hex: str = "",
        verify_receipts: bool = True,
        language: str = "bash",
        http_timeout_s: float = 60.0,
        client_factory: Optional[Callable[..., AirlockClient]] = None,
    ) -> None:
        self.cwd = cwd if cwd and cwd != "~" else "/work"
        self.timeout = timeout
        self.task_id = task_id
        self.base_url = base_url
        self.api_token = api_token
        self.public_key_hex = (public_key_hex or "").strip().lower()
        self.verify_receipts = bool(verify_receipts)
        self.language = language if language in ("bash", "python") else "bash"
        self.http_timeout_s = float(http_timeout_s)
        self._client_factory = client_factory or AirlockClient
        self._cached_pubkey: Optional[str] = None
        self._last_prev_hash: Optional[str] = None
        self._last_receipt: Optional[dict[str, Any]] = None

    def _make_client(self) -> AirlockClient:
        return self._client_factory(
            self.base_url,
            timeout_s=max(self.http_timeout_s, float(self.timeout or 0) + 5.0),
            api_token=self.api_token,
        )

    def _resolve_pubkey(self, client: AirlockClient) -> str:
        if self.public_key_hex:
            return self.public_key_hex
        if self._cached_pubkey:
            return self._cached_pubkey
        info = client.pubkey()
        key = str(info["public_key_hex"]).strip().lower()
        self._cached_pubkey = key
        return key

    def execute(self, command: str, timeout: Optional[int] = None, **kwargs: Any) -> dict[str, Any]:
        del kwargs  # forward-compat: Hermes may pass extra keys
        cmd = command if isinstance(command, str) else str(command)
        if not cmd.strip():
            return self._result("BLOCKED: empty command refused", EXIT_BLOCKED)

        effective_timeout = int(timeout or self.timeout or 60)
        try:
            with self._make_client() as client:
                # Cheap liveness probe so a down Airlock fails before we pretend to run.
                client.healthz()
                step = client.arena(lang=self.language, code=cmd)
                return self._handle_step(client, step, command_timeout=effective_timeout)
        except AirlockError as e:
            logger.warning("airlock-sandbox: Airlock unavailable: %s", e)
            return self._result(
                f"BLOCKED: Airlock unavailable ({e}). Fail-closed; nothing ran on the host.",
                EXIT_UNAVAILABLE,
            )
        except Exception as e:  # noqa: BLE001 — provider must not raise into the tool loop
            logger.exception("airlock-sandbox: unexpected execute failure")
            return self._result(
                f"BLOCKED: Airlock execute failed ({e}). Fail-closed; nothing ran on the host.",
                EXIT_UNAVAILABLE,
            )

    def _handle_step(
        self,
        client: AirlockClient,
        step: Mapping[str, Any],
        *,
        command_timeout: int,
    ) -> dict[str, Any]:
        del command_timeout
        receipt_obj = step.get("receipt")
        receipt_id = step.get("receipt_id")
        receipt_verified = False
        verify_note = "verification skipped (verify_receipts=false)"

        if self.verify_receipts:
            try:
                pubkey = self._resolve_pubkey(client)
                if isinstance(receipt_obj, Mapping):
                    verified = verify_receipt(
                        receipt_obj,
                        pubkey,
                        expected_prev_hash=None,
                    )
                elif receipt_id:
                    text = client.get_receipt_text(str(receipt_id))
                    verified = verify_receipt(text, pubkey)
                else:
                    raise ReceiptError("arena response missing receipt and receipt_id")
                receipt_verified = True
                verify_note = "receipt hash + Ed25519 signature OK"
                self._last_receipt = verified
                self._last_prev_hash = verified.get("hash")
            except (ReceiptError, AirlockError, TypeError, ValueError) as e:
                logger.warning("airlock-sandbox: invalid receipt: %s", e)
                return self._result(
                    self._format_output(
                        status="BLOCKED",
                        step=step,
                        extra=(
                            f"INVALID RECEIPT: {e}. Fail-closed; host did not trust this result."
                        ),
                        receipt_verified=False,
                    ),
                    EXIT_INVALID_RECEIPT,
                )

        verdict = str(step.get("verdict") or "").lower()
        status = status_from_step(step, receipt_verified=receipt_verified and verdict == "allow")
        # A deny with a valid receipt is still BLOCKED for execution status; surface VERIFIED
        # as a secondary line so the model sees cryptographic proof of the deny.
        if verdict != "allow":
            output = self._format_output(
                status="BLOCKED",
                step=step,
                extra=(
                    f"VERIFIED: {verify_note}" if receipt_verified else verify_note
                ),
                receipt_verified=receipt_verified,
            )
            return self._result(output, EXIT_BLOCKED)

        execution = step.get("execution") if isinstance(step.get("execution"), Mapping) else {}
        stdout = str(execution.get("stdout") or "")
        stderr = str(execution.get("stderr") or "")
        exit_code = int(execution.get("exit_code") if execution.get("exit_code") is not None else 0)
        body = stdout
        if stderr.strip():
            body = f"{stdout}{'' if stdout.endswith(chr(10)) or not stdout else chr(10)}[stderr]\n{stderr}"
        # Prefer VERIFIED when crypto passed; otherwise ALLOWED.
        display = "VERIFIED" if receipt_verified else "ALLOWED"
        output = self._format_output(
            status=display,
            step=step,
            extra=f"{verify_note}\n{body}".rstrip(),
            receipt_verified=receipt_verified,
        )
        return self._result(output, exit_code)

    def _format_output(
        self,
        *,
        status: str,
        step: Mapping[str, Any],
        extra: str = "",
        receipt_verified: bool,
    ) -> str:
        verdict = step.get("verdict")
        reason = step.get("reason") or ""
        rules = step.get("rules_fired") or []
        receipt_id = step.get("receipt_id") or ""
        receipt = step.get("receipt") if isinstance(step.get("receipt"), Mapping) else {}
        prev_hash = receipt.get("prev_hash") if isinstance(receipt, Mapping) else None
        lines = [
            f"[{status}] airlock-sandbox",
            f"verdict={verdict} status={step.get('status')}",
        ]
        if reason:
            lines.append(f"reason={reason}")
        if rules:
            lines.append("rules=" + ",".join(str(r) for r in rules))
        if receipt_id:
            lines.append(f"receipt_id={receipt_id}")
        if prev_hash:
            lines.append(f"prev_hash={prev_hash}")
        lines.append(f"receipt_verified={str(receipt_verified).lower()}")
        if extra:
            lines.append(extra)
        return "\n".join(lines)

    @staticmethod
    def _result(output: str, exit_code: int) -> dict[str, Any]:
        return {"output": output, "returncode": exit_code, "exit_code": exit_code}

    def cleanup(self) -> None:
        # Airlock sandboxes are disposable per arena call; nothing local to tear down.
        self._last_receipt = None

    def get_temp_dir(self) -> str:
        return "/tmp"
