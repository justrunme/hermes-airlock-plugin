"""Airlock-backed terminal environment (BaseEnvironment duck type).

``execute()`` validates local trust settings, sends the command to Airlock
``POST /api/arena``, verifies the signed receipt with a locally configured key,
binds signed decision/execution digests to the returned output, and returns
Hermes-shaped ``{output, returncode}`` with BLOCKED / ALLOWED / VERIFIED lines.

Unsupported Hermes features are refused explicitly (no silent success):
Airlock's public arena API has no process-stdin field and no cwd field, and
each arena call uses a disposable sandbox.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Mapping, Optional

from .binding import BindingError, bind_step_to_receipt, require_outer_execution_for_allow
from .client import AirlockClient, AirlockError
from .config import (
    ConfigError,
    normalize_base_url,
    normalize_public_key_hex,
    require_https_base_url,
    require_public_key_hex,
)
from .receipts import ReceiptError, verify_receipt

logger = logging.getLogger(__name__)

EXIT_BLOCKED = 126
EXIT_UNAVAILABLE = 75
EXIT_INVALID_RECEIPT = 74
EXIT_MISCONFIGURED = 78
EXIT_UNSUPPORTED = 125

SANDBOX_CWD = "/work"


class AirlockEnvironment:
    """Duck-typed BaseEnvironment: execute commands via Airlock's public HTTP API."""

    uses_host_filesystem = False

    def __init__(
        self,
        *,
        cwd: str,
        timeout: int,
        task_id: str = "default",
        base_url: str = "",
        api_token: Optional[str] = None,
        public_key_hex: str = "",
        verify_receipts: bool = True,
        language: str = "bash",
        http_timeout_s: float = 60.0,
        client_factory: Optional[Callable[..., AirlockClient]] = None,
    ) -> None:
        self.cwd = SANDBOX_CWD if (not cwd or cwd == "~") else cwd
        self.timeout = timeout
        self.task_id = task_id
        self.base_url = normalize_base_url(base_url)
        self.api_token = api_token
        self.public_key_hex = normalize_public_key_hex(public_key_hex)
        self.verify_receipts = bool(verify_receipts)
        self.language = language if language in ("bash", "python") else "bash"
        self.http_timeout_s = float(http_timeout_s)
        self._client_factory = client_factory or AirlockClient
        self._last_receipt: Optional[dict[str, Any]] = None
        self._lock = threading.Lock()

    def _make_client(self) -> AirlockClient:
        return self._client_factory(
            self.base_url,
            timeout_s=max(self.http_timeout_s, float(self.timeout or 0) + 5.0),
            api_token=self.api_token,
        )

    def _setup_errors(self) -> Optional[str]:
        try:
            require_https_base_url(self.base_url)
        except ConfigError as e:
            return str(e)
        if self.verify_receipts:
            try:
                require_public_key_hex(self.public_key_hex)
            except ConfigError as e:
                return str(e)
        elif self.public_key_hex:
            try:
                require_public_key_hex(self.public_key_hex)
            except ConfigError as e:
                return str(e)
        return None

    def _cwd_supported(self, cwd: str) -> bool:
        target = (cwd or self.cwd or SANDBOX_CWD).strip()
        return target in ("", "~", SANDBOX_CWD)

    def execute(
        self,
        command: str,
        cwd: str = "",
        *,
        timeout: Optional[int] = None,
        stdin_data: Optional[str] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        del kwargs
        setup_err = self._setup_errors()
        if setup_err:
            return self._result(
                f"BLOCKED: misconfigured airlock-sandbox ({setup_err}). "
                "Fail-closed; nothing was sent to Airlock.",
                EXIT_MISCONFIGURED,
            )

        if stdin_data is not None:
            return self._result(
                "BLOCKED: stdin_data is not supported by Airlock /api/arena "
                "(input_text is a sandbox file, not process stdin). "
                "File-tool writes that rely on stdin cannot be executed safely here; "
                "refusing instead of reporting a false success.",
                EXIT_UNSUPPORTED,
            )

        if not self._cwd_supported(cwd):
            return self._result(
                f"BLOCKED: cwd={cwd!r} is not supported. Airlock arena has no cwd "
                f"field and each job starts in {SANDBOX_CWD}; refusing rather than "
                "pretending the working directory changed.",
                EXIT_UNSUPPORTED,
            )

        cmd = command if isinstance(command, str) else str(command)
        if not cmd.strip():
            return self._result("BLOCKED: empty command refused", EXIT_BLOCKED)

        effective_timeout = int(timeout or self.timeout or 60)
        try:
            with self._make_client() as client:
                client.healthz()
                step = client.arena(lang=self.language, code=cmd)
                return self._handle_step(
                    client, step, command=cmd, command_timeout=effective_timeout
                )
        except AirlockError as e:
            logger.warning("airlock-sandbox: Airlock unavailable: %s", e)
            return self._result(
                f"BLOCKED: Airlock unavailable ({e}). Fail-closed; nothing ran on the host.",
                EXIT_UNAVAILABLE,
            )
        except Exception as e:  # noqa: BLE001
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
        command: str,
        command_timeout: int,
    ) -> dict[str, Any]:
        del command_timeout
        if not isinstance(step, Mapping):
            return self._result(
                "BLOCKED: Airlock arena returned a non-object step",
                EXIT_INVALID_RECEIPT,
            )

        receipt_obj = step.get("receipt")
        receipt_id = step.get("receipt_id")
        verified: Optional[dict[str, Any]] = None
        verify_note = (
            "verification skipped (verify_receipts=false); not VERIFIED. "
            "Signed receipt does not include command text."
        )

        if self.verify_receipts:
            try:
                pubkey = require_public_key_hex(self.public_key_hex)
                if isinstance(receipt_obj, Mapping):
                    verified = verify_receipt(receipt_obj, pubkey)
                elif receipt_id:
                    text = client.get_receipt_text(str(receipt_id))
                    verified = verify_receipt(text, pubkey)
                else:
                    raise ReceiptError("arena response missing receipt and receipt_id")
                verify_note = (
                    "receipt hash + Ed25519 signature OK under locally configured "
                    "public_key_hex; returned stdout/stderr/exit_code matched signed "
                    "execution digests (stdout_sha256 and stderr_sha256 both required "
                    "exact hex; exit_code exact JSON int). Signature alone does not "
                    "authorize unbound optional fields. Command text is not in the "
                    "signed receipt (VERIFIED does not prove which command was "
                    "evaluated). Chain linkage (prev_hash) is not verified here."
                )
                with self._lock:
                    self._last_receipt = verified
            except (ReceiptError, AirlockError, ConfigError, TypeError, ValueError) as e:
                logger.warning("airlock-sandbox: invalid receipt: %s", e)
                return self._result(
                    self._format_output(
                        status="BLOCKED",
                        verdict=step.get("verdict"),
                        step_status=step.get("status"),
                        reason=step.get("reason"),
                        rules=step.get("rules_fired") or [],
                        receipt_id=receipt_id,
                        prev_hash=(
                            receipt_obj.get("prev_hash")
                            if isinstance(receipt_obj, Mapping)
                            else None
                        ),
                        receipt_verified=False,
                        extra=(
                            f"INVALID RECEIPT: {e}. Fail-closed; host did not trust this result."
                        ),
                    ),
                    EXIT_INVALID_RECEIPT,
                )

            try:
                bound = bind_step_to_receipt(step, verified, command=command)
            except BindingError as e:
                logger.warning("airlock-sandbox: receipt binding failed: %s", e)
                return self._result(
                    self._format_output(
                        status="BLOCKED",
                        verdict=(verified.get("decision") or {}).get("verdict")
                        if isinstance(verified.get("decision"), Mapping)
                        else step.get("verdict"),
                        step_status=step.get("status"),
                        reason=step.get("reason"),
                        rules=step.get("rules_fired") or [],
                        receipt_id=receipt_id or verified.get("hash"),
                        prev_hash=verified.get("prev_hash"),
                        receipt_verified=False,
                        extra=(
                            f"BINDING FAILED: {e}. Signature alone is not enough; "
                            "refusing VERIFIED."
                        ),
                    ),
                    EXIT_INVALID_RECEIPT,
                )

            return self._result_from_bound(
                bound,
                prev_hash=verified.get("prev_hash"),
                receipt_verified=True,
                verify_note=verify_note,
            )

        # verify_receipts=false: still refuse missing execution on allow.
        try:
            bound = require_outer_execution_for_allow(step)
        except BindingError as e:
            return self._result(
                self._format_output(
                    status="BLOCKED",
                    verdict=step.get("verdict"),
                    step_status=step.get("status"),
                    reason=step.get("reason"),
                    rules=step.get("rules_fired") or [],
                    receipt_id=receipt_id,
                    prev_hash=None,
                    receipt_verified=False,
                    extra=f"MALFORMED STEP: {e}",
                ),
                EXIT_INVALID_RECEIPT,
            )
        return self._result_from_bound(
            bound,
            prev_hash=None,
            receipt_verified=False,
            verify_note=verify_note,
        )

    def _result_from_bound(
        self,
        bound: Mapping[str, Any],
        *,
        prev_hash: Any,
        receipt_verified: bool,
        verify_note: str,
    ) -> dict[str, Any]:
        verdict = str(bound.get("verdict") or "")
        if verdict != "allow":
            extra = f"VERIFIED: {verify_note}" if receipt_verified else verify_note
            return self._result(
                self._format_output(
                    status="BLOCKED",
                    verdict=verdict,
                    step_status=bound.get("status"),
                    reason=bound.get("reason"),
                    rules=bound.get("rules_fired") or [],
                    receipt_id=bound.get("receipt_id"),
                    prev_hash=prev_hash,
                    receipt_verified=receipt_verified,
                    extra=extra,
                ),
                EXIT_BLOCKED,
            )

        stdout = str(bound.get("stdout") or "")
        stderr = str(bound.get("stderr") or "")
        exit_code = int(bound["exit_code"])
        body = stdout
        if stderr.strip():
            body = (
                f"{stdout}"
                f"{'' if stdout.endswith(chr(10)) or not stdout else chr(10)}"
                f"[stderr]\n{stderr}"
            )
        display = "VERIFIED" if receipt_verified else "ALLOWED"
        return self._result(
            self._format_output(
                status=display,
                verdict="allow",
                step_status=bound.get("status"),
                reason=bound.get("reason"),
                rules=bound.get("rules_fired") or [],
                receipt_id=bound.get("receipt_id"),
                prev_hash=prev_hash,
                receipt_verified=receipt_verified,
                extra=f"{verify_note}\n{body}".rstrip(),
            ),
            exit_code,
        )

    def _format_output(
        self,
        *,
        status: str,
        verdict: Any,
        step_status: Any,
        reason: Any,
        rules: Any,
        receipt_id: Any,
        prev_hash: Any,
        receipt_verified: bool,
        extra: str = "",
    ) -> str:
        lines = [
            f"[{status}] airlock-sandbox",
            f"verdict={verdict} status={step_status}",
        ]
        if reason:
            lines.append(f"reason={reason}")
        if rules:
            lines.append("rules=" + ",".join(str(r) for r in rules))
        if receipt_id:
            lines.append(f"receipt_id={receipt_id}")
        if prev_hash:
            lines.append(f"prev_hash={prev_hash} (informational; chain not verified here)")
        lines.append(f"receipt_verified={str(receipt_verified).lower()}")
        if extra:
            lines.append(extra)
        return "\n".join(lines)

    @staticmethod
    def _result(output: str, exit_code: int) -> dict[str, Any]:
        return {"output": output, "returncode": exit_code, "exit_code": exit_code}

    def cleanup(self) -> None:
        with self._lock:
            self._last_receipt = None

    def get_temp_dir(self) -> str:
        return "/tmp"
