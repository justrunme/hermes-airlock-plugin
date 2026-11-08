"""Bind an arena HTTP step to a verified receipt's signed fields.

Trust premise (falsified if optional signed fields are skipped):

  "A verified receipt plus selected optional field checks is sufficient to
   label the entire returned execution result VERIFIED."

That premise is false. Airlock's schema leaves some execution digests optional
(e.g. ``stderr_sha256`` may be absent/null). Outer arena stdout/stderr/verdict/
exit_code are unsigned. Any field we return under a VERIFIED label must be
derived from exact authenticated typed signed data, or must be excluded/refused.
Unsigned outer values must not inherit a blanket VERIFIED from signature-OK alone.

Signed material we use (Receipt / Decision / Execution):
  decision.verdict, decision.reason, decision.rules_fired, decision.action_id,
  receipt.action_id, receipt.hash, execution.exit_code (exact JSON int),
  execution.stdout_sha256 (required 64-hex str), execution.stderr_sha256
  (required 64-hex str for VERIFIED — schema-optional, so absent/null refuses),
  execution.report_invalid / stdout_truncated / stderr_truncated.

Not signed / not claimed by VERIFIED:
  command text (outer action.code consistency only), prev_hash chain linkage,
  outer status string beyond requiring ``executed`` on allow.
"""

from __future__ import annotations

import re
from hashlib import sha256
from typing import Any, Mapping

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class BindingError(ValueError):
    """Outer arena step does not match the signed receipt."""


def _sha256_utf8(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def _require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BindingError(f"{name} must be an object")
    return value


def _require_exact_json_int(value: Any, name: str) -> int:
    """Accept only real JSON integers (Python ``int``), not bool/float/str."""
    if isinstance(value, bool) or type(value) is not int:
        raise BindingError(
            f"{name} must be an exact JSON integer "
            f"(not bool/float/string/coerced); got {type(value).__name__}"
        )
    return value


def _require_sha256_hex(value: Any, name: str) -> str:
    """Require a present 64-char lowercase-hex digest string (no coercion)."""
    if value is None:
        raise BindingError(f"{name} is null; refusing unbound trusted output")
    if not isinstance(value, str):
        raise BindingError(f"{name} must be a string hex digest")
    digest = value.strip().lower()
    if not _HEX64.fullmatch(digest):
        raise BindingError(f"{name} must be a 64-character hex digest")
    # Reject mixed-case / whitespace variants that are not exact wire form after normalize:
    # we accept lowercase hex only in the signed body for binding clarity.
    if value != digest:
        raise BindingError(f"{name} must be exactly 64 lowercase hex characters")
    return digest


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise BindingError(f"{name} must be a string")
    return value


def bind_step_to_receipt(
    step: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    command: str,
) -> dict[str, Any]:
    """Return bound fields for display/return, or raise BindingError.

    On success returns only fields accounted for by signed data (or empty
    strings for deny with no execution):
      verdict, reason, rules_fired, action_id, exit_code, stdout, stderr,
      status, receipt_id
    """
    receipt_id = step.get("receipt_id")
    signed_hash = receipt.get("hash")
    if receipt_id is not None and str(receipt_id) != str(signed_hash):
        raise BindingError("receipt_id does not match signed receipt.hash")

    decision = _require_mapping(receipt.get("decision"), "receipt.decision")
    signed_verdict = decision.get("verdict")
    if not isinstance(signed_verdict, str) or signed_verdict not in (
        "allow",
        "deny",
        "require_approval",
    ):
        raise BindingError("signed decision.verdict is missing or unknown")

    action_id = receipt.get("action_id")
    if not isinstance(action_id, str) or not action_id:
        raise BindingError("signed receipt.action_id is missing")
    decision_action_id = decision.get("action_id")
    if decision_action_id != action_id:
        raise BindingError("receipt.action_id does not match decision.action_id")

    outer_action = step.get("action")
    if isinstance(outer_action, Mapping):
        outer_id = outer_action.get("id")
        if outer_id is not None and outer_id != action_id:
            raise BindingError("outer action.id does not match receipt.action_id")
        if "code" in outer_action and outer_action.get("code") != command:
            raise BindingError(
                "outer action.code does not match the command sent "
                "(unsigned consistency check; command text is not in the signed receipt)"
            )

    outer_verdict = step.get("verdict")
    if outer_verdict is not None and outer_verdict != "":
        if not isinstance(outer_verdict, str) or outer_verdict != signed_verdict:
            raise BindingError(
                f"outer verdict {outer_verdict!r} disagrees with signed decision.verdict "
                f"{signed_verdict!r}"
            )

    reason = decision.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise BindingError("signed decision.reason must be a string or null")
    rules_raw = decision.get("rules_fired")
    if rules_raw is None:
        rules: list[str] = []
    else:
        if not isinstance(rules_raw, list) or not all(isinstance(r, str) for r in rules_raw):
            raise BindingError("signed decision.rules_fired must be a list of strings")
        rules = list(rules_raw)

    status = step.get("status")
    status_s = str(status) if status is not None else ""

    if signed_verdict != "allow":
        # Deny / require_approval: signed execution must be absent; do not trust
        # a fabricated outer execution body. Display no execution outputs.
        if receipt.get("execution") is not None:
            raise BindingError("signed deny/require_approval receipt must not carry execution")
        return {
            "verdict": signed_verdict,
            "reason": reason,
            "rules_fired": rules,
            "action_id": action_id,
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "status": status_s or "blocked",
            "receipt_id": str(signed_hash or receipt_id or ""),
            "bound_outputs": (),  # no execution outputs under VERIFIED deny
        }

    # allow — every returned execution output must be digest/int-bound.
    signed_exec = receipt.get("execution")
    if not isinstance(signed_exec, Mapping):
        raise BindingError("signed allow receipt is missing execution")
    outer_exec = step.get("execution")
    if not isinstance(outer_exec, Mapping):
        raise BindingError("outer step is missing execution for an allow decision")
    if status_s != "executed":
        raise BindingError(
            f"outer status {status_s!r} is not 'executed' for an allow decision"
        )

    if signed_exec.get("report_invalid") is True:
        raise BindingError(
            "signed execution.report_invalid=true; refusing to treat output as trusted"
        )
    if signed_exec.get("stdout_truncated") is True or signed_exec.get("stderr_truncated") is True:
        raise BindingError(
            "signed execution reports truncated stdout/stderr; "
            "outer previews cannot be bound to the signed hashes"
        )

    if "exit_code" not in signed_exec:
        raise BindingError("signed execution.exit_code is missing")
    if "exit_code" not in outer_exec:
        raise BindingError("outer execution.exit_code is missing")
    signed_exit = _require_exact_json_int(signed_exec["exit_code"], "signed execution.exit_code")
    outer_exit = _require_exact_json_int(outer_exec["exit_code"], "outer execution.exit_code")
    if signed_exit != outer_exit:
        raise BindingError(
            f"outer exit_code {outer_exit} disagrees with signed execution.exit_code {signed_exit}"
        )

    if "stdout" not in outer_exec or "stderr" not in outer_exec:
        raise BindingError("outer execution.stdout and execution.stderr are required")
    stdout = _require_str(outer_exec["stdout"], "outer execution.stdout")
    stderr = _require_str(outer_exec["stderr"], "outer execution.stderr")

    # Schema marks stderr_sha256 optional; treating "signature OK" as enough to
    # display outer stderr under VERIFIED is the falsified premise. Require a
    # present valid digest for both streams before returning them as trusted.
    if "stdout_sha256" not in signed_exec:
        raise BindingError("signed execution.stdout_sha256 is missing")
    if "stderr_sha256" not in signed_exec:
        raise BindingError(
            "signed execution.stderr_sha256 is absent; refusing VERIFIED with unbound stderr"
        )
    expected_out = _require_sha256_hex(signed_exec["stdout_sha256"], "signed execution.stdout_sha256")
    expected_err = _require_sha256_hex(signed_exec["stderr_sha256"], "signed execution.stderr_sha256")
    if _sha256_utf8(stdout) != expected_out:
        raise BindingError("outer stdout does not match signed execution.stdout_sha256")
    if _sha256_utf8(stderr) != expected_err:
        raise BindingError("outer stderr does not match signed execution.stderr_sha256")

    return {
        "verdict": "allow",
        "reason": reason,
        "rules_fired": rules,
        "action_id": action_id,
        "exit_code": signed_exit,
        "stdout": stdout,
        "stderr": stderr,
        "status": "executed",
        "receipt_id": str(signed_hash or receipt_id or ""),
        "bound_outputs": ("stdout", "stderr", "exit_code"),
    }


def require_outer_execution_for_allow(step: Mapping[str, Any]) -> dict[str, Any]:
    """When verify_receipts is off: still refuse missing/malformed execution on allow.

    No VERIFIED claim is made on this path; exit_code must still be an exact
    JSON integer (no float/bool/string coercion).
    """
    verdict = step.get("verdict")
    verdict_s = str(verdict or "").lower()
    if verdict_s != "allow":
        return {
            "verdict": verdict_s or "deny",
            "reason": step.get("reason"),
            "rules_fired": list(step.get("rules_fired") or []),
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "status": str(step.get("status") or "blocked"),
            "bound_outputs": (),
        }
    status = str(step.get("status") or "")
    if status != "executed":
        raise BindingError(
            f"outer status {status!r} is not 'executed'; refusing success without execution"
        )
    outer_exec = step.get("execution")
    if not isinstance(outer_exec, Mapping):
        raise BindingError("allow response missing execution object")
    if "exit_code" not in outer_exec:
        raise BindingError("execution.exit_code is required")
    exit_code = _require_exact_json_int(outer_exec["exit_code"], "execution.exit_code")
    if "stdout" not in outer_exec or "stderr" not in outer_exec:
        raise BindingError("execution.stdout and execution.stderr must be present")
    stdout = _require_str(outer_exec["stdout"], "execution.stdout")
    stderr = _require_str(outer_exec["stderr"], "execution.stderr")
    return {
        "verdict": "allow",
        "reason": step.get("reason"),
        "rules_fired": list(step.get("rules_fired") or []),
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "status": "executed",
        "bound_outputs": ("stdout", "stderr", "exit_code"),  # unsigned; not VERIFIED
    }
