"""Airlock receipt verification: RFC 8785 JCS, SHA-256, Ed25519.

Implements the public verification contract used by Airlock's own verifier
(strict JSON, canonical body excluding hash/sig, SHA-256, Ed25519). Optional
``expected_prev_hash`` can enforce a single prev link when the caller already
knows the accurate predecessor; this plugin does not maintain a shared-server
chain itself. Does not depend on the Airlock Python package.
"""

from __future__ import annotations

import json
import math
import re
from hashlib import sha256
from typing import Any, Mapping, Optional

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_SAFE_INT = 2**53
HASH_RE = re.compile(r"[0-9a-f]{64}")
SIG_RE = re.compile(r"[0-9a-f]{128}")
SIGNED_OUT = frozenset({"hash", "sig_ed25519"})


class ReceiptError(ValueError):
    """Base class for receipt parse / verify failures."""


class ReceiptFormatError(ReceiptError):
    """The document is not a strictly valid receipt."""


class ReceiptHashError(ReceiptError):
    """Stored hash is not SHA-256 of the canonical signed payload."""


class ReceiptSignatureError(ReceiptError):
    """Ed25519 signature does not verify under the given public key."""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ReceiptFormatError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    raise ReceiptFormatError(f"non-finite number {name}")


def _parse_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise ReceiptFormatError(f"number out of range: {token[:32]}")
    if value == 0 and token.startswith("-"):
        raise ReceiptFormatError("negative zero is not allowed")
    return value


def _parse_int(token: str) -> int:
    if token == "-0":
        raise ReceiptFormatError("negative zero is not allowed")
    return int(token)


def _check_ints(value: Any, where: str = "$") -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, int) and not -MAX_SAFE_INT <= value <= MAX_SAFE_INT:
        raise ReceiptFormatError(f"integer out of range at {where}")
    if isinstance(value, dict):
        for k, v in value.items():
            _check_ints(v, f"{where}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _check_ints(v, f"{where}[{i}]")


def parse_strict_json(text: str) -> Any:
    """Parse JSON rejecting duplicate keys, NaN/Infinity and unsafe integers."""
    try:
        data = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
            parse_float=_parse_float,
            parse_int=_parse_int,
        )
    except ReceiptFormatError:
        raise
    except ValueError as e:
        raise ReceiptFormatError(f"invalid JSON: {e}") from e
    _check_ints(data)
    return data


def canonical_json(data: Mapping[str, Any]) -> bytes:
    """Produce RFC 8785 JCS canonical JSON bytes."""
    return jcs.canonicalize(dict(data))


def signed_payload(receipt_dict: Mapping[str, Any]) -> bytes:
    """Canonical bytes covered by the hash and signature."""
    body = {k: v for k, v in receipt_dict.items() if k not in SIGNED_OUT}
    return canonical_json(body)


def hash_data(data: bytes) -> str:
    return sha256(data).hexdigest()


def public_key_from_hex(public_key_hex: str) -> Ed25519PublicKey:
    raw = (public_key_hex or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", raw):
        raise ReceiptFormatError("public_key_hex must be 64 lowercase hex characters")
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(raw))


def _require_receipt_shape(raw: Mapping[str, Any]) -> None:
    for field in ("schema_v", "receipt_v", "task_id", "action_id", "decision", "hash", "sig_ed25519"):
        if field not in raw:
            raise ReceiptFormatError(f"missing field {field!r}")
    if not isinstance(raw["decision"], dict):
        raise ReceiptFormatError("decision must be an object")
    if "verdict" not in raw["decision"]:
        raise ReceiptFormatError("decision.verdict is required")
    if not isinstance(raw["hash"], str) or not HASH_RE.fullmatch(raw["hash"]):
        raise ReceiptFormatError("hash must be 64 lowercase hex characters")
    if not isinstance(raw["sig_ed25519"], str) or not SIG_RE.fullmatch(raw["sig_ed25519"]):
        raise ReceiptFormatError("sig_ed25519 must be 128 lowercase hex characters")
    prev = raw.get("prev_hash")
    if prev is not None and (not isinstance(prev, str) or not HASH_RE.fullmatch(prev)):
        raise ReceiptFormatError("prev_hash must be null or 64 lowercase hex characters")


def verify_receipt(
    receipt: Mapping[str, Any] | str,
    public_key_hex: str,
    *,
    expected_prev_hash: Optional[str] = None,
) -> dict[str, Any]:
    """Parse and cryptographically verify a receipt. Returns the receipt dict.

    Fail-closed: any format, hash, signature, or prev_hash mismatch raises.
    """
    if isinstance(receipt, str):
        raw_obj = parse_strict_json(receipt)
        if not isinstance(raw_obj, dict):
            raise ReceiptFormatError("receipt must be a JSON object")
        raw: dict[str, Any] = raw_obj
    else:
        # Re-roundtrip through strict JSON so duplicate-key / type rules apply.
        raw = parse_strict_json(json.dumps(dict(receipt), separators=(",", ":")))
        if not isinstance(raw, dict):
            raise ReceiptFormatError("receipt must be a JSON object")

    _require_receipt_shape(raw)
    if expected_prev_hash is not None and raw.get("prev_hash") != expected_prev_hash:
        raise ReceiptFormatError(
            f"prev_hash mismatch: expected {expected_prev_hash}, got {raw.get('prev_hash')}"
        )

    canonical = signed_payload(raw)
    if hash_data(canonical) != raw["hash"]:
        raise ReceiptHashError("hash does not match the signed payload")

    key = public_key_from_hex(public_key_hex)
    try:
        key.verify(bytes.fromhex(raw["sig_ed25519"]), canonical)
    except Exception as e:
        raise ReceiptSignatureError("signature does not verify") from e
    return raw


def status_from_step(step: Mapping[str, Any], *, receipt_verified: bool) -> str:
    """Map an Airlock arena step to BLOCKED / ALLOWED / VERIFIED.

    VERIFIED is reserved for a receipt whose hash and signature checked out.
    BLOCKED means the policy denied before execution. ALLOWED means the gate
    passed (sandbox may or may not have run).
    """
    if receipt_verified:
        return "VERIFIED"
    verdict = str(step.get("verdict") or "").lower()
    if verdict and verdict != "allow":
        return "BLOCKED"
    if verdict == "allow":
        return "ALLOWED"
    return "BLOCKED"
