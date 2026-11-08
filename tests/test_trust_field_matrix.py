"""Rerunnable trust-field matrix for VERIFIED display.

Premise under test (must remain FALSIFIED if optional signed fields are skipped):

  "A verified receipt plus selected optional field checks is sufficient to
   label the entire returned execution result VERIFIED."

Independent omitted/null ``stderr_sha256`` and float ``exit_code`` repros show
that signature-OK alone must not authorize unbound outer execution fields.

For every field returned to Hermes under VERIFIED, this matrix asserts the value
is derived from exact authenticated typed signed data, or the step is refused /
the field is excluded. No unsigned field inherits a blanket VERIFIED label.
"""

from __future__ import annotations

import copy
import json
from hashlib import sha256
from typing import Any, Callable

import httpx
import jcs
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from airlock_sandbox_plugin.binding import BindingError, bind_step_to_receipt
from airlock_sandbox_plugin.client import AirlockClient
from airlock_sandbox_plugin.config import ConfigError, require_https_base_url
from airlock_sandbox_plugin.environment import EXIT_INVALID_RECEIPT, AirlockEnvironment
from tests.conftest import arena_step_from_receipt, make_receipt

# Fields that appear in the Hermes execute() result under a successful allow.
RETURNED_TRUSTED_FIELDS = (
    "verdict",
    "reason",
    "rules_fired",
    "exit_code",
    "stdout",
    "stderr",
    "status",
    "receipt_id",
)


def _resign(receipt: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    body = {k: v for k, v in receipt.items() if k not in {"hash", "sig_ed25519"}}
    canonical = jcs.canonicalize(body)
    receipt["hash"] = sha256(canonical).hexdigest()
    receipt["sig_ed25519"] = key.sign(canonical).hex()
    return receipt


def _env(step: dict[str, Any], pub: str) -> AirlockEnvironment:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/healthz":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(200, json=step)

    return AirlockEnvironment(
        cwd="/work",
        timeout=10,
        base_url="https://airlock.test",
        public_key_hex=pub,
        verify_receipts=True,
        client_factory=lambda url, **kw: AirlockClient(
            url, transport=httpx.MockTransport(handler), **kw
        ),
    )


def _assert_blocked(result: dict[str, Any], *, must_not_contain: str | None = None) -> None:
    assert result["returncode"] == EXIT_INVALID_RECEIPT
    assert not result["output"].startswith("[VERIFIED]")
    assert not result["output"].startswith("[ALLOWED]")
    if must_not_contain is not None:
        assert must_not_contain not in result["output"]


@pytest.fixture
def signed_pair(signing_key: Ed25519PrivateKey):
    pub = signing_key.public_key().public_bytes_raw().hex()
    receipt = make_receipt(signing_key, stdout="ok\n", stderr="", exit_code=0)
    step = arena_step_from_receipt(receipt, stdout="ok\n", stderr="", exit_code=0, code="echo ok")
    return signing_key, pub, receipt, step


# ── Premise falsifiers (must refuse after boundary fix) ──────────────────────


@pytest.mark.parametrize("mode", ["absent", "null"])
def test_premise_falsifier_optional_stderr_digest(signed_pair, mode: str) -> None:
    """Omitted/null stderr_sha256 must not emit attacker stderr under VERIFIED."""
    key, pub, receipt, _ = signed_pair
    r = copy.deepcopy(receipt)
    if mode == "absent":
        r["execution"].pop("stderr_sha256")
    else:
        r["execution"]["stderr_sha256"] = None
    _resign(r, key)
    step = arena_step_from_receipt(r, stdout="ok\n", stderr="ATTACKER UNSIGNED STDERR\n", code="echo ok")
    result = _env(step, pub).execute("echo ok")
    _assert_blocked(result, must_not_contain="ATTACKER UNSIGNED STDERR")
    assert "stderr_sha256" in result["output"] or "BINDING FAILED" in result["output"]


@pytest.mark.parametrize(
    "bad_exit",
    [0.9, 0.0, True, False, "0", "0.9", None],
)
def test_premise_falsifier_coerced_exit_types(signed_pair, bad_exit: Any) -> None:
    """Float/bool/string exit must not coerce into signed integer 0."""
    _key, pub, receipt, step = signed_pair
    s = copy.deepcopy(step)
    s["execution"]["exit_code"] = bad_exit
    result = _env(s, pub).execute("echo ok")
    _assert_blocked(result)


# ── Full field matrix ────────────────────────────────────────────────────────


def test_matrix_signed_deny_outer_allow_refuses(signed_pair) -> None:
    key, pub, _receipt, _step = signed_pair
    deny = make_receipt(key, verdict="deny", with_execution=False)
    s = arena_step_from_receipt(deny, code="echo ok")
    s["verdict"] = "allow"
    s["status"] = "executed"
    s["execution"] = {"stdout": "x\n", "stderr": "", "exit_code": 0}
    result = _env(s, pub).execute("echo ok")
    _assert_blocked(result)


@pytest.mark.parametrize(
    "field,mutator,attacker_text",
    [
        (
            "stdout",
            lambda s: s["execution"].__setitem__("stdout", "ATTACKER STDOUT\n") or s,
            "ATTACKER STDOUT",
        ),
        (
            "stderr",
            lambda s: s["execution"].__setitem__("stderr", "ATTACKER STDERR\n") or s,
            "ATTACKER STDERR",
        ),
        (
            "exit_code",
            lambda s: s["execution"].__setitem__("exit_code", 37) or s,
            None,
        ),
        (
            "receipt_id",
            lambda s: s.__setitem__("receipt_id", "f" * 64) or s,
            None,
        ),
        (
            "action_id",
            lambda s: s["action"].__setitem__("id", "other-action") or s,
            None,
        ),
        (
            "status",
            lambda s: s.__setitem__("status", "failed") or s,
            None,
        ),
        (
            "execution_absent",
            lambda s: (s.pop("execution", None), s)[1],
            None,
        ),
    ],
)
def test_matrix_outer_tamper_refuses_verified(
    signed_pair,
    field: str,
    mutator: Callable[[dict[str, Any]], Any],
    attacker_text: str | None,
) -> None:
    del field
    _key, pub, _receipt, step = signed_pair
    s = copy.deepcopy(step)
    mutator(s)
    result = _env(s, pub).execute("echo ok")
    _assert_blocked(result, must_not_contain=attacker_text)


@pytest.mark.parametrize(
    "field,mode",
    [
        ("stderr_sha256", "absent"),
        ("stderr_sha256", "null"),
        ("stderr_sha256", "malformed"),
        ("stderr_sha256", "wrong_type"),
        ("stdout_sha256", "absent"),
        ("stdout_sha256", "null"),
        ("stdout_sha256", "malformed"),
        ("stdout_sha256", "wrong_type"),
        ("exit_code", "absent"),
        ("exit_code", "null"),
        ("exit_code", "float"),
        ("exit_code", "bool"),
        ("exit_code", "string"),
        ("execution", "absent"),
        ("execution", "null"),
    ],
)
def test_matrix_signed_field_variants(signed_pair, field: str, mode: str) -> None:
    key, pub, receipt, _ = signed_pair
    r = copy.deepcopy(receipt)
    if field == "execution":
        if mode == "absent":
            r.pop("execution")
        else:
            r["execution"] = None
    else:
        exec_body = r["execution"]
        if mode == "absent":
            exec_body.pop(field, None)
        elif mode == "null":
            exec_body[field] = None
        elif mode == "malformed":
            exec_body[field] = "zz" * 32 if "sha256" in field else "nope"
        elif mode == "wrong_type":
            exec_body[field] = 123 if "sha256" in field else "0"
        elif mode == "float":
            exec_body[field] = 0.0
        elif mode == "bool":
            exec_body[field] = False
        elif mode == "string":
            exec_body[field] = "0"
    _resign(r, key)
    step = arena_step_from_receipt(r, stdout="ok\n", stderr="", exit_code=0, code="echo ok")
    # Keep outer shapes "successful" so only the signed-field defect triggers refusal.
    result = _env(step, pub).execute("echo ok")
    _assert_blocked(result)


@pytest.mark.parametrize(
    "outer_exit",
    [0.9, 0.0, True, False, "0", 1],  # 1 mismatches signed 0
)
def test_matrix_outer_exit_type_and_value(signed_pair, outer_exit: Any) -> None:
    _key, pub, _receipt, step = signed_pair
    s = copy.deepcopy(step)
    s["execution"]["exit_code"] = outer_exit
    result = _env(s, pub).execute("echo ok")
    _assert_blocked(result)


def test_matrix_genuine_unicode_and_nonzero_exit(signing_key: Ed25519PrivateKey) -> None:
    pub = signing_key.public_key().public_bytes_raw().hex()
    out, err, code = "café —\n", "warning\n", 7
    receipt = make_receipt(signing_key, stdout=out, stderr=err, exit_code=code)
    step = arena_step_from_receipt(receipt, stdout=out, stderr=err, exit_code=code, code="echo ok")
    result = _env(step, pub).execute("echo ok")
    assert result["returncode"] == 7
    assert result["output"].startswith("[VERIFIED]")
    assert "café —" in result["output"]
    assert "warning" in result["output"]
    assert "receipt_verified=true" in result["output"]


def test_matrix_genuine_empty_stderr_requires_empty_digest(signing_key: Ed25519PrivateKey) -> None:
    pub = signing_key.public_key().public_bytes_raw().hex()
    receipt = make_receipt(signing_key, stdout="ok\n", stderr="", exit_code=0)
    assert receipt["execution"]["stderr_sha256"] == sha256(b"").hexdigest()
    step = arena_step_from_receipt(receipt, stdout="ok\n", stderr="", exit_code=0, code="echo ok")
    result = _env(step, pub).execute("echo ok")
    assert result["returncode"] == 0
    assert result["output"].startswith("[VERIFIED]")
    assert "[stderr]" not in result["output"]


def test_bind_unit_accounts_for_returned_fields(signed_pair) -> None:
    _key, _pub, receipt, step = signed_pair
    bound = bind_step_to_receipt(step, receipt, command="echo ok")
    for field in RETURNED_TRUSTED_FIELDS:
        assert field in bound
    assert bound["bound_outputs"] == ("stdout", "stderr", "exit_code")
    assert bound["exit_code"] == 0
    assert bound["stdout"] == "ok\n"
    assert bound["stderr"] == ""


def test_bind_unit_rejects_null_stderr_digest(signed_pair) -> None:
    key, _pub, receipt, step = signed_pair
    r = copy.deepcopy(receipt)
    r["execution"]["stderr_sha256"] = None
    _resign(r, key)
    step = arena_step_from_receipt(r, stdout="ok\n", stderr="", code="echo ok")
    with pytest.raises(BindingError, match="stderr_sha256"):
        bind_step_to_receipt(step, r, command="echo ok")


# ── Config IPv6 / redirects stay covered elsewhere; IPv6 matrix here ─────────


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://[::1]:443", "https://[::1]:443"),
        ("https://[::1]", "https://[::1]"),
        ("https://[::1]:8443", "https://[::1]:8443"),
        ("https://127.0.0.1:443", "https://127.0.0.1:443"),
    ],
)
def test_ipv6_canonical_brackets(url: str, expected: str) -> None:
    assert require_https_base_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://[::1",
        "https://user:pass@[::1]/",
        "https://[::1]?x=1",
        "https://[::1]#frag",
    ],
)
def test_ipv6_malformed_or_unsafe_config_error_no_credential_echo(url: str) -> None:
    with pytest.raises(ConfigError) as ei:
        require_https_base_url(url)
    msg = str(ei.value)
    assert "user:pass" not in msg
    assert "pass@" not in msg
