"""Test bootstrap: import the plugin directory as package ``airlock_sandbox_plugin``.

Mirrors Hermes directory-plugin loading so relative imports resolve. Also provides
ephemeral Ed25519 keys and signed receipt helpers for fail-closed tests.
"""

from __future__ import annotations

import importlib
import sys
import types
from hashlib import sha256
from pathlib import Path
from typing import Any

import jcs
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PACKAGE = "airlock_sandbox_plugin"
_ROOT = Path(__file__).resolve().parents[1]

sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != _ROOT]


def _ensure_terminal_provider_stub() -> None:
    try:
        import agent.terminal_env_provider  # noqa: F401
        return
    except ModuleNotFoundError:
        pass
    stub = types.ModuleType("agent")
    tep = types.ModuleType("agent.terminal_env_provider")

    class TerminalEnvironmentProvider:
        is_remote = True
        is_container = True
        session_isolated_when_nonpersistent = False
        supports_streams = False

        @property
        def skip_container_guards(self):
            return self.is_container

    tep.TerminalEnvironmentProvider = TerminalEnvironmentProvider
    sys.modules["agent"] = stub
    sys.modules["agent.terminal_env_provider"] = tep
    stub.terminal_env_provider = tep


def _load_plugin_package():
    if PACKAGE in sys.modules and f"{PACKAGE}.environment" in sys.modules:
        return sys.modules[PACKAGE]

    _ensure_terminal_provider_stub()

    pkg = types.ModuleType(PACKAGE)
    pkg.__file__ = str(_ROOT / "__init__.py")
    pkg.__path__ = [str(_ROOT)]
    sys.modules[PACKAGE] = pkg

    for name in ("receipts", "client", "environment", "provider"):
        importlib.import_module(f"{PACKAGE}.{name}")

    # Execute package __init__ (register is not called at import time).
    init_path = _ROOT / "__init__.py"
    code = compile(init_path.read_text(encoding="utf-8"), str(init_path), "exec")
    exec(code, pkg.__dict__)
    return pkg


_load_plugin_package()


class _RepoRootIsNotATestPackage:
    @pytest.hookimpl(tryfirst=True)
    def pytest_collect_directory(self, path, parent):
        if Path(path).resolve() == _ROOT:
            return pytest.Dir.from_parent(parent, path=path)
        return None


def pytest_configure(config):
    if not config.pluginmanager.has_plugin("airlock-sandbox-repo-root"):
        config.pluginmanager.register(_RepoRootIsNotATestPackage(), "airlock-sandbox-repo-root")


@pytest.fixture
def signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def public_key_hex(signing_key: Ed25519PrivateKey) -> str:
    return signing_key.public_key().public_bytes_raw().hex()


def make_receipt(
    signing_key: Ed25519PrivateKey,
    *,
    verdict: str = "allow",
    prev_hash: str | None = "a" * 64,
    action_id: str = "arena-test",
    reason: str = "Safe pattern",
    rules_fired: list[str] | None = None,
    with_execution: bool = True,
) -> dict[str, Any]:
    """Build a minimally shaped, correctly signed Airlock-like receipt."""
    body: dict[str, Any] = {
        "schema_v": 1,
        "receipt_v": 1,
        "task_id": "arena",
        "action_id": action_id,
        "decision": {
            "schema_v": 1,
            "action_id": action_id,
            "verdict": verdict,
            "rules_fired": rules_fired or [],
            "blast_radius": {
                "score": 15,
                "factors": {
                    "fs_write": "tmpfs",
                    "net": "none",
                    "procs": "<=32",
                    "duration": "10s",
                },
            },
            "caps": {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32},
            "policy_sha256": "b" * 64,
            "reason": reason,
        },
        "execution": None,
        "verification": None,
        "cleanup": None,
        "model": None,
        "prev_hash": prev_hash,
    }
    if with_execution and verdict == "allow":
        body["execution"] = {
            "container_name": "airlock-test",
            "image_digest": "sha256:" + ("c" * 64),
            "runtime": "runsc",
            "started": "2026-11-06T00:00:00+00:00",
            "ended": "2026-11-06T00:00:01+00:00",
            "exit_code": 0,
            "killed_by": None,
            "peak_mem_mb": None,
            "stdout_sha256": sha256(b"ok\n").hexdigest(),
            "stderr_sha256": sha256(b"").hexdigest(),
            "artifacts": [],
            "report_invalid": False,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "artifacts_dropped": [],
            "notes": [],
        }
        body["verification"] = {
            "checks": [{"id": "V-EXIT-OK", "pass": True, "detail": None}],
            "secret_scan": "clean",
            "flagged_patterns": [],
        }
        body["cleanup"] = {
            "container_absent": True,
            "network_absent": True,
            "evidence": "gone",
        }

    signed_out = {"hash", "sig_ed25519"}
    canonical = jcs.canonicalize({k: v for k, v in body.items() if k not in signed_out})
    digest = sha256(canonical).hexdigest()
    sig = signing_key.sign(canonical).hex()
    body["hash"] = digest
    body["sig_ed25519"] = sig
    return body


def arena_step_from_receipt(
    receipt: dict[str, Any],
    *,
    stdout: str = "ok\n",
    stderr: str = "",
    exit_code: int = 0,
) -> dict[str, Any]:
    verdict = receipt["decision"]["verdict"]
    step: dict[str, Any] = {
        "action": {"id": receipt["action_id"], "lang": "bash", "code": "echo ok"},
        "verdict": verdict,
        "rules_fired": list(receipt["decision"].get("rules_fired") or []),
        "reason": receipt["decision"].get("reason"),
        "caps": receipt["decision"].get("caps"),
        "status": "executed" if verdict == "allow" else "blocked",
        "receipt_id": receipt["hash"],
        "receipt": receipt,
        "stats": {"attempts": 1, "blocked_by_policy": 0, "ran_in_sandbox": 1, "rejected": 0},
    }
    if verdict == "allow":
        step["execution"] = {
            "runtime": "runsc",
            "exit_code": exit_code,
            "killed_by": None,
            "report_invalid": False,
            "stdout": stdout,
            "stderr": stderr,
            "artifacts": [],
            "artifacts_dropped": [],
            "notes": [],
        }
    return step


@pytest.fixture
def receipt_factory(signing_key: Ed25519PrivateKey):
    def _factory(**kwargs: Any) -> dict[str, Any]:
        return make_receipt(signing_key, **kwargs)

    return _factory
