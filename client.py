"""HTTP client for the public Airlock API.

Talks only to documented endpoints on a user-configured Airlock deployment:
``/healthz``, ``/api/arena``, ``/api/receipt/{id}``.

Redirects are disabled: a 3xx response fails closed so an HTTPS POST cannot be
replayed onto another origin or downgraded to HTTP with the command body.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

import httpx

from .config import ConfigError, require_https_base_url


class AirlockError(RuntimeError):
    """Transport or API-level failure talking to Airlock."""

    def __init__(self, message: str, *, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class AirlockClient:
    """Thin HTTP wrapper. Fail closed on network / non-2xx / malformed JSON."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout_s: float = 60.0,
        api_token: Optional[str] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        try:
            self.base_url = require_https_base_url(base_url)
        except ConfigError as e:
            raise AirlockError(str(e)) from e
        headers: dict[str, str] = {"accept": "application/json"}
        if api_token:
            headers["authorization"] = f"Bearer {api_token}"
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=httpx.Timeout(timeout_s),
            headers=headers,
            transport=transport,
            # Fail closed: never follow redirects (blocks HTTPS→HTTP downgrade of POST bodies).
            follow_redirects=False,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "AirlockClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = self._client.request(method, path, **kwargs)
        except httpx.HTTPError as e:
            raise AirlockError(f"Airlock unreachable: {e}") from e
        if 300 <= response.status_code < 400:
            # Do not follow; do not forward the body elsewhere.
            raise AirlockError(
                f"Airlock returned redirect HTTP {response.status_code}; "
                "redirects are refused (fail-closed, same-origin HTTPS only)",
                status_code=response.status_code,
            )
        try:
            data = response.json()
        except ValueError as e:
            raise AirlockError(
                f"Airlock returned non-JSON (HTTP {response.status_code})",
                status_code=response.status_code,
            ) from e
        if response.status_code >= 400:
            detail = ""
            if isinstance(data, Mapping):
                detail = str(data.get("detail") or data.get("error") or data)
            raise AirlockError(
                f"Airlock HTTP {response.status_code}: {detail}",
                status_code=response.status_code,
            )
        return data

    def healthz(self) -> dict[str, Any]:
        data = self._request("GET", "/healthz")
        if not isinstance(data, dict) or data.get("ok") is not True:
            raise AirlockError("Airlock /healthz did not report ok=true")
        return data

    def arena(
        self,
        *,
        lang: str,
        code: str,
        input_text: str = "",
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"lang": lang, "code": code}
        # Airlock maps input_text to sandbox file input.txt — not process stdin.
        if input_text != "":
            body["input_text"] = input_text
        data = self._request("POST", "/api/arena", json=body)
        if not isinstance(data, dict):
            raise AirlockError("Airlock /api/arena returned a non-object")
        return data

    def get_receipt_text(self, receipt_id: str) -> str:
        try:
            response = self._client.get(f"/api/receipt/{receipt_id}")
        except httpx.HTTPError as e:
            raise AirlockError(f"Airlock unreachable: {e}") from e
        if 300 <= response.status_code < 400:
            raise AirlockError(
                f"Airlock returned redirect HTTP {response.status_code}; redirects are refused",
                status_code=response.status_code,
            )
        if response.status_code >= 400:
            raise AirlockError(
                f"Airlock HTTP {response.status_code} fetching receipt {receipt_id}",
                status_code=response.status_code,
            )
        return response.text
