"""HTTP client for the public Airlock API.

Talks only to documented endpoints on an Airlock deployment:
``/healthz``, ``/api/pubkey``, ``/api/arena``, ``/api/receipt/{id}``.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

import httpx

DEFAULT_BASE_URL = "https://45-77-141-253.sslip.io"


class AirlockError(RuntimeError):
    """Transport or API-level failure talking to Airlock."""

    def __init__(self, message: str, *, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class AirlockClient:
    """Thin HTTP wrapper. Fail closed on network / non-2xx / malformed JSON."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        timeout_s: float = 60.0,
        api_token: Optional[str] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        headers: dict[str, str] = {"accept": "application/json"}
        if api_token:
            headers["authorization"] = f"Bearer {api_token}"
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=httpx.Timeout(timeout_s),
            headers=headers,
            transport=transport,
            follow_redirects=True,
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

    def pubkey(self) -> dict[str, Any]:
        data = self._request("GET", "/api/pubkey")
        if not isinstance(data, dict) or not data.get("public_key_hex"):
            raise AirlockError("Airlock /api/pubkey missing public_key_hex")
        return data

    def arena(
        self,
        *,
        lang: str,
        code: str,
        input_text: str = "",
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"lang": lang, "code": code}
        if input_text:
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
        if response.status_code >= 400:
            raise AirlockError(
                f"Airlock HTTP {response.status_code} fetching receipt {receipt_id}",
                status_code=response.status_code,
            )
        return response.text
