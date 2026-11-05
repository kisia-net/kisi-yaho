"""Read-only client for the Wazuh Server API (:55000)."""

from __future__ import annotations

import time
from typing import Any

import requests


class WazuhServerAPIError(RuntimeError):
    pass


class WazuhServerAPIClient:
    def __init__(
        self,
        base_url: str,
        *,
        username: str,
        password: str,
        verify_tls: bool = True,
        timeout: float = 10.0,
        token_ttl: int = 840,
        session: requests.Session | None = None,
    ):
        self.base_url = str(base_url or "").rstrip("/")
        self.username = str(username or "")
        self.password = str(password or "")
        self.verify_tls = bool(verify_tls)
        self.timeout = float(timeout)
        self.token_ttl = max(60, int(token_ttl))
        self.session = session or requests.Session()

        self._token = ""
        self._token_created = 0.0

        if not self.base_url:
            raise ValueError("Wazuh Server API URL is required")

        if not self.username or not self.password:
            raise ValueError("Wazuh Server API credentials are required")

    def _token_valid(self) -> bool:
        if not self._token:
            return False

        return (
            time.monotonic() - self._token_created
            < self.token_ttl
        )

    def authenticate(self, *, force: bool = False) -> str:
        if not force and self._token_valid():
            return self._token

        url = (
            f"{self.base_url}"
            "/security/user/authenticate?raw=true"
        )

        try:
            response = self.session.post(
                url,
                auth=(self.username, self.password),
                timeout=self.timeout,
                verify=self.verify_tls,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise WazuhServerAPIError(
                f"Wazuh API authentication failed: {exc}"
            ) from exc

        token = response.text.strip()

        if not token or token.count(".") < 2:
            raise WazuhServerAPIError(
                "Wazuh API returned an invalid JWT"
            )

        self._token = token
        self._token_created = time.monotonic()
        return token

    def get(
        self,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        endpoint = "/" + endpoint.lstrip("/")
        url = f"{self.base_url}{endpoint}"

        token = self.authenticate()

        try:
            response = self.session.get(
                url,
                params=params,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
                timeout=self.timeout,
                verify=self.verify_tls,
            )

            if response.status_code == 401:
                token = self.authenticate(force=True)

                response = self.session.get(
                    url,
                    params=params,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/json",
                    },
                    timeout=self.timeout,
                    verify=self.verify_tls,
                )

            response.raise_for_status()
            payload = response.json()

        except requests.RequestException as exc:
            raise WazuhServerAPIError(
                f"Wazuh API request failed for {endpoint}: {exc}"
            ) from exc
        except ValueError as exc:
            raise WazuhServerAPIError(
                f"Wazuh API returned invalid JSON for {endpoint}"
            ) from exc

        if not isinstance(payload, dict):
            raise WazuhServerAPIError(
                f"Unexpected Wazuh API payload for {endpoint}"
            )

        if payload.get("error") not in (None, 0):
            raise WazuhServerAPIError(
                f"Wazuh API error for {endpoint}: "
                f"{payload.get('message', payload)}"
            )

        return payload

    def agents(self) -> dict[str, Any]:
        return self.get(
            "/agents",
            params={"limit": 100},
        )

    def manager_status(self) -> dict[str, Any]:
        return self.get("/manager/status")

    def agent_os(self, agent_id: str) -> dict[str, Any]:
        return self.get(
            f"/syscollector/{agent_id}/os"
        )

    def health(self) -> dict[str, Any]:
        try:
            manager = self.manager_status()
            agents = self.agents()
        except WazuhServerAPIError as exc:
            return {
                "reachable": False,
                "error": str(exc),
            }

        items = (
            agents
            .get("data", {})
            .get("affected_items", [])
        )

        endpoints = [
            item for item in items
            if isinstance(item, dict)
            and item.get("id") != "000"
        ]

        active = sum(
            1 for item in endpoints
            if item.get("status") == "active"
        )

        return {
            "reachable": True,
            "manager": manager.get("data", {}),
            "agents": {
                "total": len(endpoints),
                "active": active,
            },
        }
