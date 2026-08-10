"""Python SDK for an Agent Guard daemon."""

from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class AgentGuardAPIError(RuntimeError):
    pass


class AgentGuardClient:
    def __init__(
        self,
        base_url: str,
        *,
        operator_token: str | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.operator_token = operator_token
        self.timeout = timeout

    def issue_identity(
        self, *, agent_id: str, principal_id: str, expires_at: str
    ) -> dict[str, Any]:
        return self._post(
            "/v1/identities/issue",
            {"agent_id": agent_id, "principal_id": principal_id, "expires_at": expires_at},
        )

    def verify_identity(self, token: str) -> dict[str, Any]:
        return self._post("/v1/identities/verify", {"token": token})

    def issue_capability(self, **capability: object) -> dict[str, Any]:
        return self._post("/v1/capabilities/issue", capability)

    def delegate_capability(self, **delegation: object) -> dict[str, Any]:
        return self._post("/v1/capabilities/delegate", delegation)

    def authorize(self, request: dict[str, object]) -> dict[str, Any]:
        return self._post("/v1/authorize", request)

    def revoke(self, *, subject_type: str, subject_id: str, reason: str) -> dict[str, Any]:
        return self._post(
            "/v1/revocations",
            {"subject_type": subject_type, "subject_id": subject_id, "reason": reason},
        )

    def register_delegation(self, *, parent_agent_id: str, child_agent_id: str) -> dict[str, Any]:
        return self._post(
            "/v1/delegations",
            {"parent_agent_id": parent_agent_id, "child_agent_id": child_agent_id},
        )

    def quarantine(self, *, agent_id: str, reason: str) -> dict[str, Any]:
        return self._post("/v1/quarantine", {"agent_id": agent_id, "reason": reason})

    def submit_certification(self, **application: object) -> dict[str, Any]:
        return self._post("/v1/certification/applications", application)

    def register_mission(self, **mission: object) -> dict[str, Any]:
        return self._post("/v1/missions", mission)

    def terminate_mission(self, mission_id: str) -> dict[str, Any]:
        return self._post("/v1/missions/terminate", {"mission_id": mission_id})

    def _post(self, path: str, body: dict[str, object]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json", "AGP-Version": "0.1"}
        if self.operator_token is not None:
            headers["Authorization"] = f"Bearer {self.operator_token}"
        request = Request(
            self.base_url + path,
            data=json.dumps(body).encode(),
            headers=headers,
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.load(response)
        except HTTPError as exc:
            try:
                detail = json.load(exc)
            except Exception:
                detail = {"error": exc.reason}
            raise AgentGuardAPIError(f"Agent Guard API error {exc.code}: {detail}") from exc
