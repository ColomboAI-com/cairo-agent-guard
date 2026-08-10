"""Dependency-free local Agent Guard HTTP daemon."""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .audit import AuditLog
from .capability import CapabilityAuthority
from .certification import CertificationStore
from .guard import AgentRequest
from .identity import IdentityAuthority, TokenError
from .mission import MissionRegistry
from .revocation import RevocationRegistry
from .runtime import AgentGuardRuntime
from .guard import Guard


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class AgentGuardService:
    def __init__(
        self,
        *,
        identities: IdentityAuthority,
        operator_token: str,
        capabilities: CapabilityAuthority | None = None,
        runtime: AgentGuardRuntime | None = None,
        certifications: CertificationStore | None = None,
    ) -> None:
        self.identities = identities
        self.capabilities = capabilities
        self.runtime = runtime
        self.certifications = certifications
        if len(operator_token) < 32:
            raise ValueError("operator token must contain at least 32 characters")
        self._operator_token = operator_token

    def dispatch(
        self,
        method: str,
        path: str,
        body: dict[str, Any],
        presented_operator_token: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        protected = (
            path.startswith("/v1/identities/issue")
            or path.startswith("/v1/capabilities/")
            or path.startswith("/v1/revocations")
            or path.startswith("/v1/delegations")
            or path.startswith("/v1/quarantine")
            or path.startswith("/v1/missions")
            or path.startswith("/v1/audit")
        )
        if protected and (
            presented_operator_token is None
            or not secrets.compare_digest(presented_operator_token, self._operator_token)
        ):
            return HTTPStatus.UNAUTHORIZED, {"error": "operator authentication required"}
        if method == "GET" and path == "/healthz":
            return HTTPStatus.OK, {"status": "ok", "agp_version": "0.1"}
        if method == "POST" and path == "/v1/identities/issue":
            token = self.identities.issue_identity(
                agent_id=body["agent_id"],
                principal_id=body["principal_id"],
                expires_at=_time(body["expires_at"]),
            )
            return HTTPStatus.CREATED, {"token": token}
        if method == "POST" and path == "/v1/identities/verify":
            try:
                identity = self.identities.verify_identity(body["token"])
            except TokenError as exc:
                return HTTPStatus.UNAUTHORIZED, {"valid": False, "error": str(exc)}
            return HTTPStatus.OK, {"valid": True, "identity": asdict(identity)}
        if method == "POST" and path == "/v1/capabilities/issue":
            if self.capabilities is None:
                return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "capability service unavailable"}
            token = self.capabilities.issue(
                agent_id=body["agent_id"],
                principal_id=body["principal_id"],
                mission_id=body["mission_id"],
                resources=body["resources"],
                actions=body["actions"],
                max_risk=int(body["max_risk"]),
                expires_at=_time(body["expires_at"]),
                delegation_depth=int(body.get("delegation_depth", 0)),
            )
            capability = self.capabilities.verify(token)
            return HTTPStatus.CREATED, {
                "token": token,
                "capability_id": capability.capability_id,
            }
        if method == "POST" and path == "/v1/capabilities/delegate":
            if self.capabilities is None:
                return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "capability service unavailable"}
            token = self.capabilities.delegate(
                body["parent_token"],
                child_agent_id=body["child_agent_id"],
                resources=body["resources"],
                actions=body["actions"],
                max_risk=int(body["max_risk"]),
                expires_at=_time(body["expires_at"]),
            )
            capability = self.capabilities.verify(token)
            if self.runtime is not None:
                parent = self.capabilities.verify(body["parent_token"])
                self.runtime.register_delegation(parent.agent_id, capability.agent_id)
                self.runtime.register_capability_delegation(
                    parent.capability_id, capability.capability_id
                )
            return HTTPStatus.CREATED, {
                "token": token,
                "capability_id": capability.capability_id,
                "parent_capability_id": capability.parent_capability_id,
            }
        if method == "POST" and path == "/v1/authorize":
            if self.runtime is None:
                return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "runtime unavailable"}
            request = AgentRequest(
                request_id=body["request_id"],
                agent_id=body["agent_id"],
                principal_id=body["principal_id"],
                mission_id=body["mission_id"],
                resource=body["resource"],
                action=body["action"],
                identity_token=body["identity_token"],
                capability_token=body["capability_token"],
                session_id=body["session_id"],
                nonce=body["nonce"],
                risk_score=int(body["risk_score"]),
                timestamp=_time(body["timestamp"]),
            )
            decision = self.runtime.authorize(request)
            return HTTPStatus.OK, {
                "effect": decision.effect.value,
                "reason": decision.reason,
                "request_id": decision.request_id,
                "capability_id": decision.capability_id,
            }
        if method == "POST" and path == "/v1/revocations":
            if self.runtime is None:
                return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "runtime unavailable"}
            self.runtime.revoke(
                body["subject_type"], body["subject_id"], reason=body["reason"]
            )
            return HTTPStatus.CREATED, {"revoked": True}
        if method == "POST" and path == "/v1/delegations":
            if self.runtime is None:
                return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "runtime unavailable"}
            self.runtime.register_delegation(body["parent_agent_id"], body["child_agent_id"])
            return HTTPStatus.CREATED, {"registered": True}
        if method == "POST" and path == "/v1/missions":
            if self.runtime is None:
                return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "runtime unavailable"}
            self.runtime.missions.register(
                body["mission_id"], body["principal_id"], _time(body["expires_at"])
            )
            return HTTPStatus.CREATED, {"registered": True, "status": "ACTIVE"}
        if method == "POST" and path == "/v1/missions/terminate":
            if self.runtime is None:
                return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "runtime unavailable"}
            self.runtime.missions.terminate(body["mission_id"])
            return HTTPStatus.OK, {"terminated": True}
        if method == "POST" and path == "/v1/quarantine":
            if self.runtime is None:
                return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "runtime unavailable"}
            affected = self.runtime.quarantine(body["agent_id"], reason=body["reason"])
            return HTTPStatus.OK, {"quarantined": True, "affected_agents": affected}
        if method == "GET" and path == "/v1/audit":
            if self.runtime is None:
                return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "runtime unavailable"}
            return HTTPStatus.OK, {
                "valid_chain": self.runtime.verify_audit_chain(),
                "events": self.runtime.audit_events(),
            }
        if method == "POST" and path == "/v1/certification/applications":
            if self.certifications is None:
                return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "certification intake unavailable"}
            application = self.certifications.submit(
                organization=body["organization"],
                email=body["email"],
                target=body["target"],
                level=body["level"],
                summary=body["summary"],
            )
            return HTTPStatus.CREATED, {
                "application_id": application.application_id,
                "status": application.status,
                "workflow_stage": application.workflow_stage,
            }
        return HTTPStatus.NOT_FOUND, {"error": "route not found"}


def create_server(host: str, port: int, service: AgentGuardService) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self._dispatch({})

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError("request body must be an object")
                self._dispatch(body)
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

        def _dispatch(self, body: dict[str, Any]) -> None:
            authorization = self.headers.get("Authorization", "")
            operator_token = (
                authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else None
            )
            status, response = service.dispatch(
                self.command, self.path, body, operator_token
            )
            self._respond(status, response)

        def _respond(self, status: int, body: dict[str, Any]) -> None:
            encoded = json.dumps(body, sort_keys=True).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: object) -> None:
            return

    return ThreadingHTTPServer((host, port), Handler)


def main() -> None:
    key = os.environ.get("AGENTGUARD_SIGNING_KEY")
    if key is None or len(key.encode()) < 32:
        raise SystemExit("AGENTGUARD_SIGNING_KEY must contain at least 32 bytes")
    operator_token = os.environ.get("AGENTGUARD_OPERATOR_TOKEN")
    if operator_token is None or len(operator_token) < 32:
        raise SystemExit("AGENTGUARD_OPERATOR_TOKEN must contain at least 32 characters")
    issuer = os.environ.get("AGENTGUARD_ISSUER", "agp://cairo/local")
    keys = {"local": key.encode()}
    identities = IdentityAuthority(
        issuer=issuer,
        signing_keys=keys,
        active_key_id="local",
    )
    capabilities = CapabilityAuthority(
        issuer=f"{issuer}/capabilities",
        signing_keys=keys,
        active_key_id="local",
    )
    data_dir = os.environ.get("AGENTGUARD_DATA_DIR", ".agentguard")
    runtime = AgentGuardRuntime(
        guard=Guard(identities=identities, capabilities=capabilities),
        missions=MissionRegistry(os.path.join(data_dir, "state.db")),
        revocations=RevocationRegistry(os.path.join(data_dir, "state.db")),
        audit=AuditLog(os.path.join(data_dir, "audit.jsonl")),
    )
    server = create_server(
        os.environ.get("AGENTGUARD_HOST", "127.0.0.1"),
        int(os.environ.get("AGENTGUARD_PORT", "8787")),
        AgentGuardService(
            identities=identities,
            capabilities=capabilities,
            runtime=runtime,
            certifications=CertificationStore(os.path.join(data_dir, "certification.db")),
            operator_token=operator_token,
        ),
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
