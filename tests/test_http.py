import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from agentguard.http import AgentGuardService, create_server
from agentguard.identity import IdentityAuthority
from agentguard.mission import MissionRegistry
from agentguard.audit import AuditLog
from agentguard.capability import CapabilityAuthority
from agentguard.guard import Guard
from agentguard.revocation import RevocationRegistry
from agentguard.runtime import AgentGuardRuntime


NOW = datetime(2026, 8, 10, 20, 30, tzinfo=UTC)
OPERATOR_TOKEN = "test-operator-token-at-least-32-characters"


def test_identity_issue_and_verify_over_http() -> None:
    service = AgentGuardService(
        identities=IdentityAuthority(
            issuer="agp://cairo/identity",
            signing_keys={"root-2026": b"test-signing-key-at-least-32-bytes"},
            active_key_id="root-2026",
            clock=lambda: NOW,
        ),
        operator_token=OPERATOR_TOKEN,
    )
    server = create_server("127.0.0.1", 0, service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        issue = _post(
            f"{base_url}/v1/identities/issue",
            {
                "agent_id": "agp://cairo/support-01",
                "principal_id": "org://acme",
                "expires_at": "2026-08-10T20:45:00Z",
            },
            operator_token=OPERATOR_TOKEN,
        )
        verified = _post(
            f"{base_url}/v1/identities/verify", {"token": issue["token"]}
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

    assert verified["valid"] is True
    assert verified["identity"]["agent_id"] == "agp://cairo/support-01"


def test_capability_authorize_and_revoke_over_http(tmp_path: Path) -> None:
    capabilities = CapabilityAuthority(
        issuer="agp://cairo/capabilities",
        signing_keys={"cap-2026": b"test-capability-key-at-least-32-b"},
        active_key_id="cap-2026",
        clock=lambda: NOW,
    )
    identities = IdentityAuthority(
        issuer="agp://cairo/identity",
        signing_keys={"root-2026": b"test-signing-key-at-least-32-bytes"},
        active_key_id="root-2026",
        clock=lambda: NOW,
    )
    identity_token = identities.issue_identity(
        agent_id="agp://cairo/support-01",
        principal_id="org://acme",
        expires_at=NOW.replace(minute=45),
    )
    child_identity_token = identities.issue_identity(
        agent_id="agp://cairo/support-child",
        principal_id="org://acme",
        expires_at=NOW.replace(minute=45),
    )
    missions = MissionRegistry(tmp_path / "state.db", clock=lambda: NOW)
    missions.register("mission://support-7", "org://acme", NOW.replace(minute=50))
    runtime = AgentGuardRuntime(
        guard=Guard(identities=identities, capabilities=capabilities),
        missions=missions,
        revocations=RevocationRegistry(tmp_path / "state.db", clock=lambda: NOW),
        audit=AuditLog(tmp_path / "audit.jsonl", clock=lambda: NOW),
    )
    service = AgentGuardService(
        identities=identities,
        capabilities=capabilities,
        runtime=runtime,
        operator_token=OPERATOR_TOKEN,
    )
    server = create_server("127.0.0.1", 0, service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        issued = _post(
            f"{base_url}/v1/capabilities/issue",
            {
                "agent_id": "agp://cairo/support-01",
                "principal_id": "org://acme",
                "mission_id": "mission://support-7",
                "resources": ["mcp://crm/read_customer"],
                "actions": ["invoke"],
                "max_risk": 40,
                "expires_at": "2026-08-10T20:45:00Z",
                "delegation_depth": 1,
            },
            operator_token=OPERATOR_TOKEN,
        )
        delegated = _post(
            f"{base_url}/v1/capabilities/delegate",
            {
                "parent_token": issued["token"],
                "child_agent_id": "agp://cairo/support-child",
                "resources": ["mcp://crm/read_customer"],
                "actions": ["invoke"],
                "max_risk": 30,
                "expires_at": "2026-08-10T20:44:00Z",
            },
            operator_token=OPERATOR_TOKEN,
        )
        request_body = {
            "request_id": "req-http-1",
            "agent_id": "agp://cairo/support-01",
            "principal_id": "org://acme",
            "mission_id": "mission://support-7",
            "resource": "mcp://crm/read_customer",
            "action": "invoke",
            "identity_token": identity_token,
            "capability_token": issued["token"],
            "session_id": "session-http",
            "nonce": "nonce-http-request-0001",
            "risk_score": 10,
            "timestamp": "2026-08-10T20:30:00Z",
        }
        allowed = _post(f"{base_url}/v1/authorize", request_body)
        _post(
            f"{base_url}/v1/revocations",
            {
                "subject_type": "capability",
                "subject_id": issued["capability_id"],
                "reason": "operator kill",
            },
            operator_token=OPERATOR_TOKEN,
        )
        denied = _post(f"{base_url}/v1/authorize", request_body)
        child_denied = _post(
            f"{base_url}/v1/authorize",
            {
                **request_body,
                "request_id": "req-http-child",
                "agent_id": "agp://cairo/support-child",
                "identity_token": child_identity_token,
                "capability_token": delegated["token"],
                "session_id": "session-http-child",
                "nonce": "nonce-http-child-0001",
            },
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

    assert allowed["effect"] == "ALLOW"
    assert denied["effect"] == "DENY"
    assert denied["reason"] == "capability is revoked: operator kill"
    assert child_denied["effect"] == "DENY"
    assert child_denied["reason"] == "capability is revoked: operator kill"


def test_authority_endpoint_rejects_missing_operator_authentication() -> None:
    service = AgentGuardService(
        identities=IdentityAuthority(
            issuer="agp://cairo/identity",
            signing_keys={"root-2026": b"test-signing-key-at-least-32-bytes"},
            active_key_id="root-2026",
            clock=lambda: NOW,
        ),
        operator_token=OPERATOR_TOKEN,
    )
    server = create_server("127.0.0.1", 0, service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        try:
            _post(
                f"http://127.0.0.1:{server.server_port}/v1/identities/issue",
                {
                    "agent_id": "agp://cairo/attacker",
                    "principal_id": "org://attacker",
                    "expires_at": "2026-08-10T20:45:00Z",
                },
            )
        except HTTPError as exc:
            assert exc.code == 401
        else:
            raise AssertionError("authority endpoint must require operator authentication")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def _post(
    url: str, body: dict[str, object], *, operator_token: str | None = None
) -> dict[str, object]:
    headers = {"Content-Type": "application/json"}
    if operator_token is not None:
        headers["Authorization"] = f"Bearer {operator_token}"
    request = Request(
        url,
        data=json.dumps(body).encode(),
        headers=headers,
        method="POST",
    )
    with urlopen(request, timeout=2) as response:
        return json.load(response)
