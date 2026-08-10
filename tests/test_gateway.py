from datetime import UTC, datetime, timedelta

import pytest

from agentguard.audit import AuditLog
from agentguard.capability import CapabilityAuthority
from agentguard.gateway import ExecutionDenied, ExecutionGateway
from agentguard.guard import AgentRequest, Guard
from agentguard.identity import IdentityAuthority
from agentguard.mission import MissionRegistry
from agentguard.revocation import RevocationRegistry
from agentguard.runtime import AgentGuardRuntime


NOW = datetime(2026, 8, 10, 20, 30, tzinfo=UTC)


def test_denied_tool_call_never_reaches_executor(tmp_path) -> None:
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
        agent_id="agp://cairo/reader",
        principal_id="org://acme",
        expires_at=NOW + timedelta(minutes=15),
    )
    token = capabilities.issue(
        agent_id="agp://cairo/reader",
        principal_id="org://acme",
        mission_id="mission://read-only",
        resources=["mcp://crm/read_customer"],
        actions=["invoke"],
        max_risk=40,
        expires_at=NOW + timedelta(minutes=10),
    )
    missions = MissionRegistry(tmp_path / "state.db", clock=lambda: NOW)
    missions.register("mission://read-only", "org://acme", NOW + timedelta(minutes=20))
    runtime = AgentGuardRuntime(
        guard=Guard(identities=identities, capabilities=capabilities),
        missions=missions,
        revocations=RevocationRegistry(tmp_path / "state.db", clock=lambda: NOW),
        audit=AuditLog(tmp_path / "audit.jsonl", clock=lambda: NOW),
    )
    gateway = ExecutionGateway(runtime)
    called = False

    def destructive_tool() -> str:
        nonlocal called
        called = True
        return "deleted"

    with pytest.raises(ExecutionDenied, match="outside the capability"):
        gateway.execute(
            AgentRequest(
                request_id="req-delete",
                agent_id="agp://cairo/reader",
                principal_id="org://acme",
                mission_id="mission://read-only",
                resource="mcp://crm/delete_customer",
                action="invoke",
                identity_token=identity_token,
                capability_token=token,
                session_id="session-gateway",
                nonce="nonce-gateway-0001",
                risk_score=10,
                timestamp=NOW,
            ),
            destructive_tool,
        )

    assert called is False
