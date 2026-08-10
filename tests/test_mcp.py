from datetime import UTC, datetime, timedelta

from agentguard.audit import AuditLog
from agentguard.capability import CapabilityAuthority
from agentguard.gateway import ExecutionGateway
from agentguard.guard import Guard
from agentguard.identity import IdentityAuthority
from agentguard.mission import MissionRegistry
from agentguard.mcp import MCPContext, MCPGuardProxy
from agentguard.revocation import RevocationRegistry
from agentguard.runtime import AgentGuardRuntime


NOW = datetime(2026, 8, 10, 20, 30, tzinfo=UTC)


def test_mcp_proxy_blocks_unauthorized_tool_without_calling_upstream(tmp_path) -> None:
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
        mission_id="mission://crm-read",
        resources=["mcp://crm/read_customer"],
        actions=["invoke"],
        max_risk=40,
        expires_at=NOW + timedelta(minutes=10),
    )
    missions = MissionRegistry(tmp_path / "state.db", clock=lambda: NOW)
    missions.register("mission://crm-read", "org://acme", NOW + timedelta(minutes=20))
    runtime = AgentGuardRuntime(
        guard=Guard(identities=identities, capabilities=capabilities),
        missions=missions,
        revocations=RevocationRegistry(tmp_path / "state.db", clock=lambda: NOW),
        audit=AuditLog(tmp_path / "audit.jsonl", clock=lambda: NOW),
    )
    proxy = MCPGuardProxy(ExecutionGateway(runtime), server_name="crm")
    called = False

    def upstream(message: dict[str, object]) -> dict[str, object]:
        nonlocal called
        called = True
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    response = proxy.handle(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "delete_customer", "arguments": {"id": "123"}},
        },
        MCPContext(
            agent_id="agp://cairo/reader",
            principal_id="org://acme",
            mission_id="mission://crm-read",
            identity_token=identity_token,
            capability_token=token,
            session_id="session-mcp",
            risk_score=10,
            timestamp=NOW,
        ),
        upstream,
    )

    assert called is False
    assert response["error"]["code"] == -32003
    assert response["error"]["data"]["effect"] == "DENY"
