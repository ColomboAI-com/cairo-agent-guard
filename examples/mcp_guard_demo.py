"""Demonstrate that an unauthorized MCP call never reaches its upstream."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from agentguard.audit import AuditLog
from agentguard.capability import CapabilityAuthority
from agentguard.gateway import ExecutionGateway
from agentguard.guard import Guard
from agentguard.identity import IdentityAuthority
from agentguard.mission import MissionRegistry
from agentguard.mcp import MCPContext, MCPGuardProxy
from agentguard.revocation import RevocationRegistry
from agentguard.runtime import AgentGuardRuntime


def main() -> None:
    now = datetime.now(UTC)
    authority = CapabilityAuthority(
        issuer="agp://demo/capabilities",
        signing_keys={"demo": b"demo-only-key-material-32-bytes!!!"},
        active_key_id="demo",
    )
    identities = IdentityAuthority(
        issuer="agp://demo/identity",
        signing_keys={"demo": b"demo-only-identity-key-32-bytes!!"},
        active_key_id="demo",
    )
    identity_token = identities.issue_identity(
        agent_id="agp://demo/reader",
        principal_id="org://demo",
        expires_at=now + timedelta(minutes=5),
    )
    token = authority.issue(
        agent_id="agp://demo/reader",
        principal_id="org://demo",
        mission_id="mission://read-only",
        resources=["mcp://crm/read_customer"],
        actions=["invoke"],
        max_risk=40,
        expires_at=now + timedelta(minutes=5),
    )
    with TemporaryDirectory() as directory:
        state = Path(directory)
        missions = MissionRegistry(state / "state.db")
        missions.register("mission://read-only", "org://demo", now + timedelta(minutes=5))
        runtime = AgentGuardRuntime(
            guard=Guard(identities=identities, capabilities=authority),
            missions=missions,
            revocations=RevocationRegistry(state / "state.db"),
            audit=AuditLog(state / "audit.jsonl"),
        )
        proxy = MCPGuardProxy(ExecutionGateway(runtime), server_name="crm")
        reached_upstream = False

        def upstream(message: dict[str, object]) -> dict[str, object]:
            nonlocal reached_upstream
            reached_upstream = True
            return {"jsonrpc": "2.0", "id": message["id"], "result": {}}

        response = proxy.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "delete_customer", "arguments": {"id": "123"}},
            },
            MCPContext(
                agent_id="agp://demo/reader",
                principal_id="org://demo",
                mission_id="mission://read-only",
                identity_token=identity_token,
                capability_token=token,
                session_id="session-demo",
                risk_score=10,
                timestamp=now,
            ),
            upstream,
        )
        print(response)
        print(f"upstream reached: {reached_upstream}")


if __name__ == "__main__":
    main()
