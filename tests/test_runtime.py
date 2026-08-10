from datetime import UTC, datetime, timedelta

from agentguard.audit import AuditLog
from agentguard.capability import CapabilityAuthority
from agentguard.guard import AgentRequest, Effect, Guard
from agentguard.identity import IdentityAuthority
from agentguard.mission import MissionRegistry
from agentguard.revocation import RevocationRegistry
from agentguard.runtime import AgentGuardRuntime


NOW = datetime(2026, 8, 10, 20, 30, tzinfo=UTC)


def identity_authority() -> IdentityAuthority:
    return IdentityAuthority(
        issuer="agp://cairo/identity",
        signing_keys={"root-2026": b"test-signing-key-at-least-32-bytes"},
        active_key_id="root-2026",
        clock=lambda: NOW,
    )


def test_revoked_capability_is_denied_and_recorded_in_tamper_evident_audit(tmp_path) -> None:
    capabilities = CapabilityAuthority(
        issuer="agp://cairo/capabilities",
        signing_keys={"cap-2026": b"test-capability-key-at-least-32-b"},
        active_key_id="cap-2026",
        clock=lambda: NOW,
    )
    identities = identity_authority()
    identity_token = identities.issue_identity(
        agent_id="agp://cairo/billing-01",
        principal_id="org://acme",
        expires_at=NOW + timedelta(minutes=15),
    )
    token = capabilities.issue(
        agent_id="agp://cairo/billing-01",
        principal_id="org://acme",
        mission_id="mission://invoice-9",
        resources=["payments/invoice/*"],
        actions=["propose"],
        max_risk=40,
        expires_at=NOW + timedelta(minutes=10),
    )
    capability_id = capabilities.verify(token).capability_id
    missions = MissionRegistry(tmp_path / "state.db", clock=lambda: NOW)
    missions.register("mission://invoice-9", "org://acme", NOW + timedelta(minutes=20))
    runtime = AgentGuardRuntime(
        guard=Guard(identities=identities, capabilities=capabilities),
        missions=missions,
        revocations=RevocationRegistry(tmp_path / "state.db", clock=lambda: NOW),
        audit=AuditLog(tmp_path / "audit.jsonl", clock=lambda: NOW),
    )
    runtime.revoke("capability", capability_id, reason="incident-17")

    decision = runtime.authorize(
        AgentRequest(
            request_id="req-revoked",
            agent_id="agp://cairo/billing-01",
            principal_id="org://acme",
            mission_id="mission://invoice-9",
            resource="payments/invoice/9",
            action="propose",
            identity_token=identity_token,
            capability_token=token,
            session_id="session-invoice",
            nonce="nonce-invoice-0001",
            risk_score=10,
            timestamp=NOW,
        )
    )

    assert decision.effect is Effect.DENY
    assert decision.reason == "capability is revoked: incident-17"
    assert [event["event_type"] for event in runtime.audit_events()] == [
        "revocation.created",
        "authorization.decided",
    ]
    assert runtime.verify_audit_chain() is True


def test_quarantine_propagates_through_delegated_agent_tree(tmp_path) -> None:
    capabilities = CapabilityAuthority(
        issuer="agp://cairo/capabilities",
        signing_keys={"cap-2026": b"test-capability-key-at-least-32-b"},
        active_key_id="cap-2026",
        clock=lambda: NOW,
    )
    identities = identity_authority()
    identity_token = identities.issue_identity(
        agent_id="agp://cairo/grandchild",
        principal_id="org://acme",
        expires_at=NOW + timedelta(minutes=15),
    )
    token = capabilities.issue(
        agent_id="agp://cairo/grandchild",
        principal_id="org://acme",
        mission_id="mission://ops-4",
        resources=["cloud/status"],
        actions=["read"],
        max_risk=40,
        expires_at=NOW + timedelta(minutes=10),
    )
    missions = MissionRegistry(tmp_path / "state.db", clock=lambda: NOW)
    missions.register("mission://ops-4", "org://acme", NOW + timedelta(minutes=20))
    runtime = AgentGuardRuntime(
        guard=Guard(identities=identities, capabilities=capabilities),
        missions=missions,
        revocations=RevocationRegistry(tmp_path / "state.db", clock=lambda: NOW),
        audit=AuditLog(tmp_path / "audit.jsonl", clock=lambda: NOW),
    )
    runtime.register_delegation("agp://cairo/parent", "agp://cairo/child")
    runtime.register_delegation("agp://cairo/child", "agp://cairo/grandchild")

    affected = runtime.quarantine("agp://cairo/parent", reason="escape signal")
    decision = runtime.authorize(
        AgentRequest(
            request_id="req-grandchild",
            agent_id="agp://cairo/grandchild",
            principal_id="org://acme",
            mission_id="mission://ops-4",
            resource="cloud/status",
            action="read",
            identity_token=identity_token,
            capability_token=token,
            session_id="session-ops",
            nonce="nonce-ops-0000001",
            risk_score=10,
            timestamp=NOW,
        )
    )

    assert affected == [
        "agp://cairo/parent",
        "agp://cairo/child",
        "agp://cairo/grandchild",
    ]
    assert decision.effect is Effect.DENY
    assert decision.reason == "agent is revoked: quarantine: escape signal"


def test_runtime_rejects_replayed_request(tmp_path) -> None:
    capabilities = CapabilityAuthority(
        issuer="agp://cairo/capabilities",
        signing_keys={"cap-2026": b"test-capability-key-at-least-32-b"},
        active_key_id="cap-2026",
        clock=lambda: NOW,
    )
    identities = identity_authority()
    identity_token = identities.issue_identity(
        agent_id="agp://cairo/replay-test",
        principal_id="org://acme",
        expires_at=NOW + timedelta(minutes=15),
    )
    capability_token = capabilities.issue(
        agent_id="agp://cairo/replay-test",
        principal_id="org://acme",
        mission_id="mission://replay-test",
        resources=["crm/status"],
        actions=["read"],
        max_risk=40,
        expires_at=NOW + timedelta(minutes=15),
    )
    missions = MissionRegistry(tmp_path / "state.db", clock=lambda: NOW)
    missions.register("mission://replay-test", "org://acme", NOW + timedelta(minutes=20))
    runtime = AgentGuardRuntime(
        guard=Guard(identities=identities, capabilities=capabilities),
        missions=missions,
        revocations=RevocationRegistry(tmp_path / "state.db", clock=lambda: NOW),
        audit=AuditLog(tmp_path / "audit.jsonl", clock=lambda: NOW),
    )
    request = AgentRequest(
        request_id="req-replay",
        agent_id="agp://cairo/replay-test",
        principal_id="org://acme",
        mission_id="mission://replay-test",
        resource="crm/status",
        action="read",
        identity_token=identity_token,
        capability_token=capability_token,
        session_id="session-replay",
        nonce="nonce-replay-0001",
        risk_score=10,
        timestamp=NOW,
    )

    assert runtime.authorize(request).effect is Effect.ALLOW
    replay = runtime.authorize(request)
    assert replay.effect is Effect.DENY
    assert replay.reason == "request id or nonce has already been used"


def test_terminated_mission_denies_fresh_request(tmp_path) -> None:
    capabilities = CapabilityAuthority(
        issuer="agp://cairo/capabilities",
        signing_keys={"cap-2026": b"test-capability-key-at-least-32-b"},
        active_key_id="cap-2026",
        clock=lambda: NOW,
    )
    identities = identity_authority()
    identity_token = identities.issue_identity(
        agent_id="agp://cairo/mission-test",
        principal_id="org://acme",
        expires_at=NOW + timedelta(minutes=15),
    )
    capability_token = capabilities.issue(
        agent_id="agp://cairo/mission-test",
        principal_id="org://acme",
        mission_id="mission://terminable",
        resources=["crm/status"],
        actions=["read"],
        max_risk=40,
        expires_at=NOW + timedelta(minutes=15),
    )
    missions = MissionRegistry(tmp_path / "state.db", clock=lambda: NOW)
    missions.register("mission://terminable", "org://acme", NOW + timedelta(minutes=20))
    missions.terminate("mission://terminable")
    runtime = AgentGuardRuntime(
        guard=Guard(identities=identities, capabilities=capabilities),
        missions=missions,
        revocations=RevocationRegistry(tmp_path / "state.db", clock=lambda: NOW),
        audit=AuditLog(tmp_path / "audit.jsonl", clock=lambda: NOW),
    )
    decision = runtime.authorize(
        AgentRequest(
            request_id="req-terminated-mission",
            agent_id="agp://cairo/mission-test",
            principal_id="org://acme",
            mission_id="mission://terminable",
            resource="crm/status",
            action="read",
            identity_token=identity_token,
            capability_token=capability_token,
            session_id="session-mission",
            nonce="nonce-mission-0001",
            risk_score=10,
            timestamp=NOW,
        )
    )
    assert decision.effect is Effect.DENY
    assert decision.reason == "mission is not active"
