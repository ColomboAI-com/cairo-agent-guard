import base64
from datetime import UTC, datetime, timedelta

import pytest

from agentguard.capability import CapabilityAuthority
from agentguard.guard import AgentRequest, Effect, Guard
from agentguard.identity import IdentityAuthority, TokenError


NOW = datetime(2026, 8, 10, 20, 30, tzinfo=UTC)


def identities() -> IdentityAuthority:
    return IdentityAuthority(
        issuer="agp://cairo/identity",
        signing_keys={"root-2026": b"test-signing-key-at-least-32-bytes"},
        active_key_id="root-2026",
        clock=lambda: NOW,
    )


def test_mission_bound_capability_authorizes_matching_request() -> None:
    capabilities = CapabilityAuthority(
        issuer="agp://cairo/capabilities",
        signing_keys={"cap-2026": b"test-capability-key-at-least-32-b"},
        active_key_id="cap-2026",
        clock=lambda: NOW,
    )
    identity_authority = identities()
    identity_token = identity_authority.issue_identity(
        agent_id="agp://cairo/support-01",
        principal_id="org://acme",
        expires_at=NOW + timedelta(minutes=15),
    )
    token = capabilities.issue(
        agent_id="agp://cairo/support-01",
        principal_id="org://acme",
        mission_id="mission://customer-support-7",
        resources=["crm/customer/*"],
        actions=["read"],
        max_risk=40,
        expires_at=NOW + timedelta(minutes=10),
    )
    guard = Guard(identities=identity_authority, capabilities=capabilities)

    decision = guard.evaluate(
        AgentRequest(
            request_id="req-1",
            agent_id="agp://cairo/support-01",
            principal_id="org://acme",
            mission_id="mission://customer-support-7",
            resource="crm/customer/123",
            action="read",
            identity_token=identity_token,
            capability_token=token,
            session_id="session-1",
            nonce="nonce-request-0001",
            risk_score=12,
            timestamp=NOW,
        )
    )

    assert decision.effect is Effect.ALLOW
    assert decision.reason == "authorized by mission-bound capability"


def test_risk_can_only_tighten_an_authorized_decision() -> None:
    capabilities = CapabilityAuthority(
        issuer="agp://cairo/capabilities",
        signing_keys={"cap-2026": b"test-capability-key-at-least-32-b"},
        active_key_id="cap-2026",
        clock=lambda: NOW,
    )
    identity_authority = identities()
    identity_token = identity_authority.issue_identity(
        agent_id="agp://cairo/ops-01",
        principal_id="org://acme",
        expires_at=NOW + timedelta(minutes=15),
    )
    token = capabilities.issue(
        agent_id="agp://cairo/ops-01",
        principal_id="org://acme",
        mission_id="mission://deploy-7",
        resources=["cloud/deployment/*"],
        actions=["update"],
        max_risk=100,
        expires_at=NOW + timedelta(minutes=10),
    )
    guard = Guard(identities=identity_authority, capabilities=capabilities)

    effects = []
    for risk in (20, 55, 75, 95):
        effects.append(
            guard.evaluate(
                AgentRequest(
                    request_id=f"req-{risk}",
                    agent_id="agp://cairo/ops-01",
                    principal_id="org://acme",
                    mission_id="mission://deploy-7",
                    resource="cloud/deployment/api",
                    action="update",
                    identity_token=identity_token,
                    capability_token=token,
                    session_id="session-risk",
                    nonce=f"nonce-request-{risk}",
                    risk_score=risk,
                    timestamp=NOW,
                )
            ).effect
        )

    assert effects == [
        Effect.ALLOW,
        Effect.REQUIRE_APPROVAL,
        Effect.QUARANTINE,
        Effect.TERMINATE,
    ]


def test_delegation_can_only_reduce_parent_authority() -> None:
    capabilities = CapabilityAuthority(
        issuer="agp://cairo/capabilities",
        signing_keys={"cap-2026": b"test-capability-key-at-least-32-b"},
        active_key_id="cap-2026",
        clock=lambda: NOW,
    )
    parent = capabilities.issue(
        agent_id="agp://cairo/parent",
        principal_id="org://acme",
        mission_id="mission://support-4",
        resources=["crm/customer/*", "crm/ticket/*"],
        actions=["read", "update"],
        max_risk=50,
        expires_at=NOW + timedelta(minutes=20),
        delegation_depth=2,
    )

    child = capabilities.delegate(
        parent,
        child_agent_id="agp://cairo/child",
        resources=["crm/ticket/*"],
        actions=["read"],
        max_risk=30,
        expires_at=NOW + timedelta(minutes=10),
    )
    verified = capabilities.verify(child)
    assert verified.parent_capability_id == capabilities.verify(parent).capability_id
    assert verified.delegation_depth == 1

    with pytest.raises(ValueError, match="subset"):
        capabilities.delegate(
            parent,
            child_agent_id="agp://cairo/hostile-child",
            resources=["cloud/admin/*"],
            actions=["delete"],
            max_risk=100,
            expires_at=NOW + timedelta(hours=1),
        )


def test_signed_authority_cannot_be_rebound_to_another_principal() -> None:
    identity_authority = identities()
    capabilities = CapabilityAuthority(
        issuer="agp://cairo/capabilities",
        signing_keys={"cap-2026": b"test-capability-key-at-least-32-b"},
        active_key_id="cap-2026",
        clock=lambda: NOW,
    )
    identity_token = identity_authority.issue_identity(
        agent_id="agp://cairo/agent-1",
        principal_id="org://acme",
        expires_at=NOW + timedelta(minutes=10),
    )
    capability_token = capabilities.issue(
        agent_id="agp://cairo/agent-1",
        principal_id="org://acme",
        mission_id="mission://safe",
        resources=["crm/customer/*"],
        actions=["read"],
        max_risk=40,
        expires_at=NOW + timedelta(minutes=10),
    )

    decision = Guard(
        identities=identity_authority, capabilities=capabilities
    ).evaluate(
        AgentRequest(
            request_id="req-principal-swap",
            agent_id="agp://cairo/agent-1",
            principal_id="org://attacker",
            mission_id="mission://safe",
            resource="crm/customer/1",
            action="read",
            identity_token=identity_token,
            capability_token=capability_token,
            session_id="session-safe",
            nonce="nonce-principal-0001",
            risk_score=10,
            timestamp=NOW,
        )
    )

    assert decision.effect is Effect.DENY
    assert decision.reason == "request is outside the capability boundary"


def test_out_of_range_risk_is_denied() -> None:
    identity_authority = identities()
    capabilities = CapabilityAuthority(
        issuer="agp://cairo/capabilities",
        signing_keys={"cap-2026": b"test-capability-key-at-least-32-b"},
        active_key_id="cap-2026",
        clock=lambda: NOW,
    )
    identity_token = identity_authority.issue_identity(
        agent_id="agp://cairo/agent-1",
        principal_id="org://acme",
        expires_at=NOW + timedelta(minutes=10),
    )
    capability_token = capabilities.issue(
        agent_id="agp://cairo/agent-1",
        principal_id="org://acme",
        mission_id="mission://safe",
        resources=["crm/customer/*"],
        actions=["read"],
        max_risk=100,
        expires_at=NOW + timedelta(minutes=10),
    )
    decision = Guard(identities=identity_authority, capabilities=capabilities).evaluate(
        AgentRequest(
            request_id="req-negative-risk",
            agent_id="agp://cairo/agent-1",
            principal_id="org://acme",
            mission_id="mission://safe",
            resource="crm/customer/1",
            action="read",
            identity_token=identity_token,
            capability_token=capability_token,
            session_id="session-safe",
            nonce="nonce-risk-negative",
            risk_score=-1,
            timestamp=NOW,
        )
    )
    assert decision.effect is Effect.DENY
    assert decision.reason == "risk score is outside 0..100"


def test_capability_rejects_noncanonical_signature_encoding() -> None:
    capabilities = CapabilityAuthority(
        issuer="agp://cairo/capabilities",
        signing_keys={"cap-2026": b"test-capability-key-at-least-32-b"},
        active_key_id="cap-2026",
        clock=lambda: NOW,
    )
    token = capabilities.issue(
        agent_id="agp://cairo/agent-1",
        principal_id="org://acme",
        mission_id="mission://safe",
        resources=["crm/customer/*"],
        actions=["read"],
        max_risk=40,
        expires_at=NOW + timedelta(minutes=10),
    )
    head, payload, signature = token.split(".")
    decoded = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    equivalent = next(
        candidate
        for candidate in alphabet
        if candidate != signature[-1]
        and base64.urlsafe_b64decode(
            signature[:-1] + candidate + "=" * (-len(signature) % 4)
        )
        == decoded
    )

    with pytest.raises(TokenError, match="signature"):
        capabilities.verify(f"{head}.{payload}.{signature[:-1]}{equivalent}")
