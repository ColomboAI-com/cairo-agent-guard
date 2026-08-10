"""Stateful Agent Guard runtime orchestration."""

from __future__ import annotations

from .audit import AuditLog
from .guard import AgentDecision, AgentRequest, Effect, Guard
from .identity import TokenError
from .mission import MissionRegistry
from .revocation import RevocationRegistry, SubjectType


class AgentGuardRuntime:
    def __init__(
        self,
        *,
        guard: Guard,
        missions: MissionRegistry,
        revocations: RevocationRegistry,
        audit: AuditLog,
    ) -> None:
        self.guard = guard
        self.missions = missions
        self.revocations = revocations
        self.audit = audit

    def authorize(self, request: AgentRequest) -> AgentDecision:
        try:
            identity = self.guard.verify_identity(request.identity_token)
            capability = self.guard.verify_capability(request.capability_token)
        except TokenError:
            identity = None
            capability = None
        revoked: tuple[str, str] | None = None
        subjects = [
            (SubjectType.AGENT, request.agent_id),
            (SubjectType.SESSION, request.session_id),
            (SubjectType.MISSION, request.mission_id),
        ]
        if identity is not None:
            subjects.append((SubjectType.IDENTITY, identity.identity_id))
        if capability is not None:
            subjects.append((SubjectType.CAPABILITY, capability.capability_id))
        if request.resource.startswith("secret://"):
            subjects.append((SubjectType.CREDENTIAL, request.resource.removeprefix("secret://")))
        if request.resource.startswith(("http://", "https://")):
            subjects.append((SubjectType.NETWORK, request.resource))
        if request.resource.startswith("paip://"):
            subjects.append((SubjectType.PHYSICAL_AUTHORITY, request.resource))
        for subject_type, subject_id in subjects:
            reason = self.revocations.reason(subject_type, subject_id)
            if reason is not None:
                revoked = (subject_type, reason)
                break
        mission_reason = self.missions.denial_reason(request.mission_id, request.principal_id)
        replay_reason = None
        if revoked is None and mission_reason is None:
            replay_reason = self.revocations.claim_request(
                request.request_id, request.nonce, request.timestamp
            )
        if revoked is not None:
            decision = AgentDecision(
                Effect.DENY,
                f"{revoked[0]} is revoked: {revoked[1]}",
                request.request_id,
                None if capability is None else capability.capability_id,
            )
        elif mission_reason is not None:
            decision = AgentDecision(Effect.DENY, mission_reason, request.request_id)
        elif replay_reason is not None:
            decision = AgentDecision(Effect.DENY, replay_reason, request.request_id)
        else:
            decision = self.guard.evaluate(request)
        self.audit.append(
            "authorization.decided",
            {
                "request_id": request.request_id,
                "agent_id": request.agent_id,
                "mission_id": request.mission_id,
                "resource": request.resource,
                "action": request.action,
                "effect": decision.effect.value,
                "reason": decision.reason,
                "risk_score": request.risk_score,
            },
        )
        return decision

    def revoke(self, subject_type: str, subject_id: str, *, reason: str) -> None:
        parsed_type = SubjectType(subject_type)
        affected = [subject_id]
        if parsed_type is SubjectType.CAPABILITY:
            affected = self.revocations.capability_tree(subject_id)
        elif parsed_type is SubjectType.DELEGATED_SUBTREE:
            affected = self.revocations.delegated_tree(subject_id)
            parsed_type = SubjectType.AGENT
        for affected_id in affected:
            self.revocations.revoke(parsed_type.value, affected_id, reason=reason)
        self.audit.append(
            "revocation.created",
            {
                "subject_type": parsed_type.value,
                "subject_id": subject_id,
                "affected_subjects": affected,
                "reason": reason,
            },
        )

    def register_delegation(self, parent_agent_id: str, child_agent_id: str) -> None:
        self.revocations.register_delegation(parent_agent_id, child_agent_id)
        self.audit.append(
            "delegation.registered",
            {"parent_agent_id": parent_agent_id, "child_agent_id": child_agent_id},
        )

    def register_capability_delegation(
        self, parent_capability_id: str, child_capability_id: str
    ) -> None:
        self.revocations.register_capability_delegation(
            parent_capability_id, child_capability_id
        )
        self.audit.append(
            "capability.delegation.registered",
            {
                "parent_capability_id": parent_capability_id,
                "child_capability_id": child_capability_id,
            },
        )

    def quarantine(self, root_agent_id: str, *, reason: str) -> list[str]:
        affected = self.revocations.delegated_tree(root_agent_id)
        for agent_id in affected:
            self.revocations.revoke("agent", agent_id, reason=f"quarantine: {reason}")
        self.audit.append(
            "quarantine.propagated",
            {"root_agent_id": root_agent_id, "affected_agents": affected, "reason": reason},
        )
        return affected

    def audit_events(self) -> list[dict[str, object]]:
        return list(self.audit.events())

    def verify_audit_chain(self) -> bool:
        return self.audit.verify()
