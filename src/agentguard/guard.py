"""Deterministic Agent Guard authorization kernel."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from fnmatch import fnmatchcase

from .capability import AgentCapability, CapabilityAuthority
from .identity import AgentIdentity, IdentityAuthority, TokenError


class Effect(StrEnum):
    ALLOW = "ALLOW"
    ALLOW_WITH_LIMITS = "ALLOW_WITH_LIMITS"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    SANITIZE = "SANITIZE"
    REDIRECT = "REDIRECT"
    RATE_LIMIT = "RATE_LIMIT"
    ISOLATE = "ISOLATE"
    QUARANTINE = "QUARANTINE"
    DENY = "DENY"
    TERMINATE = "TERMINATE"


@dataclass(frozen=True, slots=True)
class AgentRequest:
    request_id: str
    agent_id: str
    principal_id: str
    mission_id: str
    resource: str
    action: str
    identity_token: str
    capability_token: str
    session_id: str
    nonce: str
    risk_score: int
    timestamp: datetime


@dataclass(frozen=True, slots=True)
class AgentDecision:
    effect: Effect
    reason: str
    request_id: str
    capability_id: str | None = None


class Guard:
    def __init__(
        self, *, identities: IdentityAuthority, capabilities: CapabilityAuthority
    ) -> None:
        self._identities = identities
        self._capabilities = capabilities

    def verify_identity(self, token: str) -> AgentIdentity:
        return self._identities.verify_identity(token)

    def verify_capability(self, token: str) -> AgentCapability:
        return self._capabilities.verify(token)

    def evaluate(self, request: AgentRequest) -> AgentDecision:
        try:
            identity = self._identities.verify_identity(request.identity_token)
            capability = self._capabilities.verify(request.capability_token)
        except TokenError as exc:
            return AgentDecision(Effect.DENY, str(exc), request.request_id)
        if not 0 <= request.risk_score <= 100:
            return AgentDecision(Effect.DENY, "risk score is outside 0..100", request.request_id)
        matches = (
            identity.agent_id == request.agent_id
            and identity.principal_id == request.principal_id
            and capability.agent_id == request.agent_id
            and capability.principal_id == request.principal_id
            and capability.mission_id == request.mission_id
            and request.action in capability.actions
            and any(fnmatchcase(request.resource, pattern) for pattern in capability.resources)
            and request.risk_score <= capability.max_risk
        )
        if not matches:
            return AgentDecision(
                Effect.DENY,
                "request is outside the capability boundary",
                request.request_id,
                capability.capability_id,
            )
        if request.risk_score >= 91:
            return AgentDecision(
                Effect.TERMINATE,
                "risk threshold requires termination",
                request.request_id,
                capability.capability_id,
            )
        if request.risk_score >= 71:
            return AgentDecision(
                Effect.QUARANTINE,
                "risk threshold requires quarantine",
                request.request_id,
                capability.capability_id,
            )
        if request.risk_score >= 51:
            return AgentDecision(
                Effect.REQUIRE_APPROVAL,
                "risk threshold requires human authorization",
                request.request_id,
                capability.capability_id,
            )
        return AgentDecision(
            Effect.ALLOW,
            "authorized by mission-bound capability",
            request.request_id,
            capability.capability_id,
        )
