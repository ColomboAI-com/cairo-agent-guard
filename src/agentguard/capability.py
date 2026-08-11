"""Mission-bound AGP capability tokens."""

from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Callable, Mapping, Sequence

from .token_codec import (
    TokenError,
    decode_segment,
    encode_segment,
    sign_hmac_sha256,
    verify_hmac_sha256,
)


def _b64decode(value: str) -> bytes:
    return decode_segment(value, error_message="invalid capability encoding")


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _datetime(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except (TypeError, ValueError) as exc:
        raise TokenError("invalid capability timestamp") from exc


@dataclass(frozen=True, slots=True)
class AgentCapability:
    agp_version: str
    type: str
    capability_id: str
    agent_id: str
    principal_id: str
    mission_id: str
    resources: tuple[str, ...]
    actions: tuple[str, ...]
    max_risk: int
    delegation_depth: int
    parent_capability_id: str | None
    issued_at: str
    expires_at: str
    issuer: str
    key_id: str


class CapabilityAuthority:
    def __init__(
        self,
        *,
        issuer: str,
        signing_keys: Mapping[str, bytes],
        active_key_id: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if active_key_id not in signing_keys:
            raise ValueError("active signing key is missing")
        if any(len(key) < 32 for key in signing_keys.values()):
            raise ValueError("signing keys must contain at least 32 bytes")
        self.issuer = issuer
        self._keys = dict(signing_keys)
        self._active_key_id = active_key_id
        self._clock = clock or (lambda: datetime.now(UTC))

    def issue(
        self,
        *,
        agent_id: str,
        principal_id: str,
        mission_id: str,
        resources: Sequence[str],
        actions: Sequence[str],
        max_risk: int,
        expires_at: datetime,
        delegation_depth: int = 0,
    ) -> str:
        now = self._clock().astimezone(UTC)
        if not resources or not actions:
            raise ValueError("capabilities require resource and action scopes")
        if not 0 <= max_risk <= 100:
            raise ValueError("max_risk must be between 0 and 100")
        if expires_at.astimezone(UTC) <= now:
            raise ValueError("capability expiry must be in the future")
        capability = AgentCapability(
            agp_version="0.1",
            type="AgentCapability",
            capability_id=f"cap_{secrets.token_urlsafe(16)}",
            agent_id=agent_id,
            principal_id=principal_id,
            mission_id=mission_id,
            resources=tuple(resources),
            actions=tuple(actions),
            max_risk=max_risk,
            delegation_depth=delegation_depth,
            parent_capability_id=None,
            issued_at=_iso(now),
            expires_at=_iso(expires_at),
            issuer=self.issuer,
            key_id=self._active_key_id,
        )
        return self._encode_capability(capability)

    def delegate(
        self,
        parent_token: str,
        *,
        child_agent_id: str,
        resources: Sequence[str],
        actions: Sequence[str],
        max_risk: int,
        expires_at: datetime,
    ) -> str:
        parent = self.verify(parent_token)
        child_expiry = expires_at.astimezone(UTC)
        within_parent = (
            parent.delegation_depth > 0
            and bool(resources)
            and bool(actions)
            and set(resources).issubset(parent.resources)
            and set(actions).issubset(parent.actions)
            and 0 <= max_risk
            and max_risk <= parent.max_risk
            and child_expiry > self._clock().astimezone(UTC)
            and child_expiry <= _datetime(parent.expires_at)
        )
        if not within_parent:
            raise ValueError("delegated authority must be a strict subset of parent authority")
        now = self._clock().astimezone(UTC)
        capability = AgentCapability(
            agp_version="0.1",
            type="AgentCapability",
            capability_id=f"cap_{secrets.token_urlsafe(16)}",
            agent_id=child_agent_id,
            principal_id=parent.principal_id,
            mission_id=parent.mission_id,
            resources=tuple(resources),
            actions=tuple(actions),
            max_risk=max_risk,
            delegation_depth=parent.delegation_depth - 1,
            parent_capability_id=parent.capability_id,
            issued_at=_iso(now),
            expires_at=_iso(child_expiry),
            issuer=self.issuer,
            key_id=self._active_key_id,
        )
        return self._encode_capability(capability)

    def _encode_capability(self, capability: AgentCapability) -> str:
        header = {"alg": "HS256", "kid": self._active_key_id, "typ": "AGP-CAP"}
        head = encode_segment(
            json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
        )
        body = encode_segment(
            json.dumps(asdict(capability), sort_keys=True, separators=(",", ":")).encode()
        )
        signature = sign_hmac_sha256(
            self._keys[self._active_key_id], f"{head}.{body}".encode()
        )
        return f"{head}.{body}.{signature}"

    def verify(self, token: str) -> AgentCapability:
        try:
            head, body, signature = token.split(".")
            header = json.loads(_b64decode(head))
            key = self._keys[header["kid"]]
            verify_hmac_sha256(
                key,
                f"{head}.{body}".encode(),
                signature,
                error_message="invalid capability signature",
            )
            raw = json.loads(_b64decode(body))
            raw["resources"] = tuple(raw["resources"])
            raw["actions"] = tuple(raw["actions"])
            capability = AgentCapability(**raw)
        except TokenError:
            raise
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise TokenError("malformed capability") from exc
        if capability.issuer != self.issuer or capability.agp_version != "0.1":
            raise TokenError("untrusted capability issuer or protocol version")
        if _datetime(capability.expires_at) <= self._clock().astimezone(UTC):
            raise TokenError("capability has expired")
        return capability
