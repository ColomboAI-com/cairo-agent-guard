"""Signed AGP identity documents.

The reference implementation uses keyed HMAC signatures so it remains
dependency-free. Production deployments should put signing keys in an HSM or
replace this authority with an asymmetric issuer behind the same interface.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Callable, Mapping


class TokenError(ValueError):
    """Raised when an AGP token cannot be trusted."""


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode(data: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    except Exception as exc:  # pragma: no cover - Python varies by malformed input
        raise TokenError("invalid token encoding") from exc


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except (TypeError, ValueError) as exc:
        raise TokenError("invalid token timestamp") from exc


@dataclass(frozen=True, slots=True)
class AgentIdentity:
    agp_version: str
    type: str
    identity_id: str
    agent_id: str
    principal_id: str
    issuer: str
    issued_at: str
    expires_at: str
    key_id: str


class IdentityAuthority:
    """Issues and verifies compact, signed AgentIdentity documents."""

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

    def issue_identity(
        self, *, agent_id: str, principal_id: str, expires_at: datetime
    ) -> str:
        now = self._clock().astimezone(UTC)
        if expires_at.astimezone(UTC) <= now:
            raise ValueError("identity expiry must be in the future")
        identity = AgentIdentity(
            agp_version="0.1",
            type="AgentIdentity",
            identity_id=f"identity_{secrets.token_urlsafe(16)}",
            agent_id=agent_id,
            principal_id=principal_id,
            issuer=self.issuer,
            issued_at=_timestamp(now),
            expires_at=_timestamp(expires_at),
            key_id=self._active_key_id,
        )
        return self._sign(asdict(identity), self._active_key_id)

    def verify_identity(self, token: str) -> AgentIdentity:
        payload = self._verify(token)
        required = {field.name for field in AgentIdentity.__dataclass_fields__.values()}
        if set(payload) != required or payload.get("type") != "AgentIdentity":
            raise TokenError("invalid AgentIdentity payload")
        identity = AgentIdentity(**payload)
        if identity.agp_version != "0.1" or identity.issuer != self.issuer:
            raise TokenError("untrusted identity issuer or protocol version")
        if _parse_timestamp(identity.expires_at) <= self._clock().astimezone(UTC):
            raise TokenError("identity has expired")
        return identity

    def _sign(self, payload: dict[str, object], key_id: str) -> str:
        header = {"alg": "HS256", "kid": key_id, "typ": "AGP"}
        head = _encode(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
        body = _encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        signature = hmac.new(
            self._keys[key_id], f"{head}.{body}".encode("ascii"), hashlib.sha256
        ).digest()
        return f"{head}.{body}.{_encode(signature)}"

    def _verify(self, token: str) -> dict[str, object]:
        try:
            head, body, signature = token.split(".")
            header = json.loads(_decode(head))
            key_id = header["kid"]
            key = self._keys[key_id]
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            raise TokenError("malformed or unknown token") from exc
        expected = hmac.new(
            key, f"{head}.{body}".encode("ascii"), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected, _decode(signature)):
            raise TokenError("invalid token signature")
        try:
            payload = json.loads(_decode(body))
        except json.JSONDecodeError as exc:
            raise TokenError("invalid token payload") from exc
        if not isinstance(payload, dict):
            raise TokenError("invalid token payload")
        return payload
