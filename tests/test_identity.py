from datetime import UTC, datetime, timedelta

import pytest

from agentguard.identity import IdentityAuthority, TokenError


def test_signed_identity_can_be_verified_but_not_tampered_with() -> None:
    now = datetime(2026, 8, 10, 20, 30, tzinfo=UTC)
    authority = IdentityAuthority(
        issuer="agp://cairo/identity",
        signing_keys={"root-2026": b"test-signing-key-at-least-32-bytes"},
        active_key_id="root-2026",
        clock=lambda: now,
    )

    token = authority.issue_identity(
        agent_id="agp://cairo/support-01",
        principal_id="org://acme",
        expires_at=now + timedelta(minutes=15),
    )

    verified = authority.verify_identity(token)
    assert verified.agent_id == "agp://cairo/support-01"
    assert verified.principal_id == "org://acme"
    assert verified.issuer == "agp://cairo/identity"

    head, payload, signature = token.split(".")
    with pytest.raises(TokenError, match="signature"):
        authority.verify_identity(f"{head}.{payload}.{signature[:-1]}A")
