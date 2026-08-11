"""Canonical compact-token encoding and HMAC verification."""

from __future__ import annotations

import base64
import hashlib
import hmac


class TokenError(ValueError):
    """Raised when an AGP token cannot be trusted."""


def encode_segment(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_segment(value: str, *, error_message: str) -> bytes:
    try:
        decoded = base64.b64decode(
            (value + "=" * (-len(value) % 4)).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except Exception as exc:  # pragma: no cover - Python varies by malformed input
        raise TokenError(error_message) from exc
    if encode_segment(decoded) != value:
        raise TokenError(error_message)
    return decoded


def sign_hmac_sha256(key: bytes, message: bytes) -> str:
    return encode_segment(hmac.new(key, message, hashlib.sha256).digest())


def verify_hmac_sha256(
    key: bytes,
    message: bytes,
    encoded_signature: str,
    *,
    error_message: str,
) -> None:
    try:
        presented = decode_segment(encoded_signature, error_message=error_message)
    except TokenError as exc:
        raise TokenError(error_message) from exc
    expected = hmac.new(key, message, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, presented):
        raise TokenError(error_message)
