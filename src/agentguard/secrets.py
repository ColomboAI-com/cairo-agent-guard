"""Blind credential execution for operator-registered connectors."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any


class UnknownSecret(KeyError):
    def __str__(self) -> str:
        return str(self.args[0])


Connector = Callable[[str, dict[str, object]], object]
SENSITIVE_KEYS = {"authorization", "api_key", "apikey", "secret", "token"}


class SecretBroker:
    def __init__(self) -> None:
        self._entries: dict[str, tuple[str, Connector]] = {}

    def register(self, name: str, secret: str, connector: Connector) -> None:
        if not name or not secret:
            raise ValueError("secret name and value are required")
        self._entries[name] = (secret, connector)

    def execute(self, name: str, request: dict[str, object]) -> object:
        try:
            secret, connector = self._entries[name]
        except KeyError as exc:
            raise UnknownSecret(f"secret is not registered: {name}") from exc
        response = connector(secret, dict(request))
        return _sanitize(response, secret)


def _sanitize(value: Any, secret: str) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _sanitize(item, secret)
            for key, item in value.items()
            if str(key).lower() not in SENSITIVE_KEYS and item != secret
        }
    if isinstance(value, list):
        return [_sanitize(item, secret) for item in value if item != secret]
    if isinstance(value, tuple):
        return tuple(_sanitize(item, secret) for item in value if item != secret)
    if isinstance(value, str):
        return value.replace(secret, "[REDACTED]")
    return value
