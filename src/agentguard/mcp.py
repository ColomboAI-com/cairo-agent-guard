"""Reference MCP JSON-RPC enforcement proxy."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .gateway import ExecutionDenied, ExecutionGateway
from .guard import AgentRequest


@dataclass(frozen=True, slots=True)
class MCPContext:
    agent_id: str
    principal_id: str
    mission_id: str
    identity_token: str
    capability_token: str
    session_id: str
    risk_score: int
    timestamp: datetime


class MCPGuardProxy:
    def __init__(self, gateway: ExecutionGateway, *, server_name: str) -> None:
        self.gateway = gateway
        self.server_name = server_name

    def handle(
        self,
        message: dict[str, Any],
        context: MCPContext,
        upstream: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        if message.get("method") != "tools/call":
            return upstream(message)
        message_id = message.get("id")
        params = message.get("params") or {}
        tool_name = params.get("name")
        if not isinstance(tool_name, str) or not tool_name:
            return self._error(message_id, -32602, "invalid tool name", "DENY")
        request = AgentRequest(
            request_id=f"mcp-{message_id}",
            agent_id=context.agent_id,
            principal_id=context.principal_id,
            mission_id=context.mission_id,
            resource=f"mcp://{self.server_name}/{tool_name}",
            action="invoke",
            identity_token=context.identity_token,
            capability_token=context.capability_token,
            session_id=context.session_id,
            nonce=f"mcp-{context.session_id}-{message_id}",
            risk_score=context.risk_score,
            timestamp=context.timestamp,
        )
        try:
            return self.gateway.execute(request, lambda: upstream(message))
        except ExecutionDenied as exc:
            effect = str(exc).split(":", 1)[0]
            return self._error(message_id, -32003, str(exc), effect)

    @staticmethod
    def _error(message_id: object, code: int, message: str, effect: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": message_id,
            "error": {"code": code, "message": message, "data": {"effect": effect}},
        }
