"""Mandatory execution gateway for host runtimes such as Cairo and MCP."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from .guard import AgentRequest, Effect
from .runtime import AgentGuardRuntime


ResultT = TypeVar("ResultT")


class ExecutionDenied(PermissionError):
    pass


class ExecutionGateway:
    """Authorizes an action before allowing its executor to run."""

    def __init__(self, runtime: AgentGuardRuntime) -> None:
        self.runtime = runtime

    def execute(self, request: AgentRequest, executor: Callable[[], ResultT]) -> ResultT:
        decision = self.runtime.authorize(request)
        if decision.effect not in {Effect.ALLOW, Effect.ALLOW_WITH_LIMITS}:
            raise ExecutionDenied(f"{decision.effect.value}: {decision.reason}")
        try:
            result = executor()
        except Exception as exc:
            self.runtime.audit.append(
                "execution.failed",
                {"request_id": request.request_id, "error_type": type(exc).__name__},
            )
            raise
        self.runtime.audit.append(
            "execution.completed",
            {"request_id": request.request_id, "resource": request.resource},
        )
        return result
