"""Durable AGP revocation registry."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Callable


class SubjectType(StrEnum):
    IDENTITY = "identity"
    AGENT = "agent"
    SESSION = "session"
    MISSION = "mission"
    CAPABILITY = "capability"
    DELEGATED_SUBTREE = "delegated_subtree"
    CREDENTIAL = "credential"
    NETWORK = "network"
    PHYSICAL_AUTHORITY = "physical_authority"


class RevocationRegistry:
    def __init__(
        self, database: str | Path, *, clock: Callable[[], datetime] | None = None
    ) -> None:
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock or (lambda: datetime.now(UTC))
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS revocations (
                    subject_type TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    revoked_at TEXT NOT NULL,
                    PRIMARY KEY (subject_type, subject_id)
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS capability_delegations (
                    parent_capability_id TEXT NOT NULL,
                    child_capability_id TEXT PRIMARY KEY
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS consumed_requests (
                    request_id TEXT PRIMARY KEY,
                    nonce TEXT NOT NULL UNIQUE,
                    consumed_at TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS delegations (
                    parent_agent_id TEXT NOT NULL,
                    child_agent_id TEXT PRIMARY KEY
                )"""
            )

    def revoke(self, subject_type: str, subject_id: str, *, reason: str) -> None:
        if not subject_type or not subject_id or not reason:
            raise ValueError("revocation subject and reason are required")
        subject_type = SubjectType(subject_type).value
        revoked_at = self._clock().astimezone(UTC).isoformat().replace("+00:00", "Z")
        with closing(self._connect()) as connection, connection:
            connection.execute(
                "INSERT OR REPLACE INTO revocations VALUES (?, ?, ?, ?)",
                (subject_type, subject_id, reason, revoked_at),
            )

    def reason(self, subject_type: str, subject_id: str) -> str | None:
        subject_type = SubjectType(subject_type).value
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT reason FROM revocations WHERE subject_type = ? AND subject_id = ?",
                (subject_type, subject_id),
            ).fetchone()
        return None if row is None else str(row[0])

    def register_delegation(self, parent_agent_id: str, child_agent_id: str) -> None:
        if parent_agent_id == child_agent_id:
            raise ValueError("an agent cannot delegate to itself")
        with closing(self._connect()) as connection, connection:
            connection.execute(
                "INSERT OR REPLACE INTO delegations VALUES (?, ?)",
                (parent_agent_id, child_agent_id),
            )

    def delegated_tree(self, root_agent_id: str) -> list[str]:
        ordered = [root_agent_id]
        seen = {root_agent_id}
        index = 0
        with closing(self._connect()) as connection, connection:
            while index < len(ordered):
                parent = ordered[index]
                index += 1
                rows = connection.execute(
                    "SELECT child_agent_id FROM delegations WHERE parent_agent_id = ? ORDER BY child_agent_id",
                    (parent,),
                ).fetchall()
                for row in rows:
                    child = str(row[0])
                    if child not in seen:
                        seen.add(child)
                        ordered.append(child)
        return ordered

    def register_capability_delegation(
        self, parent_capability_id: str, child_capability_id: str
    ) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                "INSERT OR REPLACE INTO capability_delegations VALUES (?, ?)",
                (parent_capability_id, child_capability_id),
            )

    def capability_tree(self, root_capability_id: str) -> list[str]:
        ordered = [root_capability_id]
        seen = {root_capability_id}
        index = 0
        with closing(self._connect()) as connection, connection:
            while index < len(ordered):
                parent = ordered[index]
                index += 1
                rows = connection.execute(
                    "SELECT child_capability_id FROM capability_delegations WHERE parent_capability_id = ? ORDER BY child_capability_id",
                    (parent,),
                ).fetchall()
                for row in rows:
                    child = str(row[0])
                    if child not in seen:
                        seen.add(child)
                        ordered.append(child)
        return ordered

    def claim_request(self, request_id: str, nonce: str, timestamp: datetime) -> str | None:
        if timestamp.tzinfo is None:
            return "request timestamp must be timezone-aware"
        now = self._clock().astimezone(UTC)
        if abs((now - timestamp.astimezone(UTC)).total_seconds()) > 300:
            return "request timestamp is outside the five-minute window"
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    "INSERT INTO consumed_requests VALUES (?, ?, ?)",
                    (request_id, nonce, now.isoformat()),
                )
        except sqlite3.IntegrityError:
            return "request id or nonce has already been used"
        return None

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database)
