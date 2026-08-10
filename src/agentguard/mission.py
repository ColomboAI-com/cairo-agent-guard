"""Persistent mission lifecycle state."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable


class MissionRegistry:
    def __init__(
        self, database: str | Path, *, clock: Callable[[], datetime] | None = None
    ) -> None:
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock or (lambda: datetime.now(UTC))
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS missions (
                    mission_id TEXT PRIMARY KEY,
                    principal_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL
                )"""
            )

    def register(self, mission_id: str, principal_id: str, expires_at: datetime) -> None:
        if expires_at.tzinfo is None or expires_at.astimezone(UTC) <= self._clock().astimezone(UTC):
            raise ValueError("mission expiry must be timezone-aware and in the future")
        with closing(self._connect()) as connection, connection:
            connection.execute(
                "INSERT OR REPLACE INTO missions VALUES (?, ?, ?, 'ACTIVE')",
                (mission_id, principal_id, expires_at.astimezone(UTC).isoformat()),
            )

    def terminate(self, mission_id: str) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                "UPDATE missions SET status = 'TERMINATED' WHERE mission_id = ?",
                (mission_id,),
            )

    def denial_reason(self, mission_id: str, principal_id: str) -> str | None:
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT principal_id, expires_at, status FROM missions WHERE mission_id = ?",
                (mission_id,),
            ).fetchone()
        if row is None:
            return "mission is not registered"
        if row[0] != principal_id:
            return "mission principal does not match"
        if row[2] != "ACTIVE":
            return "mission is not active"
        if datetime.fromisoformat(str(row[1])).astimezone(UTC) <= self._clock().astimezone(UTC):
            return "mission has expired"
        return None

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database)
