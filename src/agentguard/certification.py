"""Durable intake workflow for AGP certification applications."""

from __future__ import annotations

import secrets
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable


LEVELS = {"AGP-L1", "AGP-L2", "AGP-L3", "AGP-L4", "AGP-P"}


@dataclass(frozen=True, slots=True)
class CertificationApplication:
    application_id: str
    organization: str
    email: str
    target: str
    level: str
    summary: str
    status: str
    workflow_stage: str
    submitted_at: str


class CertificationStore:
    def __init__(
        self, database: str | Path, *, clock: Callable[[], datetime] | None = None
    ) -> None:
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock or (lambda: datetime.now(UTC))
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS certification_applications (
                    application_id TEXT PRIMARY KEY,
                    organization TEXT NOT NULL,
                    email TEXT NOT NULL,
                    target TEXT NOT NULL,
                    level TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    status TEXT NOT NULL,
                    workflow_stage TEXT NOT NULL,
                    submitted_at TEXT NOT NULL
                )"""
            )

    def submit(
        self,
        *,
        organization: str,
        email: str,
        target: str,
        level: str,
        summary: str,
    ) -> CertificationApplication:
        values = [organization.strip(), email.strip(), target.strip(), summary.strip()]
        if not all(values) or "@" not in email:
            raise ValueError("organization, valid email, target, and summary are required")
        if level not in LEVELS:
            raise ValueError("unknown certification level")
        application = CertificationApplication(
            application_id=f"cert_{secrets.token_urlsafe(16)}",
            organization=organization.strip(),
            email=email.strip().lower(),
            target=target.strip(),
            level=level,
            summary=summary.strip(),
            status="SUBMITTED",
            workflow_stage="EVIDENCE_REVIEW",
            submitted_at=self._clock().astimezone(UTC).isoformat().replace("+00:00", "Z"),
        )
        with closing(self._connect()) as connection, connection:
            connection.execute(
                "INSERT INTO certification_applications VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(getattr(application, name) for name in application.__dataclass_fields__),
            )
        return application

    def get(self, application_id: str) -> CertificationApplication:
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT * FROM certification_applications WHERE application_id = ?",
                (application_id,),
            ).fetchone()
        if row is None:
            raise KeyError(application_id)
        return CertificationApplication(*row)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database)
