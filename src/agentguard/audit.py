"""Append-only, hash-chained Agent Guard audit events."""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Iterator, Mapping


class AuditLog:
    def __init__(
        self, path: str | Path, *, clock: Callable[[], datetime] | None = None
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()

    def append(self, event_type: str, data: Mapping[str, object]) -> dict[str, object]:
        with self._lock:
            previous_hash = "0" * 64
            for prior_event in self.events():
                previous_hash = str(prior_event["event_hash"])
            event: dict[str, object] = {
                "event_id": f"evt_{secrets.token_urlsafe(12)}",
                "event_type": event_type,
                "timestamp": self._clock().astimezone(UTC).isoformat().replace("+00:00", "Z"),
                "previous_hash": previous_hash,
                "data": dict(data),
            }
            event["event_hash"] = self._hash(event)
            with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
                stream.flush()
        return event

    def events(self) -> Iterator[dict[str, object]]:
        if not self.path.exists():
            return
        with self.path.open(encoding="utf-8") as stream:
            for line in stream:
                if line.strip():
                    yield json.loads(line)

    def verify(self) -> bool:
        with self._lock:
            expected_previous = "0" * 64
            for event in self.events():
                if event.get("previous_hash") != expected_previous:
                    return False
                expected_hash = self._hash(event)
                if event.get("event_hash") != expected_hash:
                    return False
                expected_previous = str(event["event_hash"])
            return True

    @staticmethod
    def _hash(event: Mapping[str, object]) -> str:
        content = {key: value for key, value in event.items() if key != "event_hash"}
        encoded = json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()
