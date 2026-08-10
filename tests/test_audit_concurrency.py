from datetime import UTC, datetime
from threading import Thread

from agentguard.audit import AuditLog


def test_concurrent_audit_appends_remain_one_valid_chain(tmp_path) -> None:
    audit = AuditLog(
        tmp_path / "audit.jsonl",
        clock=lambda: datetime(2026, 8, 10, 20, 30, tzinfo=UTC),
    )
    threads = [
        Thread(target=audit.append, args=("test.event", {"sequence": sequence}))
        for sequence in range(20)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(list(audit.events())) == 20
    assert audit.verify() is True
