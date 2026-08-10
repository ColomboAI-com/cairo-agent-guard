from datetime import UTC, datetime

from agentguard.certification import CertificationStore


NOW = datetime(2026, 8, 10, 20, 30, tzinfo=UTC)


def test_certification_application_persists_with_review_workflow(tmp_path) -> None:
    database = tmp_path / "certification.db"
    store = CertificationStore(database, clock=lambda: NOW)

    submitted = store.submit(
        organization="Acme AI",
        email="security@acme.example",
        target="Agent Runtime / Harness",
        level="AGP-L3",
        summary="A sandboxed runtime with mediated tools and network egress.",
    )
    reopened = CertificationStore(database, clock=lambda: NOW)
    application = reopened.get(submitted.application_id)

    assert application.organization == "Acme AI"
    assert application.level == "AGP-L3"
    assert application.status == "SUBMITTED"
    assert application.workflow_stage == "EVIDENCE_REVIEW"
