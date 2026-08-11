import json
from pathlib import Path


def test_website_is_a_full_three_pillar_product_experience() -> None:
    page = Path("website/app/site-client.tsx").read_text(encoding="utf-8")
    layout = Path("website/app/layout.tsx").read_text(encoding="utf-8")

    assert "Agent Identity" in page
    assert "Agent Guard Protocol" in page
    assert "Agent Guard Edge" in page
    assert "Agent Guard Runtime" in page
    assert "Apply for Agent Guard certification" in page
    assert "Cairo Super Agent" in page
    assert "Security infrastructure for the " in page
    assert "<em>Agentic Internet.</em>" in page
    assert "https://cairo.sh/AgentGuard" in layout
    assert "/AgentGuard/og.png" in layout


def test_certification_intake_uses_durable_site_storage() -> None:
    route = Path(
        "website/app/api/certification/applications/route.ts"
    ).read_text(encoding="utf-8")
    schema = Path("website/db/schema.ts").read_text(encoding="utf-8")
    hosting = json.loads(
        Path("website/.openai/hosting.json").read_text(encoding="utf-8")
    )

    assert "certificationApplications" in route
    assert "crypto.randomUUID" in route
    assert "certification_applications" in schema
    assert hosting["d1"] == "DB"
    assert hosting["r2"] is None


def test_repository_presents_identity_protocol_and_edge_as_first_class_pillars() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    identity = Path("docs/IDENTITY-INTEGRATION.md").read_text(encoding="utf-8")
    edge = Path("docs/AGENT-GUARD-EDGE.md").read_text(encoding="utf-8")

    assert "## The three pillars" in readme
    assert "## Agent Identity" in readme
    assert "## Agent Guard Edge" in readme
    assert "Identity is not permission" in identity
    assert "## Identity lifecycle" in identity
    assert "## Edge decision pipeline" in edge
    assert "## Deployment patterns" in edge
    assert "not yet a production-distributed Edge service" in edge
