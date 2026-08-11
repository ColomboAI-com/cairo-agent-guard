from pathlib import Path


def test_website_uses_durable_certification_api_and_contains_rich_docs() -> None:
    html = Path("website/index.html").read_text(encoding="utf-8")
    app = Path("website/app.js").read_text(encoding="utf-8")
    assert 'id="cert-form"' in html
    assert "v1/certification/applications" in app
    assert "localStorage" not in app
    assert app.count("title:") >= 10
    assert "CairoExecutionGateway.beforeToolCall" in app


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
