from pathlib import Path


def test_website_uses_durable_certification_api_and_contains_rich_docs() -> None:
    html = Path("website/index.html").read_text(encoding="utf-8")
    app = Path("website/app.js").read_text(encoding="utf-8")
    assert 'id="cert-form"' in html
    assert "v1/certification/applications" in app
    assert "localStorage" not in app
    assert app.count("title:") >= 10
    assert "CairoExecutionGateway.beforeToolCall" in app
