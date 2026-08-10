import threading
from datetime import UTC, datetime

from agentguard.client import AgentGuardClient
from agentguard.http import AgentGuardService, create_server
from agentguard.identity import IdentityAuthority


NOW = datetime(2026, 8, 10, 20, 30, tzinfo=UTC)
OPERATOR_TOKEN = "test-operator-token-at-least-32-characters"


def test_python_client_verifies_agent_identity() -> None:
    service = AgentGuardService(
        identities=IdentityAuthority(
            issuer="agp://cairo/identity",
            signing_keys={"root-2026": b"test-signing-key-at-least-32-bytes"},
            active_key_id="root-2026",
            clock=lambda: NOW,
        ),
        operator_token=OPERATOR_TOKEN,
    )
    server = create_server("127.0.0.1", 0, service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = AgentGuardClient(
        f"http://127.0.0.1:{server.server_port}", operator_token=OPERATOR_TOKEN
    )
    try:
        issued = client.issue_identity(
            agent_id="agp://cairo/sdk-01",
            principal_id="org://acme",
            expires_at="2026-08-10T20:45:00Z",
        )
        verified = client.verify_identity(issued["token"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

    assert verified["valid"] is True
    assert verified["identity"]["agent_id"] == "agp://cairo/sdk-01"
