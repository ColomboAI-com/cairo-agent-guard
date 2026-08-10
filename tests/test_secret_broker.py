from agentguard.secrets import SecretBroker, UnknownSecret


def test_secret_broker_executes_without_returning_raw_credential() -> None:
    observed_authorization = ""

    def payment_connector(secret: str, request: dict[str, object]) -> dict[str, object]:
        nonlocal observed_authorization
        observed_authorization = secret
        return {
            "status": "accepted",
            "authorization": secret,
            "transaction_id": request["transaction_id"],
        }

    broker = SecretBroker()
    broker.register("payments-api", "sk_agentguard_super_secret", payment_connector)

    result = broker.execute("payments-api", {"transaction_id": "txn-17"})

    assert observed_authorization == "sk_agentguard_super_secret"
    assert result == {"status": "accepted", "transaction_id": "txn-17"}
    assert "sk_agentguard_super_secret" not in repr(result)

    try:
        broker.execute("missing", {})
    except UnknownSecret as exc:
        assert str(exc) == "secret is not registered: missing"
    else:
        raise AssertionError("unknown secret must fail closed")
