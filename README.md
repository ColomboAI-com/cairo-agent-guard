# Cairo Agent Guard

**The zero-trust security layer for the Agentic Internet.**

Cairo Agent Guard is an open protocol and runnable reference implementation for
containing autonomous agents, protecting platforms from agent-driven attacks,
and establishing verifiable trust between agents and services.

> Intelligence is not authority. Every consequential agent action must be
> explicitly authorized, bounded, observable, and revocable.

## What works in V0.1

- Signed, expiring `AgentIdentity` documents.
- Mission-bound, revocable `AgentCapability` tokens.
- Monotonic delegation: child authority cannot exceed parent authority.
- Deterministic default-deny policy with risk-only tightening.
- SQLite revocation state and append-only hash-chained audit events.
- Mandatory execution gateway that blocks tools before invocation.
- MCP JSON-RPC policy proxy and unauthorized-tool demo.
- Blind secret broker with response scrubbing.
- Local dependency-free HTTP daemon and Python client.
- Durable certification application intake.
- TypeScript SDK and Cairo host-integration contract.
- Rich static website/docs for `Cairo.sh/AgentGuard`.

## Repository map

```text
cairo-agent-guard/
├── spec/AGP-v0.1.md
├── schemas/
├── src/agentguard/              # Python runtime + SDK
├── packages/sdk-ts/             # TypeScript SDK
├── integrations/cairo/          # Cairo mandatory gateway contract
├── integrations/mcp/            # MCP Guard notes and demo
├── docs/                         # product/developer/certification docs
├── security/                     # threat model + disclosure policy
├── examples/
└── website/                      # target: Cairo.sh/AgentGuard
```

## Quick start

Requires Python 3.11+ and has no runtime dependencies.

```bash
python -m pip install -e .
set AGENTGUARD_SIGNING_KEY=replace-with-at-least-32-random-bytes
set AGENTGUARD_OPERATOR_TOKEN=use-a-different-32-character-random-token
agentguardd
```

Run the conformance tests:

```bash
python -m pytest -q
```

Python client:

```python
from agentguard.client import AgentGuardClient

guard = AgentGuardClient("http://127.0.0.1:8787")
decision = guard.authorize({
    "request_id": "req-01",
    "agent_id": "agp://cairo/support-01",
    "principal_id": "org://acme",
    "mission_id": "mission://support-7",
    "resource": "mcp://crm/read_customer",
    "action": "invoke",
    "identity_token": "<signed identity>",
    "capability_token": "<signed token>",
    "session_id": "session-01",
    "nonce": "one-time-random-value",
    "risk_score": 12,
    "timestamp": "2026-08-10T20:30:00Z"
})
```

## Security boundary

This repository provides the policy/runtime reference layer. Non-bypassability
also requires deployment controls outside the agent—OS sandboxing, container or
VM isolation, default-deny network policy, workload identity, and exclusive
credential access by the broker. See [the threat model](security/THREAT-MODEL.md).

## Open/commercial boundary

Open under Apache-2.0: AGP, schemas, deterministic runtime, SDKs, reference MCP
and Cairo integrations, conformance requirements, certification profiles,
examples, and threat model.

Commercial platform: managed CA/identity, Agent SOC, semantic DLP, behavioral
and escape detection, threat intelligence, managed Agent Guard Edge, remote
attestation, enterprise secret brokers, compliance evidence, managed
certification, HA, and SLAs.

## Status

AGP v0.1 is a draft reference implementation, not a claim of production
hardening or certification. Full request-envelope proof-of-possession and
cryptographic approval consumption remain explicit next-step conformance work.
Security reports: see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0.
