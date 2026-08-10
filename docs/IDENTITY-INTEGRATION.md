# Integrate Agent Identity into Your Platform

Verification flow:

```text
Agent → signed AGP request → Agent Guard middleware
      → identity → capability → revocation → platform policy → enforce
```

## HTTP profile

```http
AGP-Version: 0.1
AGP-Agent-ID: agp://cairo/agent-123
AGP-Mission-ID: mission_01J...
AGP-Capability: cap_01J...
AGP-Request-ID: req_01J...
AGP-Timestamp: 2026-08-10T20:30:00Z
AGP-Envelope-Signature: <detached-signature>
```

Never trust an Agent ID string without issuer/signature validation. Identity is
not permission. Cache briefly, keep revocation fresh for high-impact actions,
challenge unknown agents, and distinguish human from agent identities in audit.

