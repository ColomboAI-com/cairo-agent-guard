# Agent Identity

**Know the autonomous actor at your boundary.**

Agent Identity is the trust layer that lets a platform verify which agent is
acting, which principal it represents, who issued the identity, and whether the
identity is current or revoked.

Identity is not permission. It establishes the subject for policy evaluation;
mission and capability determine what that subject may attempt.

## Why agents need a distinct identity

API keys and service accounts identify credentials, not autonomous actors. A
single credential may be shared by a human, an application, and many agents.

That makes attribution, delegation, revocation, policy, and incident response
ambiguous. Agent Identity creates a stable security subject for each agent.

A useful identity answers:

- Which agent made the request?
- Which human or organization is the accountable principal?
- Which authority issued and signed the identity?
- Which key and runtime presented it?
- When was it issued, when does it expire, and has it been revoked?
- Which mission and capability accompany the request?
- Which delegated parent or agent tree does it belong to?

## Identity in the Agent Guard stack

```text
Agent Identity       AGP authority             Agent Guard Edge
Who is acting?   +   What may it do?       +   Will this platform allow it?
      │                    │                           │
      └────────────── AgentRequest ───────────────────┘
                               │
                               ▼
                         AgentDecision
```

Agent Identity is designed to be portable when backed by asymmetric issuer keys
and explicit trust federation.

V0.1 provides a locally pinned HMAC reference authority. Authorization always
remains local, and a receiving platform may deny any requested operation.

## Identity document

The V0.1 `AgentIdentity` includes:

| Field | Purpose |
|---|---|
| `agp_version` | Protocol version for parsing and compatibility. |
| `type` | Object type, fixed to `AgentIdentity`. |
| `identity_id` | Unique identifier for this issued identity document. |
| `agent_id` | Stable identifier for the autonomous actor. |
| `principal_id` | Human or organization ultimately represented. |
| `issuer` | Authority that makes and signs the identity claim. |
| `issued_at` | Beginning of the identity validity window. |
| `expires_at` | End of the identity validity window. |
| `key_id` | Signing key identifier used for verification and rotation. |

The signed token binds these values together. A request cannot safely replace
the principal, agent, issuer, or lifetime outside the signed document.

Example decoded document:

```json
{
  "agp_version": "0.1",
  "type": "AgentIdentity",
  "identity_id": "identity_V7k2mQ4p9xL3nR8s",
  "agent_id": "agp://cairo/support-01",
  "principal_id": "org://acme",
  "issuer": "agp://cairo/identity",
  "issued_at": "2026-08-10T20:30:00Z",
  "expires_at": "2026-08-10T20:45:00Z",
  "key_id": "root-2026"
}
```

## Identity lifecycle

### 1. Register

Create a stable agent record. Bind ownership, operator, software provenance,
allowed identity issuers, and incident contact.

Do not derive an agent ID from a mutable display name or prompt. Treat the ID as
a durable security subject.

### 2. Prove principal authority

Before issuance, verify that the human or organization may register and operate
the agent. The proof may use enterprise SSO, workload onboarding, or PKI.

### 3. Issue

Issue a short-lived signed identity that binds the exact agent and principal.
Keep signing keys outside model and agent-controlled context.

### 4. Present

The agent presents the identity token with a mission, capability, request ID,
nonce, timestamp, and any required proof-of-possession or attestation.

### 5. Verify

The receiving platform validates the issuer, key, signature, object type,
version, time window, agent and principal binding, and revocation state.

### 6. Authorize

After identity verification, evaluate mission, capability, resource, action,
delegation, risk, and receiving-platform policy.

### 7. Rotate

Rotate signing and workload keys without changing the stable `agent_id`. Publish
key identifiers and overlap windows that verifiers can handle safely.

### 8. Revoke or retire

Revoke compromised identities immediately. Retire agents when ownership,
software purpose, or operating authority ends.

Revocation should propagate to active sessions, capabilities, delegated
descendants, network access, broker credentials, and physical authority.

## Verification flow

```text
Inbound agent request
        │
        ▼
Parse canonical AGP envelope
        │
        ▼
Resolve trusted issuer and key
        │
        ▼
Verify signature, version, type, and time window
        │
        ▼
Bind request agent + principal to signed identity
        │
        ▼
Check identity, agent, mission, and capability revocation
        │
        ▼
Evaluate mission + capability + local policy
        │
        ▼
Enforce decision and record evidence
```

Never trust `agent_id` or `principal_id` strings without verifying the signed
document that binds them.

## Trust policy

A platform should maintain an explicit issuer trust policy.

| Decision input | Questions |
|---|---|
| Issuer | Is this authority trusted for this tenant, agent class, or resource? |
| Key | Is the key active, rotated safely, and uncompromised? |
| Principal | Is this principal recognized and allowed on the platform? |
| Agent | Is the stable agent registered, certified, or previously challenged? |
| Lifetime | Is the identity valid now and short-lived enough for its risk? |
| Revocation | Is the required revocation view sufficiently fresh? |
| Attestation | Does this action require proof of runtime or workload state? |

Trust should be scoped. An issuer trusted for customer-support agents may not be
trusted for financial, administrative, or physical-control agents.

## Identity and authority are different

The following request can contain a valid identity and still be denied:

```text
identity:   verified agent agp://cairo/support-01 for org://acme
mission:    customer support
capability: crm/customer/* → read
request:    cloud/admin/production → delete
decision:   DENY
```

The signed identity proves that its issuer bound the named agent and principal.
It does not prove that the current presenter controls the agent, and it does not
grant the requested cloud authority.

Presenter control requires request-envelope proof-of-possession or an attested
profile, which remains beyond the V0.1 reference implementation.

## HTTP profile

An AGP-aware request may carry these headers:

```http
AGP-Version: 0.1
AGP-Agent-ID: agp://cairo/agent-123
AGP-Mission-ID: mission_01J...
AGP-Capability: cap_01J...
AGP-Request-ID: req_01J...
AGP-Timestamp: 2026-08-10T20:30:00Z
AGP-Envelope-Signature: <detached-signature>
```

Headers are a transport profile, not a shortcut around signature verification.
Normalize proxy headers carefully and reject ambiguous duplicates.

Full request-envelope proof-of-possession is planned beyond the V0.1 reference
implementation. See [known limitations](../security/THREAT-MODEL.md).

## Issue and verify with the Python client

Identity issuance is an operator action. Verification is a protocol surface.

```python
from datetime import UTC, datetime, timedelta

from agentguard.client import AgentGuardClient

base_url = "http://127.0.0.1:8787"
operator = AgentGuardClient(base_url, operator_token="<operator-token>")
verifier = AgentGuardClient(base_url)

expires_at = (
    datetime.now(UTC) + timedelta(minutes=15)
).isoformat().replace("+00:00", "Z")

issued = operator.issue_identity(
    agent_id="agp://cairo/support-01",
    principal_id="org://acme",
    expires_at=expires_at,
)

verified = verifier.verify_identity(issued["token"])
assert verified["valid"] is True
assert verified["identity"]["principal_id"] == "org://acme"
```

The operator token must never be available to an untrusted agent. Put issuance
behind authenticated administrative ingress.

## Verify with the TypeScript client

```ts
import { AgentGuardClient } from "@cairo/agentguard";

const guard = new AgentGuardClient("https://guard.example.com");
const result = await guard.verifyIdentity(identityToken);

if (!result.valid) {
  throw new Error("Unverified agent identity");
}

const { agent_id, principal_id, issuer } = result.identity;
```

Verification alone must not trigger the protected operation. Build and authorize
the complete `AgentRequest` next.

## Platform integration patterns

### API and SaaS ingress

Verify Agent Identity before tenant routing or sensitive action handling. Bind
the verified principal to the platform tenant.

### MCP server

Verify the identity and capability before `tools/call`. Ensure the client cannot
reach the upstream MCP transport through an unguarded route.

### Multi-agent delegation

Give each child its own identity. Record parent-child relationships separately
from capability delegation so incident response can quarantine the whole tree.

### Workload and runtime identity

An agent identity describes the autonomous actor. A workload identity describes
the trusted runtime enforcing it. High-assurance actions may require both.

### Human-agent collaboration

Keep human identity, agent identity, and principal binding distinct in audit.
Do not make an agent indistinguishable from the human account it represents.

## Caching and revocation

Cache verified signatures only for a bounded period. Cache keys should include
issuer, key ID, token digest, and policy-relevant version.

For high-impact operations, use fresher revocation state than for read-only or
low-risk operations. A stale cache must not silently increase authority.

Revocation subjects include:

- identity document;
- stable agent;
- session;
- mission;
- capability and delegated descendants;
- broker credential;
- network access; and
- physical authority.

## Key management

The V0.1 local issuer uses HMAC for a dependency-free reference implementation.
Production identity services should use asymmetric signing and protected keys.

Recommended production controls include:

- HSM or managed KMS custody;
- independently authorized issuance and revocation;
- short-lived identity documents;
- published key identifiers and rotation windows;
- issuer pinning or explicit trust federation;
- compromise playbooks and emergency revocation; and
- signed, auditable administrative operations.

## Privacy and audit

Agent identity improves accountability but can create tracking risk. Use stable
identifiers only where needed and avoid leaking internal principal details.

Audit the verified agent, principal, issuer, mission, resource, action,
capability, decision, risk, policy version, and revocation references.

Do not require or store private model chain-of-thought.

## Common mistakes

- Trusting `AGP-Agent-ID` without verifying a signature.
- Treating a verified identity as permission.
- Issuing one identity to an entire uncontrolled agent fleet.
- Sharing a human session or API key as the agent's identity.
- Ignoring principal binding when validating a capability.
- Using long-lived tokens without current revocation.
- Allowing the agent to call identity issuance or revocation endpoints.
- Logging raw identity or capability tokens unnecessarily.
- Failing to distinguish agent, workload, service, and human identities.

## Integration checklist

- [ ] Stable agent IDs are separate from display names.
- [ ] Agent and principal are cryptographically bound.
- [ ] Trusted issuers and keys are explicit and scoped.
- [ ] Signature, type, version, and time window are validated.
- [ ] Revocation freshness matches action impact.
- [ ] Identity verification precedes mission and capability evaluation.
- [ ] Identity never grants authority by itself.
- [ ] Child agents receive distinct identities.
- [ ] Operator credentials remain outside agent context.
- [ ] Audit preserves agent/human/service distinctions.

## Current implementation status

V0.1 implements signed, expiring identity issuance and verification, issuer and
key IDs, principal binding, request binding, and revocation-aware decisions.

The local daemon is a reference authority. Managed CA, identity federation,
public discovery, hardware-backed keys, remote attestation, and a global agent
registry remain product and roadmap work.

## Related documentation

- [Agent Guard Edge](AGENT-GUARD-EDGE.md)
- [AGP v0.1](../spec/AGP-v0.1.md)
- [Daemon API](API.md)
- [Deployment and non-bypassability](DEPLOYMENT.md)
- [Certification](CERTIFICATION.md)
- [`AgentIdentity` schema](../schemas/agent-identity.schema.json)
