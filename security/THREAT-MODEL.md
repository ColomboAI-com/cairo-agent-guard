# Agent Guard V0.1 Threat Model

## Assets

Principal authority, identity/capability signing keys, credentials, policy,
audit evidence, data, external systems, delegated agents, and physical control.

## Trust boundaries

Model output and retrieved content are untrusted. The Guardian, issuer,
revocation state, operator approval channel, secret broker, and OS/cloud
enforcement layer are trusted only within their documented deployment boundary.

## Priority threats and controls

- Prompt injection or model compromise: data is not authority; external policy.
- Forged identity/capability: signed short-lived tokens and issuer pinning.
- Replay: unique request id, timestamp/expiry, and deployment nonce cache.
- Confused deputy: bind exact agent, principal, mission, resource, and action.
- Delegation escalation: conservative child-subset validation and depth limits.
- Direct tool/network bypass: exclusive host gateway plus OS/network isolation.
- Credential theft: broker-only custody and response scrubbing.
- Audit tampering: append-only hash chain and external log shipping.
- Guardian outage: fail closed and explicit recovery path.
- Kill evasion: revoke agent/mission/capabilities and propagate the subtree.

## Known V0.1 limitations

The reference token issuer uses HMAC, has no distributed replay cache, does not
itself configure kernel/network isolation, and stores local state in SQLite and
JSONL. Production deployments should use asymmetric keys/HSM custody, mTLS,
distributed strongly consistent revocation, remote immutable audit storage,
and platform-native isolation.

V0.1 verifies signed identities and capabilities plus one-time request IDs,
nonces, and timestamps; proof-of-possession signatures over the complete request
envelope and cryptographic HumanAuthorization consumption remain conformance
work for the next protocol increment. `REQUIRE_APPROVAL` therefore blocks
execution rather than accepting an unsigned approval.
