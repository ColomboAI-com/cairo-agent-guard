# Agent Guard Protocol (AGP) v0.1

Status: Draft specification  
Owner: Cairo / ColomboAI

## 1. Purpose

AGP defines a zero-trust trust-and-control protocol for autonomous agents. It
governs identity, attestation, mission, capabilities, delegation, risk, policy
decisions, audit evidence, revocation, and incident response across digital and
physical systems.

AGP separates intelligence from authority. A model may be arbitrarily capable
while actionable authority remains narrow, time-bounded, independently
enforced, cryptographically verifiable, and revocable.

## 2. Actors

- **Principal**: human or organization ultimately authorizing a mission.
- **Agent**: autonomous or semi-autonomous software actor.
- **Guardian**: enforcement runtime outside the agent's control boundary.
- **Resource Server**: API, tool, data store, service, or device.
- **Attester**: trusted component proving runtime/security state.
- **Authorization Service**: identity, capability, and approval issuer/verifier.
- **Auditor**: consumer of immutable structured security events.

## 3. Protocol objects

AGP v0.1 standardizes `AgentIdentity`, `AgentPassport`, `AgentMission`,
`AgentCapability`, `AgentDelegation`, `AgentRequest`, `AgentDecision`,
`AgentAttestation`, `AgentRisk`, `AgentIncident`, `AgentRevocation`, and
`HumanAuthorization`.

## 4. Required request envelope

Every consequential action SHOULD be representable as an `AgentRequest` with
protocol version, unique request id, agent and principal, mission, resource,
operation, capability, delegation digest, risk, execution environment,
timestamp, expiry/nonce, and signatures or attestation where required.

## 5. Decision effects

`ALLOW`, `ALLOW_WITH_LIMITS`, `REQUIRE_APPROVAL`, `SANITIZE`, `REDIRECT`,
`RATE_LIMIT`, `ISOLATE`, `QUARANTINE`, `DENY`, and `TERMINATE`.

## 6. Authorization invariants

1. **Default deny.** Missing explicit authority MUST resolve to `DENY`.
2. **Mission binding.** Mission-scoped grants MUST expire with the mission.
3. **Delegation monotonicity.** `Authority(child) ⊆ Authority(parent)` across
   resource/action scope, budget, time, geography, and delegation depth.
4. **Data is not authority.** Content is not an authorization channel unless
   explicitly trusted as one under policy.
5. **Blind credential use.** Prefer brokered execution to revealing secrets.
6. **Fail closed.** Verification or security-service failure cannot increase
   authority.

## 7. Risk controls

Risk MAY tighten but MUST NOT grant authority. Default reference bands are:
0–25 autonomous, 26–50 constrained, 51–70 approval, 71–90 quarantine, and
91–100 terminate/revoke. Deployments may configure stricter thresholds.

## 8. Human authorization

High-impact approval SHOULD be signed and bind the exact agent, action,
resource, transaction parameters, validity window, nonce, and usage semantics.
Material mutation invalidates the approval.

## 9. Network and runtime enforcement

High-assurance deployments SHOULD use default-deny egress and constrain domain,
IP, protocol, method, and workload identity. Runtime attestation may bind build
digest, policy hash, sandbox posture, Guardian status, tool inventory, network
isolation, and hardware evidence.

## 10. Audit and revocation

Consequential decisions SHOULD record agent, principal, mission, action,
policy, effect, risk, approvals, side effect, and incident/revocation links.
Private chain-of-thought is neither required nor recommended.

Revocation MUST support identity, session, mission, capability, delegated
subtree, broker credential, network access, and physical authority. Kill SHOULD
propagate through the delegation graph.

## 11. Physical AI profile

AGP-P binds digital authority to PAIP/device constraints including geofence,
velocity, force, temperature, proximity, actuator class, energy thresholds,
emergency stop, and operator presence. Model commands MUST NOT override an
independent safety controller.

## 12. Versioning

Objects carry `agp_version`. Compatible additions increment minor version;
breaking wire or semantic changes increment major version.

