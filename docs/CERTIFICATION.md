# Agent Guard Certification

AGP Certification validates measurable security properties for agents,
runtimes, platforms, MCP servers, and physical systems.

| Level | Profile | Required controls |
|---|---|---|
| AGP-L1 | Identity Ready | Stable identity, principal binding, signed envelopes, revocation, disclosure process |
| AGP-L2 | Capability Controlled | L1 + mission grants, default deny, monotonic delegation, expiry, auditable decisions |
| AGP-L3 | Runtime Protected | L2 + non-bypassable tools/network/files/secrets, DLP, quarantine/kill, telemetry |
| AGP-L4 | High Assurance | L3 + attestation, independent policy, tamper resistance, signed approvals, exercises |
| AGP-P | Physical AI | L3/L4 + PAIP command envelope, safety controller, physical limits, E-stop and replay |

## Flow

Apply → scope profile → submit evidence → automated conformance → adversarial
validation for L3+ → remediate → signed certificate/registry → annual or
material-change renewal.

Evidence includes architecture, threat model, policies, delegation behavior,
sandbox/network model, secret handling, audit samples, revocation test, incident
contact, L3+ red-team evidence, and AGP-P safety case.

