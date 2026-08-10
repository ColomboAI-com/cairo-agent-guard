# Agent Guard Daemon API

Default address: `http://127.0.0.1:8787`. Remote deployments should require
mTLS or authenticated ingress and must never expose issuance endpoints to
untrusted agents.

Authority/control routes require `Authorization: Bearer
<AGENTGUARD_OPERATOR_TOKEN>`. Identity verification, authorization, health, and
certification intake remain unprivileged protocol surfaces.

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Liveness and AGP version |
| POST | `/v1/identities/issue` | Issue signed AgentIdentity |
| POST | `/v1/identities/verify` | Verify signature, issuer, and expiry |
| POST | `/v1/capabilities/issue` | Issue mission-bound capability |
| POST | `/v1/capabilities/delegate` | Create a reduced child capability |
| POST | `/v1/missions` | Register an active principal-bound mission |
| POST | `/v1/missions/terminate` | End a mission immediately |
| POST | `/v1/authorize` | Evaluate one consequential action |
| POST | `/v1/revocations` | Revoke identity/agent/mission/capability |
| POST | `/v1/delegations` | Register the agent delegation graph |
| POST | `/v1/quarantine` | Revoke an agent and delegated descendants |
| GET | `/v1/audit` | Retrieve events and hash-chain status |
| POST | `/v1/certification/applications` | Persist certification intake |

Issuance, revocation, audit retrieval, and certification administration require
operator authentication at the deployment ingress. The dependency-free local
daemon intentionally does not invent an application identity layer.
