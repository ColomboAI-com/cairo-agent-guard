# Deployment and Non-Bypassability

The Python gateway enforces call order inside a trusted host process. A secure
deployment must additionally ensure the agent cannot obtain an alternate path.

1. Run model/agent code in a sandboxed process, container, microVM, or VM.
2. Route all egress through a default-deny proxy owned by Agent Guard.
3. Give only the Guardian filesystem write handles and tool transports.
4. Store credentials in an external vault; expose only broker operations.
5. Bind workload identity to the Guardian, never to model-generated code.
6. Ship audit events to remote append-only or WORM storage.
7. Set a high-entropy operator token, keep it outside agent context, and add
   authenticated ingress/mTLS around operator APIs.
8. Exercise revocation, quarantine, key rotation, and fail-closed recovery.

The static site should mount at `/AgentGuard`; proxy `/AgentGuard/api/*` to the
daemon's `/v1/*` and health endpoints, preserving HTTPS and request limits.

## Agent Guard Edge deployments

For receiving-side protection, deploy Agent Guard Edge as a reverse proxy,
API-gateway policy module, MCP gateway, service-mesh sidecar, SaaS agent ingress,
or physical-system gateway.

Edge must be the only route to the protected upstream. A policy check that an
agent can bypass is observability, not enforcement.

Keep identity and capability verification in the data path. Distribute issuer
trust, policy, revocation, and threat intelligence through a separately
authenticated control plane.

See [Agent Guard Edge](AGENT-GUARD-EDGE.md) for the full architecture and
[Agent Identity](IDENTITY-INTEGRATION.md) for the verifier lifecycle.
