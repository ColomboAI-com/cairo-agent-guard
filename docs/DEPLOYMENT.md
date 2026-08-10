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
