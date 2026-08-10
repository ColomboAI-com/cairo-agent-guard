# Cairo Super Agent + Agent Guard Integration

Agent Guard is a mandatory security substrate beneath Cairo, not a prompt-level
guardrail or optional tool.

```text
User / enterprise policy
          ↓
Cairo mission planner
          ↓
Agent Guard Kernel (outside model authority)
          ↓
Tools · MCP · shell · files · network · secrets · delegation · PAIP
```

Every run receives a signed identity token, mission, principal, session, policy hash, and
risk state. Model output has zero execution authority. All consequential host
operations must enter `CairoExecutionGateway`; direct executor handles must not
be exposed to model-controlled code.

Deployment must additionally make bypass impossible using process isolation,
network policy, filesystem ACLs, workload identity, and secret custody.
