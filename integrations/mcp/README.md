# MCP Guard Reference Adapter

`agentguard.mcp.MCPGuardProxy` intercepts `tools/call` JSON-RPC messages, maps
the server/tool to `mcp://server/tool`, sends an `AgentRequest` through the
mandatory execution gateway, and calls upstream only for `ALLOW` or
`ALLOW_WITH_LIMITS`.

Run the blocking demonstration:

```bash
python examples/mcp_guard_demo.py
```

The reference class is transport-neutral. Production proxies must also isolate
the agent from the upstream MCP transport so it cannot open a second unguarded
connection.

