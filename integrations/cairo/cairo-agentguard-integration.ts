import type { AgentDecision, AgentRequest } from "../../packages/sdk-ts/src/index.js";

export interface CairoRunSecurityContext {
  agentId: string;
  principalId: string;
  missionId: string;
  identityToken: string;
  capabilityToken: string;
  sessionId: string;
  policyBundleHash: string;
  riskScore: number;
}

export interface AgentGuardAuthorizer {
  authorize(request: AgentRequest): Promise<AgentDecision>;
}

export class CairoExecutionDenied extends Error {
  constructor(readonly decision: AgentDecision) {
    super(`${decision.effect}: ${decision.reason}`);
  }
}

export class CairoExecutionGateway {
  constructor(private readonly guard: AgentGuardAuthorizer) {}

  beforeToolCall(context: CairoRunSecurityContext, server: string, tool: string) {
    return this.authorize(context, `mcp://${server}/${tool}`, "invoke");
  }

  beforeShell(context: CairoRunSecurityContext, commandClass: string) {
    return this.authorize(context, `shell://${commandClass}`, "execute");
  }

  beforeFilesystem(
    context: CairoRunSecurityContext,
    normalizedPath: string,
    operation: "read" | "write" | "delete",
  ) {
    return this.authorize(context, `file://${normalizedPath}`, operation);
  }

  beforeNetwork(
    context: CairoRunSecurityContext,
    origin: string,
    method: string,
  ) {
    return this.authorize(context, `https://${origin}`, method.toLowerCase());
  }

  beforeSecretUse(context: CairoRunSecurityContext, secretName: string) {
    return this.authorize(context, `secret://${secretName}`, "broker_execute");
  }

  beforeDelegation(context: CairoRunSecurityContext, childAgentId: string) {
    return this.authorize(context, `agent://${childAgentId}`, "delegate");
  }

  async execute<T>(decision: Promise<AgentDecision>, operation: () => Promise<T>): Promise<T> {
    const resolved = await decision;
    if (resolved.effect !== "ALLOW" && resolved.effect !== "ALLOW_WITH_LIMITS") {
      throw new CairoExecutionDenied(resolved);
    }
    return operation();
  }

  private authorize(
    context: CairoRunSecurityContext,
    resource: string,
    action: string,
  ): Promise<AgentDecision> {
    return this.guard.authorize({
      request_id: crypto.randomUUID(),
      agent_id: context.agentId,
      principal_id: context.principalId,
      mission_id: context.missionId,
      resource,
      action,
      identity_token: context.identityToken,
      capability_token: context.capabilityToken,
      session_id: context.sessionId,
      nonce: crypto.randomUUID(),
      risk_score: context.riskScore,
      timestamp: new Date().toISOString(),
    });
  }
}
