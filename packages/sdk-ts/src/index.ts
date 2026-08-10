export type AgentEffect =
  | "ALLOW"
  | "ALLOW_WITH_LIMITS"
  | "REQUIRE_APPROVAL"
  | "SANITIZE"
  | "REDIRECT"
  | "RATE_LIMIT"
  | "ISOLATE"
  | "QUARANTINE"
  | "DENY"
  | "TERMINATE";

export interface AgentRequest {
  request_id: string;
  agent_id: string;
  principal_id: string;
  mission_id: string;
  resource: string;
  action: string;
  identity_token: string;
  capability_token: string;
  session_id: string;
  nonce: string;
  risk_score: number;
  timestamp: string;
}

export interface AgentDecision {
  effect: AgentEffect;
  reason: string;
  request_id: string;
  capability_id: string | null;
}

export interface AgentIdentity {
  agp_version: "0.1";
  type: "AgentIdentity";
  identity_id: string;
  agent_id: string;
  principal_id: string;
  issuer: string;
  issued_at: string;
  expires_at: string;
  key_id: string;
}

export class AgentGuardApiError extends Error {
  constructor(
    readonly status: number,
    readonly detail: unknown,
  ) {
    super(`Agent Guard API error ${status}`);
  }
}

export class AgentGuardClient {
  constructor(
    private readonly baseUrl: string,
    private readonly operatorToken?: string,
    private readonly fetcher: typeof fetch = fetch,
  ) {}

  issueIdentity(input: {
    agent_id: string;
    principal_id: string;
    expires_at: string;
  }): Promise<{ token: string }> {
    return this.post("/v1/identities/issue", input);
  }

  verifyIdentity(token: string): Promise<{ valid: boolean; identity: AgentIdentity }> {
    return this.post("/v1/identities/verify", { token });
  }

  issueCapability(input: Record<string, unknown>): Promise<{
    token: string;
    capability_id: string;
  }> {
    return this.post("/v1/capabilities/issue", input);
  }

  delegateCapability(input: Record<string, unknown>): Promise<{
    token: string;
    capability_id: string;
    parent_capability_id: string;
  }> {
    return this.post("/v1/capabilities/delegate", input);
  }

  authorize(request: AgentRequest): Promise<AgentDecision> {
    return this.post("/v1/authorize", request);
  }

  revoke(input: {
    subject_type: string;
    subject_id: string;
    reason: string;
  }): Promise<{ revoked: true }> {
    return this.post("/v1/revocations", input);
  }

  registerDelegation(input: {
    parent_agent_id: string;
    child_agent_id: string;
  }): Promise<{ registered: true }> {
    return this.post("/v1/delegations", input);
  }

  quarantine(input: {
    agent_id: string;
    reason: string;
  }): Promise<{ quarantined: true; affected_agents: string[] }> {
    return this.post("/v1/quarantine", input);
  }

  submitCertification(input: Record<string, unknown>): Promise<{
    application_id: string;
    status: string;
  }> {
    return this.post("/v1/certification/applications", input);
  }

  registerMission(input: Record<string, unknown>): Promise<{ registered: true }> {
    return this.post("/v1/missions", input);
  }

  terminateMission(mission_id: string): Promise<{ terminated: true }> {
    return this.post("/v1/missions/terminate", { mission_id });
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "AGP-Version": "0.1",
    };
    if (this.operatorToken) headers.Authorization = `Bearer ${this.operatorToken}`;
    const response = await this.fetcher(`${this.baseUrl.replace(/\/$/, "")}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    const detail: unknown = await response.json();
    if (!response.ok) throw new AgentGuardApiError(response.status, detail);
    return detail as T;
  }
}
