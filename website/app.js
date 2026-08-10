const docs = {
  overview: {
    title: "Agent Guard in one minute",
    body: `<p>Agent Guard separates intelligence from authority. The model proposes an action; a Guardian outside model control verifies identity, mission, capability, delegation, revocation, and risk before any executor is called.</p><h4>Security invariants</h4><ul><li>Missing authority is denial.</li><li>Risk can reduce authority but never create it.</li><li>Child authority is a subset of parent authority.</li><li>External content is data, never permission.</li><li>Security failure cannot increase authority.</li></ul><h4>Decision vocabulary</h4><p><code>ALLOW</code>, <code>ALLOW_WITH_LIMITS</code>, <code>REQUIRE_APPROVAL</code>, <code>SANITIZE</code>, <code>REDIRECT</code>, <code>RATE_LIMIT</code>, <code>ISOLATE</code>, <code>QUARANTINE</code>, <code>DENY</code>, and <code>TERMINATE</code>.</p>`,
  },
  quickstart: {
    title: "Run the local Guardian",
    body: `<p>The V0.1 daemon has no Python runtime dependencies. Protect the signing key outside model-accessible files or environment.</p><pre>python -m pip install -e .
set AGENTGUARD_SIGNING_KEY=&lt;32+ random bytes&gt;
set AGENTGUARD_OPERATOR_TOKEN=&lt;different 32+ random characters&gt;
set AGENTGUARD_DATA_DIR=.agentguard
agentguardd</pre><p>The service exposes health, identity issuance and verification, capability issuance, authorization, revocation, audit, and certification intake. Bind to loopback by default and place mTLS or authenticated ingress in front of remote deployments.</p><pre>curl http://127.0.0.1:8787/healthz</pre>`,
  },
  architecture: {
    title: "Reference architecture",
    body: `<p>The Guardian runs below the planning and model layer. It owns the only handles capable of executing tools, opening egress, writing protected files, accessing secrets, or creating delegated agents.</p><pre>User / enterprise policy
        ↓
Cairo mission planner
        ↓
Identity + Mission + Capability
        ↓
AGENT GUARD KERNEL
        ↓
MCP · Shell · Files · Network · Secrets · PAIP</pre><h4>Non-bypassability</h4><p>Application mediation is necessary but insufficient. Production deployments must pair the gateway with OS sandboxing, container or VM boundaries, default-deny network policy, filesystem ACLs, cloud IAM, and broker-only secret custody.</p>`,
  },
  identity: {
    title: "Agent Identity",
    body: `<p>A stable Agent ID is useful only when the receiving platform can verify its issuer, signature, principal binding, lifetime, and revocation status. Identity is never permission by itself.</p><pre>POST /v1/identities/verify
{
  "token": "&lt;signed AgentIdentity&gt;"
}</pre><h4>HTTP profile</h4><table><tr><th>Header</th><th>Purpose</th></tr><tr><td>AGP-Version</td><td>Protocol negotiation</td></tr><tr><td>AGP-Agent-ID</td><td>Autonomous actor identifier</td></tr><tr><td>AGP-Mission-ID</td><td>Declared purpose binding</td></tr><tr><td>AGP-Capability</td><td>Signed authority reference</td></tr><tr><td>AGP-Request-ID</td><td>Audit and replay correlation</td></tr></table>`,
  },
  policy: {
    title: "Capability and risk policy",
    body: `<p>A capability binds one agent to one mission, a finite resource/action scope, maximum risk, expiry, and delegation depth. The reference runtime uses conservative exact-pattern subset validation when delegating.</p><pre>{
  "agent_id": "agp://cairo/support-01",
  "mission_id": "mission://support-7",
  "resources": ["crm/customer/*"],
  "actions": ["read"],
  "max_risk": 40,
  "delegation_depth": 1
}</pre><h4>Risk tightening</h4><p>0–50 remains within the capability boundary; 51–70 requires approval; 71–90 quarantines; 91–100 terminates. A deployment may choose stricter thresholds.</p>`,
  },
  mcp: {
    title: "MCP Guard",
    body: `<p>The reference proxy maps every <code>tools/call</code> request to <code>mcp://server/tool</code>. The upstream callback is unreachable until the execution gateway returns an allow effect.</p><pre>python examples/mcp_guard_demo.py

effect: DENY
upstream reached: false</pre><p>Production deployments must prevent agents from opening a second, unguarded MCP transport. The proxy should own the only upstream credentials and network route.</p>`,
  },
  edge: {
    title: "Agent Guard Edge",
    body: `<p>Edge protects the receiving platform. It classifies verified, unknown, challenged, and hostile agents; verifies AGP envelopes; applies platform-local policy; and returns allow, challenge, limit, deny, or quarantine.</p><h4>Integration sequence</h4><ol><li>Verify issuer, identity signature, expiry, and revocation.</li><li>Verify mission and capability without treating identity as permission.</li><li>Evaluate the platform's own resource policy.</li><li>Enforce at ingress and emit structured evidence.</li></ol>`,
  },
  cairo: {
    title: "Cairo Super Agent integration",
    body: `<p>Every Cairo run receives identity, principal, mission, capability, session, policy hash, and risk state. Model output has zero execution authority.</p><pre>CairoExecutionGateway.beforeToolCall()
CairoExecutionGateway.beforeShell()
CairoExecutionGateway.beforeFilesystem()
CairoExecutionGateway.beforeNetwork()
CairoExecutionGateway.beforeSecretUse()
CairoExecutionGateway.beforeDelegation()</pre><p>The integration contract is in <code>integrations/cairo/cairo-agentguard-integration.ts</code>. Cairo's actual executor registry must expose handles only to this gateway.</p>`,
  },
  physical: {
    title: "AGP-P and PAIP",
    body: `<p>AGP-P binds digital authorization to device safety constraints: geofence, altitude or depth, velocity, force, temperature, human proximity, actuator class, energy thresholds, operator presence, and emergency stop.</p><p>A model command cannot override the independent safety controller. Identity, capability, and mission checks happen above the hardware safety envelope—not instead of it.</p>`,
  },
  cert: {
    title: "Certification profiles",
    body: `<table><tr><th>Level</th><th>Assurance</th></tr><tr><td>AGP-L1</td><td>Signed identity and revocation</td></tr><tr><td>AGP-L2</td><td>Mission-bound least authority</td></tr><tr><td>AGP-L3</td><td>Non-bypassable runtime controls</td></tr><tr><td>AGP-L4</td><td>Attestation and adversarial validation</td></tr><tr><td>AGP-P</td><td>Physical safety integration</td></tr></table><h4>Evidence</h4><p>Architecture, threat model, capability samples, delegation tests, sandbox/network model, secret handling, audit events, revocation exercise, incident contact, red-team evidence for L3+, and a safety case for AGP-P.</p>`,
  },
};

const docContent = document.querySelector("#doc-content");
const renderDoc = (name) => {
  const doc = docs[name] || docs.overview;
  docContent.innerHTML = `<h3>${doc.title}</h3>${doc.body}`;
};
document.querySelectorAll(".doc-link").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".doc-link").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    renderDoc(button.dataset.doc);
    if (window.innerWidth < 900) docContent.focus();
  });
});
renderDoc("overview");

document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const source = document.getElementById(button.dataset.copy);
    try {
      await navigator.clipboard.writeText(source.textContent);
      const previous = button.textContent;
      button.textContent = "Copied";
      setTimeout(() => (button.textContent = previous), 1400);
    } catch {
      button.textContent = "Select text to copy";
    }
  });
});

const navToggle = document.querySelector(".nav-toggle");
const nav = document.querySelector("#nav");
navToggle.addEventListener("click", () => {
  const open = nav.classList.toggle("open");
  navToggle.setAttribute("aria-expanded", String(open));
});
nav.addEventListener("click", () => {
  nav.classList.remove("open");
  navToggle.setAttribute("aria-expanded", "false");
});

const form = document.querySelector("#cert-form");
const status = document.querySelector("#cert-status");
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  status.classList.remove("error");
  status.textContent = "Submitting securely…";
  const submit = form.querySelector("button[type=submit]");
  submit.disabled = true;
  const application = Object.fromEntries(new FormData(form).entries());
  const apiBase = document.body.dataset.apiBase || "/AgentGuard/api";
  try {
    const response = await fetch(`${apiBase}/v1/certification/applications`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "AGP-Version": "0.1" },
      body: JSON.stringify(application),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Application could not be submitted");
    form.reset();
    status.textContent = `Application ${result.application_id} received. Evidence review is next.`;
  } catch (error) {
    status.classList.add("error");
    status.textContent = error instanceof Error ? error.message : "Application could not be submitted";
  } finally {
    submit.disabled = false;
  }
});
