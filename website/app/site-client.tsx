"use client";

/* eslint-disable @next/next/no-img-element -- official Cairo SVG is served directly */

import type { FormEvent, ReactNode } from "react";
import { useState } from "react";

const decisions = [
  "ALLOW",
  "ALLOW_WITH_LIMITS",
  "REQUIRE_APPROVAL",
  "SANITIZE",
  "REDIRECT",
  "RATE_LIMIT",
  "ISOLATE",
  "QUARANTINE",
  "DENY",
  "TERMINATE",
];

const docs: Record<string, { label: string; title: string; body: ReactNode }> = {
  overview: {
    label: "Overview",
    title: "Agent Guard in one minute",
    body: (
      <>
        <p>
          Agent Guard separates intelligence from authority. Models propose actions; a
          Guardian outside model control decides whether any side effect may happen.
        </p>
        <h4>Three connected pillars</h4>
        <ul>
          <li><strong>Agent Identity</strong> establishes the signed actor and principal claim.</li>
          <li><strong>AGP</strong> expresses missions, capabilities, delegation, risk, and decisions.</li>
          <li><strong>Agent Guard Edge</strong> applies receiving-platform policy at ingress.</li>
        </ul>
        <h4>Security invariants</h4>
        <p>Default deny. Risk only tightens. Child authority stays inside parent authority. Data is never permission. Security failure cannot increase access.</p>
      </>
    ),
  },
  identity: {
    label: "Agent Identity",
    title: "A verifiable subject for every agent",
    body: (
      <>
        <p>A stable ID matters only when a platform can verify issuer, key, signature, principal binding, lifetime, and revocation. Identity is not permission.</p>
        <pre>{`Register → Prove principal → Issue → Present
         → Verify → Authorize → Rotate → Revoke`}</pre>
        <h4>V0.1 boundary</h4>
        <p>The reference authority uses locally pinned HMAC. Cross-organization portability requires asymmetric issuer keys, explicit federation, and proof-of-possession.</p>
      </>
    ),
  },
  edge: {
    label: "Agent Guard Edge",
    title: "Protect your platform from external agents",
    body: (
      <>
        <p>Edge normalizes inbound agent activity, verifies identity and authority, applies local policy, tightens with live risk, and enforces before the upstream service is reached.</p>
        <pre>{`Discover → Verify → Classify → Authorize
         → Enforce → Record evidence`}</pre>
        <h4>Deployment patterns</h4>
        <p>Reverse proxy, API-gateway policy module, MCP gateway, service-mesh sidecar, SaaS agent ingress, or physical-system gateway.</p>
        <p>V0.1 ships reference primitives—not yet a managed, distributed Edge service.</p>
      </>
    ),
  },
  agp: {
    label: "AGP",
    title: "The trust language for autonomous actors",
    body: (
      <>
        <p>AGP standardizes identity, mission, capability, delegation, request, decision, risk, attestation, incident, revocation, passport, and human authorization objects.</p>
        <pre>{`identity + mission + capability + risk
                    ↓
              AgentDecision`}</pre>
        <p>The protocol is portable authority context. It never forces a receiving platform to honor an external grant.</p>
      </>
    ),
  },
  runtime: {
    label: "Runtime",
    title: "Protect the world from your agent",
    body: (
      <>
        <p>The Guardian owns the only execution handles. Model-controlled code cannot call tools, shell, files, network, credentials, child agents, commerce, cloud, or devices directly.</p>
        <pre>{`Cairo planner
    ↓
Agent Guard Runtime
    ↓
Mandatory execution gateway
    ↓
MCP · shell · files · network · secrets · PAIP`}</pre>
      </>
    ),
  },
  policy: {
    label: "Policy model",
    title: "Mission-bound least authority",
    body: (
      <>
        <p>A capability binds one agent and principal to one mission, finite resources and actions, a risk ceiling, expiry, and delegation depth.</p>
        <pre>{`{
  "resource": "mcp://crm/read_customer",
  "action": "invoke",
  "max_risk": 40,
  "delegation_depth": 1
}`}</pre>
        <p>The V0.1 Guard fails closed for approval outcomes. Signed approval consumption remains next-protocol work.</p>
      </>
    ),
  },
  mcp: {
    label: "MCP Guard",
    title: "Authorization before tools/call",
    body: (
      <>
        <p>The reference proxy maps every MCP call to <code>mcp://server/tool</code>. Upstream is unreachable until the execution gateway returns an allowed effect.</p>
        <pre>{`python examples/mcp_guard_demo.py

effect: DENY
upstream reached: false`}</pre>
        <p>Production deployments must also remove every alternate route to the unguarded MCP transport.</p>
      </>
    ),
  },
  cairo: {
    label: "Cairo integration",
    title: "Mandatory security beneath Cairo",
    body: (
      <>
        <p>Every Cairo run carries agent, principal, mission, signed identity, capability, session, policy hash, and risk state. Model output has zero execution authority.</p>
        <pre>{`beforeToolCall()
beforeShell()
beforeFilesystem()
beforeNetwork()
beforeSecretUse()
beforeDelegation()`}</pre>
      </>
    ),
  },
  deployment: {
    label: "Deployment",
    title: "Non-bypassability is the boundary",
    body: (
      <>
        <p>Application checks must be paired with process isolation, default-deny egress, filesystem ACLs, workload identity, external secret custody, and remote immutable audit storage.</p>
        <h4>Production checklist</h4>
        <ul>
          <li>Agent code has no direct upstream or credential route.</li>
          <li>Issuer keys and operator credentials stay outside agent context.</li>
          <li>Revocation, quarantine, key rotation, and outage recovery are exercised.</li>
        </ul>
      </>
    ),
  },
  certification: {
    label: "Certification",
    title: "Measurable assurance profiles",
    body: (
      <>
        <p>Certification progresses from signed identity through capability control, non-bypassable runtime protection, high assurance, and physical AI safety integration.</p>
        <pre>{`AGP-L1  Identity Ready
AGP-L2  Capability Controlled
AGP-L3  Runtime Protected
AGP-L4  High Assurance
AGP-P   Physical AI`}</pre>
        <p>An application begins evidence review. It is not itself a certificate or claim of conformance.</p>
      </>
    ),
  },
};

const requestExample = `{
  "agp_version": "0.1",
  "type": "AgentRequest",
  "agent_id": "agp://cairo/procurement-8472",
  "principal_id": "org://acme",
  "mission_id": "mission://reconcile-invoice-4471",
  "resource": "payments/invoice/4471",
  "action": "propose_payment",
  "identity_token": "<signed identity>",
  "capability_token": "<signed capability>",
  "session_id": "session-8472",
  "nonce": "one-time-random-value",
  "risk_score": 17,
  "timestamp": "2026-08-11T00:30:00Z"
}`;

export function AgentGuardSite() {
  const [navOpen, setNavOpen] = useState(false);
  const [activeDoc, setActiveDoc] = useState("overview");
  const [copyLabel, setCopyLabel] = useState("Copy request");
  const [formStatus, setFormStatus] = useState("");
  const [formError, setFormError] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  async function copyRequest() {
    try {
      await navigator.clipboard.writeText(requestExample);
      setCopyLabel("Copied");
      window.setTimeout(() => setCopyLabel("Copy request"), 1400);
    } catch {
      setCopyLabel("Select and copy");
    }
  }

  async function submitCertification(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setFormError(false);
    setFormStatus("Submitting securely…");
    const form = event.currentTarget;
    const payload = Object.fromEntries(new FormData(form).entries());

    try {
      const response = await fetch("/AgentGuard/api/certification/applications", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const result = (await response.json()) as { application_id?: string; error?: string };
      if (!response.ok) throw new Error(result.error || "Application could not be submitted.");
      form.reset();
      setFormStatus(`Application ${result.application_id} received. Evidence review is next.`);
    } catch (error) {
      setFormError(true);
      setFormStatus(error instanceof Error ? error.message : "Application could not be submitted.");
    } finally {
      setSubmitting(false);
    }
  }

  const active = docs[activeDoc] ?? docs.overview;

  return (
    <>
      <a className="skip-link" href="#main">Skip to content</a>
      <div className="ambient ambient-one" aria-hidden="true" />
      <div className="ambient ambient-two" aria-hidden="true" />

      <header className="topbar">
        <a className="brand" href="#top" aria-label="Cairo Agent Guard home">
          <img src="/AgentGuard/cairo-logo.svg" alt="" />
          <span><b>Cairo</b> Agent Guard</span>
        </a>
        <button
          className="nav-toggle"
          type="button"
          aria-expanded={navOpen}
          aria-controls="primary-nav"
          onClick={() => setNavOpen((value) => !value)}
        >
          Menu
        </button>
        <nav id="primary-nav" className={navOpen ? "open" : ""} aria-label="Primary navigation">
          <a href="#identity" onClick={() => setNavOpen(false)}>Identity</a>
          <a href="#protocol" onClick={() => setNavOpen(false)}>AGP</a>
          <a href="#edge" onClick={() => setNavOpen(false)}>Edge</a>
          <a href="#runtime" onClick={() => setNavOpen(false)}>Runtime</a>
          <a href="#certification" onClick={() => setNavOpen(false)}>Certification</a>
          <a href="#docs" onClick={() => setNavOpen(false)}>Docs</a>
        </nav>
        <a className="button button-small desktop-cta" href="#quickstart">Start building</a>
      </header>

      <main id="main">
        <section id="top" className="hero shell">
          <div className="hero-copy">
            <div className="eyebrow"><span /> Cairo / ColomboAI · V0.1 Foundation</div>
            <h1>Security infrastructure for the <em>Agentic Internet.</em></h1>
            <p className="hero-lead">Know the agent. Bound its authority. Enforce before action.</p>
            <p className="hero-detail">Cairo Agent Guard combines Agent Identity, an open trust protocol, a non-bypassable runtime, and receiving-side Edge protection for software agents and physical AI.</p>
            <div className="hero-actions">
              <a className="button" href="#pillars">Explore the platform</a>
              <a className="button button-ghost" href="https://github.com/ColomboAI-com/cairo-agent-guard">View open source</a>
            </div>
            <div className="principle"><span>01</span><p><b>Intelligence is not authority.</b> Every consequential action must be explicitly authorized, narrowly bounded, observable, and revocable.</p></div>
          </div>

          <div className="hero-visual" aria-label="Example Agent Guard authorization decision">
            <div className="orbit orbit-a" />
            <div className="orbit orbit-b" />
            <div className="hero-shield"><img src="/AgentGuard/cairo-logo.svg" alt="Cairo logo" /></div>
            <div className="signal signal-identity"><span>IDENTITY</span><b>VERIFIED CLAIM</b></div>
            <div className="signal signal-mission"><span>MISSION</span><b>BOUND</b></div>
            <div className="signal signal-risk"><span>RISK</span><b>17 / 100</b></div>
            <div className="signal signal-effect"><span>DECISION</span><b>ALLOW</b></div>
          </div>
        </section>

        <section className="proof-strip" aria-label="Agent Guard outcomes">
          <div><b>IDENTIFY</b><span>Signed agent and principal context</span></div>
          <div><b>CONTROL</b><span>Mission-bound, least authority</span></div>
          <div><b>DEFEND</b><span>Ingress enforcement for platforms</span></div>
          <div><b>PROVE</b><span>Structured, revocation-linked evidence</span></div>
        </section>

        <section id="pillars" className="section shell">
          <div className="section-heading">
            <div><span className="kicker">THE AGENT GUARD STACK</span><h2>Three pillars.<br />One trust boundary.</h2></div>
            <p>AGP is the language—not the whole product. Identity establishes the signed subject. AGP carries authority. Edge makes the receiving platform sovereign.</p>
          </div>
          <div className="pillar-grid">
            <article className="pillar identity-pillar"><span className="pillar-number">01</span><div className="pillar-icon">ID</div><h3>Agent Identity</h3><p>Who is acting, which principal it represents, who issued the claim, and whether it remains valid.</p><ul><li>Stable agent identity</li><li>Principal binding</li><li>Issuer trust and rotation</li><li>Revocation-aware verification</li></ul><a href="#identity">Explore Identity →</a></article>
            <article className="pillar protocol-pillar"><span className="pillar-number">02</span><div className="pillar-icon">AGP</div><h3>Agent Guard Protocol</h3><p>Portable mission, capability, delegation, risk, decision, attestation, and incident context.</p><ul><li>Default deny</li><li>Monotonic delegation</li><li>Risk-only tightening</li><li>Ten decision effects</li></ul><a href="#protocol">Read the protocol →</a></article>
            <article className="pillar edge-pillar"><span className="pillar-number">03</span><div className="pillar-icon">EDGE</div><h3>Agent Guard Edge</h3><p>Receiving-side discovery, verification, platform policy, containment, and security evidence.</p><ul><li>Trust classification</li><li>Challenge and step-up</li><li>Rate, data, economic control</li><li>Quarantine and denial</li></ul><a href="#edge">Explore Edge →</a></article>
          </div>
        </section>

        <section id="identity" className="section identity-section">
          <div className="shell split-layout">
            <div>
              <span className="kicker">AGENT IDENTITY</span>
              <h2>Know the autonomous actor at your door.</h2>
              <p className="section-lead">Agent Identity creates a distinct security subject for every agent without confusing it with the human, service account, or workload operating behind it.</p>
              <div className="identity-lifecycle" aria-label="Agent Identity lifecycle">
                {['Register','Prove','Issue','Present','Verify','Authorize','Rotate','Revoke'].map((step, index) => <div key={step}><span>{String(index + 1).padStart(2, '0')}</span><b>{step}</b></div>)}
              </div>
              <p className="boundary-note"><b>Identity is not permission.</b> V0.1 verifies the issuer’s signed claim. Proving that the current presenter controls the agent requires proof-of-possession or attestation.</p>
            </div>
            <div className="trust-card">
              <div className="card-head"><span>identity://verification</span><b>LIVE</b></div>
              <dl><div><dt>AGENT</dt><dd>agp://cairo/procurement-8472</dd></div><div><dt>ISSUER</dt><dd>Cairo Agent Guard CA</dd></div><div><dt>PRINCIPAL</dt><dd>org://acme</dd></div><div><dt>KEY</dt><dd>root-2026</dd></div><div><dt>VALIDITY</dt><dd className="good">CURRENT</dd></div><div><dt>REVOCATION</dt><dd className="good">CLEAR</dd></div></dl>
              <div className="trust-result"><span>TRUST STATE</span><strong>VERIFIED CLAIM</strong></div>
            </div>
          </div>
        </section>

        <section id="protocol" className="section protocol-section">
          <div className="shell">
            <div className="section-heading light"><div><span className="kicker">AGENT GUARD PROTOCOL</span><h2>The shared trust language for autonomous actors.</h2></div><p>AGP lets independent agents, runtimes, services, and auditors describe authority with the same deterministic objects and effects.</p></div>
            <div className="protocol-flow"><div><span>01</span><b>Identity</b><small>Who?</small></div><i>→</i><div><span>02</span><b>Mission</b><small>Why?</small></div><i>→</i><div><span>03</span><b>Capability</b><small>What?</small></div><i>→</i><div><span>04</span><b>Risk</b><small>What changed?</small></div><i>→</i><div className="active"><span>05</span><b>Decision</b><small>Enforce</small></div></div>
            <div className="protocol-content">
              <div className="code-panel"><div className="code-head"><span>AgentRequest.json</span><button type="button" onClick={copyRequest}>{copyLabel}</button></div><pre>{requestExample}</pre></div>
              <div className="decision-panel"><span className="kicker">DECISION VOCABULARY</span><h3>Beyond allow or deny.</h3><p>Express constraints, approvals, sanitation, redirection, isolation, quarantine, and termination in one interoperable result.</p><div className="decision-cloud">{decisions.map((decision) => <span key={decision}>{decision}</span>)}</div></div>
            </div>
          </div>
        </section>

        <section id="edge" className="section edge-section shell">
          <div className="section-heading"><div><span className="kicker">AGENT GUARD EDGE</span><h2>Protect your platform from agents.</h2></div><p>External agent authority is never automatically accepted. Edge intersects verified authority with your platform’s own policy before the request reaches an API, tool, data store, or device.</p></div>
          <div className="edge-pipeline"><div><span>01</span><b>Discover</b><small>Agent-aware ingress</small></div><div><span>02</span><b>Verify</b><small>Identity + authority</small></div><div><span>03</span><b>Classify</b><small>Trust state</small></div><div><span>04</span><b>Authorize</b><small>Local policy</small></div><div><span>05</span><b>Enforce</b><small>Before upstream</small></div><div><span>06</span><b>Record</b><small>Security evidence</small></div></div>
          <div className="edge-grid">
            <div className="edge-map"><div className="edge-origin">External autonomous actor</div><div className="edge-core"><img src="/AgentGuard/cairo-logo.svg" alt="" /><b>AGENT GUARD EDGE</b><span>Platform sovereignty boundary</span></div><div className="edge-targets"><span>API</span><span>SaaS</span><span>MCP</span><span>DATA</span><span>COMMERCE</span><span>DEVICE</span></div></div>
            <div className="trust-states"><h3>Trust is a live state.</h3><div><b className="verified">VERIFIED</b><span>Continue to authority and policy.</span></div><div><b className="constrained">CONSTRAINED</b><span>Narrow routes, methods, budgets, or data.</span></div><div><b className="challenged">CHALLENGED</b><span>Require stronger evidence or approval.</span></div><div><b className="unknown">UNKNOWN</b><span>Isolate or deny sensitive access.</span></div><div><b className="revoked">REVOKED</b><span>Deny and link a security incident.</span></div><div><b className="hostile">HOSTILE</b><span>Quarantine and propagate intelligence.</span></div></div>
          </div>
          <p className="boundary-note centered"><b>Product boundary:</b> V0.1 ships Edge architecture and reference enforcement primitives. Distributed replay, semantic DLP, behavior detection, global control plane, HA, and SLAs remain managed-platform work.</p>
        </section>

        <section id="runtime" className="section runtime-section">
          <div className="shell">
            <div className="section-heading light"><div><span className="kicker">AGENT GUARD RUNTIME</span><h2>Protect the world from your agent.</h2></div><p>The model can reason about actions. Only the external Guardian can authorize and execute them.</p></div>
            <div className="runtime-diagram"><div className="runtime-agent"><span>UNTRUSTED</span><b>Agent / model process</b><small>Proposes actions</small></div><div className="runtime-arrow">↓</div><div className="runtime-kernel"><img src="/AgentGuard/cairo-logo.svg" alt="" /><span>TRUSTED ENFORCEMENT</span><b>Agent Guard Kernel</b><small>Identity · mission · capability · replay · risk · revocation</small></div><div className="runtime-arrow">↓</div><div className="runtime-targets">{['MCP','TOOLS','SHELL','FILES','NETWORK','SECRETS','DELEGATION','CLOUD','PAIP'].map((item) => <span key={item}>{item}</span>)}</div></div>
            <div className="controls-grid"><article><span>01</span><h3>Capability control</h3><p>Short-lived, mission-bound, revocable authority instead of raw credentials.</p></article><article><span>02</span><h3>Delegation guard</h3><p>Every child remains a strict subset of parent scope, time, risk, and depth.</p></article><article><span>03</span><h3>Blind secrets</h3><p>Perform authenticated work without revealing credentials to the model.</p></article><article><span>04</span><h3>Replay defense</h3><p>Reject reused request IDs, nonces, and stale authorization envelopes.</p></article><article><span>05</span><h3>Quarantine trees</h3><p>Stop an agent and its known delegated descendants immediately.</p></article><article><span>06</span><h3>Flight recorder</h3><p>Hash-chain structured actions without collecting private chain-of-thought.</p></article></div>
          </div>
        </section>

        <section className="section architecture-section shell">
          <div className="section-heading"><div><span className="kicker">DEPLOYMENT ARCHITECTURE</span><h2>Policy centralization.<br />Enforcement everywhere.</h2></div><p>A high-assurance deployment separates fast, local request decisions from administrative authority and global intelligence.</p></div>
          <div className="plane-grid"><article><span>DATA PLANE</span><h3>Decide in the path.</h3><ul><li>Canonical request parsing</li><li>Identity and capability verification</li><li>Mission, replay, revocation, and risk</li><li>Gateway enforcement and response limits</li><li>Structured security telemetry</li></ul></article><article><span>CONTROL PLANE</span><h3>Govern the fleet.</h3><ul><li>Issuer and key trust</li><li>Policy distribution and versioning</li><li>Revocation and threat intelligence</li><li>Agent registry and certification</li><li>Incidents, evidence, and operations</li></ul></article></div>
          <div className="nonbypass"><b>NON-BYPASSABILITY</b><p>The agent must have no alternate route to tools, upstream services, credentials, network egress, protected files, or physical actuators.</p></div>
        </section>

        <section className="section cairo-section">
          <div className="shell split-layout">
            <div><span className="kicker">CAIRO SUPER AGENT</span><h2>Cairo Super Agent security beneath the planner—not inside the prompt.</h2><p className="section-lead">Every Cairo run receives a signed identity, principal, mission, capability, session, policy hash, and risk state. Direct executor handles never enter model-controlled code.</p><ul className="check-list"><li>Tools and MCP</li><li>Shell and filesystem</li><li>Network and credentials</li><li>Purchases and cloud</li><li>Delegated agents</li><li>PAIP and physical AI</li></ul></div>
            <div className="code-panel cairo-code"><div className="code-head"><span>CairoExecutionGateway.ts</span><span>REFERENCE CONTRACT</span></div><pre>{`await gateway.execute(
  gateway.beforeToolCall(
    securityContext,
    "crm",
    "read_customer"
  ),
  () => crm.call("read_customer")
);`}</pre><div className="code-status"><span>Identity</span><b>BOUND</b><span>Gateway</span><b>MANDATORY</b><span>Bypass</span><b>NONE</b></div></div>
          </div>
        </section>

        <section id="certification" className="section certification-section shell">
          <div className="section-heading"><div><span className="kicker">AGENT GUARD CERTIFICATION</span><h2>Turn security claims into evidence.</h2></div><p>Apply measurable assurance profiles to agents, runtimes, platforms, MCP servers, and physical AI systems.</p></div>
          <div className="levels"><article><b>AGP-L1</b><span>Identity Ready</span><small>Identity · principal · revocation</small></article><article><b>AGP-L2</b><span>Capability Controlled</span><small>Mission · least authority · audit</small></article><article><b>AGP-L3</b><span>Runtime Protected</span><small>Non-bypassable enforcement</small></article><article><b>AGP-L4</b><span>High Assurance</span><small>Attestation · independent validation</small></article><article><b>AGP-P</b><span>Physical AI</span><small>PAIP · safety controller · E-stop</small></article></div>
          <div className="cert-flow"><span>Apply</span><i>→</i><span>Scope</span><i>→</i><span>Evidence</span><i>→</i><span>Conformance</span><i>→</i><span>Validation</span><i>→</i><span>Certificate</span></div>
          <form className="cert-form" onSubmit={submitCertification}>
            <div className="form-intro"><span className="kicker">START AN ASSESSMENT</span><h3>Apply for Agent Guard certification.</h3><p>Your submission begins scoping and evidence review. It is not itself a certificate or conformance claim.</p></div>
            <div className="form-fields"><label>Organization<input name="organization" required maxLength={160} placeholder="Acme AI" /></label><label>Work email<input name="email" type="email" required maxLength={254} placeholder="security@company.com" /></label><label>Certification target<select name="target" defaultValue="AI Agent"><option>AI Agent</option><option>Agent Runtime / Harness</option><option>Platform / API</option><option>MCP Server</option><option>Physical AI System</option></select></label><label>Requested level<select name="level" defaultValue="AGP-L1"><option>AGP-L1</option><option>AGP-L2</option><option>AGP-L3</option><option>AGP-L4</option><option>AGP-P</option></select></label><label className="honeypot" aria-hidden="true">Company website<input name="companyWebsite" tabIndex={-1} autoComplete="off" /></label><label className="full">Architecture and security boundary<textarea name="summary" required minLength={40} maxLength={4000} placeholder="Describe the system, deployment model, trust boundary, and current security controls…" /></label><div className="form-action full"><button className="button" disabled={submitting} type="submit">{submitting ? "Submitting…" : "Apply for certification"}</button><span className={formError ? "form-status error" : "form-status"} role="status" aria-live="polite">{formStatus}</span></div></div>
          </form>
        </section>

        <section id="docs" className="section docs-section">
          <div className="shell"><div className="section-heading light"><div><span className="kicker">DOCUMENTATION</span><h2>Build on Agent Guard.</h2></div><p>Move from product model to implementation details without leaving the site.</p></div><div className="docs-layout"><aside aria-label="Documentation topics">{Object.entries(docs).map(([key, doc]) => <button key={key} type="button" className={activeDoc === key ? "active" : ""} onClick={() => setActiveDoc(key)}>{doc.label}<span>→</span></button>)}</aside><article className="doc-content" tabIndex={-1}><span className="doc-index">AGENT GUARD DOCS / {activeDoc.toUpperCase()}</span><h3>{active.title}</h3>{active.body}<div className="doc-links"><a href="https://github.com/ColomboAI-com/cairo-agent-guard">GitHub repository ↗</a><a href="https://github.com/ColomboAI-com/cairo-agent-guard/blob/main/README.md">Full README ↗</a></div></article></div></div>
        </section>

        <section id="quickstart" className="section open-section shell">
          <div className="open-grid"><div><span className="kicker">OPEN FOUNDATION</span><h2>Open protocol.<br />Open core.<br />Interoperable trust.</h2><p>Agent Identity schemas, AGP, deterministic runtime, SDKs, Edge architecture, reference adapters, certification profiles, and the threat model are open under Apache-2.0.</p><div className="hero-actions"><a className="button" href="https://github.com/ColomboAI-com/cairo-agent-guard">Explore the repository</a><a className="button button-ghost" href="#docs">Read the docs</a></div></div><div className="repo-tree"><pre>{`cairo-agent-guard/
├── spec/AGP-v0.1.md
├── schemas/
├── src/agentguard/
├── packages/sdk-ts/
├── integrations/
│   ├── cairo/
│   └── mcp/
├── docs/
│   ├── IDENTITY-INTEGRATION.md
│   └── AGENT-GUARD-EDGE.md
├── security/
└── website/`}</pre></div></div>
        </section>

        <section className="finale shell"><div className="finale-logo"><img src="/AgentGuard/cairo-logo.svg" alt="" /></div><span className="kicker">CAIRO AGENT GUARD</span><h2>Autonomous intelligence needs autonomous security.</h2><p>Build agents that can become more capable without silently becoming more powerful.</p><div className="hero-actions"><a className="button" href="#quickstart">Start integrating</a><a className="button button-ghost" href="#certification">Get certified</a></div></section>
      </main>

      <footer><div className="shell footer-grid"><div className="brand footer-brand"><img src="/AgentGuard/cairo-logo.svg" alt="" /><span><b>Cairo</b> Agent Guard</span></div><p>Agentic security infrastructure by ColomboAI.</p><div><a href="https://github.com/ColomboAI-com/cairo-agent-guard">GitHub</a><a href="#docs">Documentation</a><a href="#certification">Certification</a></div><div><span>Cairo.sh/AgentGuard</span><span>V0.1 Foundation</span><span>© 2026 ColomboAI Inc.</span></div></div></footer>
    </>
  );
}
