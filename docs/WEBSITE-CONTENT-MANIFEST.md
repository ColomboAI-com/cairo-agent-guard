# Agent Guard website content preservation manifest

This manifest records the public content and behavior present before the 2026 launch-experience redesign and where each item remains afterward. It is a regression contract for `https://cairo.sh/AgentGuard`.

## Route, metadata, and brand

| Before | Preserved after | Implementation |
| --- | --- | --- |
| Production route `/AgentGuard` | Yes | `website/next.config.ts` base path |
| Cairo Agent Guard name and Cairo logo | Yes | Header, hero security boundary, runtime, Edge, final CTA, footer |
| Product description covering Identity, AGP, Runtime, and Edge | Yes, expanded | Metadata, hero, pillars, documentation |
| Open Graph and X/Twitter preview | Yes | `website/app/layout.tsx` and `website/public/og.png` |
| GitHub repository URL | Yes | Hero/open-source, integrations, docs, footer |
| Apache-2.0 open-source statement | Yes | Open foundation and FAQ |

## Sections and claims

| Existing section | Preserved after | Notes |
| --- | --- | --- |
| Hero: intelligence is not authority | Yes | New identity-led headline; invariant retained verbatim |
| Identify / Control / Defend / Prove outcomes | Yes | Proof strip retained |
| Agent Identity | Yes | Lifecycle, signed claim, principal binding, validity, revocation, V0.1 HMAC/federation boundary retained |
| Agent Guard Protocol | Yes | Request example, object model, ten decision effects, default-deny and delegation invariants retained |
| Agent Guard Edge | Yes | Discover/verify/classify/authorize/enforce/record pipeline, trust states, targets, and managed-platform boundary retained |
| Runtime | Yes | Non-bypassable Guardian, executor targets, six controls, and reference contract retained |
| Deployment architecture | Yes | Data plane, control plane, and non-bypassability requirement retained |
| Cairo Super Agent | Yes | Security context, mandatory gateway, and protected surfaces retained |
| Certification | Yes | AGP-L1 through AGP-L4 and AGP-P, six-step flow, caveat, and application form retained |
| Documentation | Yes | All ten topics, code examples, GitHub links; search added |
| Open foundation | Yes | Repository tree, open-core scope, GitHub/docs CTAs retained |
| Final CTA and footer | Yes | Integration, certification, brand, version, ownership, GitHub/docs links retained |

## Certification application contract

The form continues to submit JSON to `/AgentGuard/api/certification/applications` and preserves every field and constraint:

- `organization`: required, 160 characters maximum.
- `email`: required work email, 254 characters maximum.
- `target`: AI Agent, Agent Runtime / Harness, Platform / API, MCP Server, or Physical AI System.
- `level`: AGP-L1, AGP-L2, AGP-L3, AGP-L4, or AGP-P.
- `summary`: required architecture/security boundary, 40–4,000 characters.
- `companyWebsite`: inaccessible honeypot for automated abuse.

The D1 storage binding, schema, migration, validation, success response, error response, and certification caveat are unchanged. The redesign adds recoverable draft persistence in `sessionStorage`, prevents duplicate submission while a request is in flight, and clears the draft only after success.

## New launch content

- Identity-led hero: “Every AI Agent Needs an Identity.”
- “Why Agent Guard / Why now” threat narrative.
- Five-pillar system model: Identity, Runtime, Policy, Certification, Platform Defense.
- Integration and ecosystem matrix.
- Searchable documentation navigation.
- Product-boundary FAQ.
- Active-section navigation and responsive/mobile refinements.

## Technical boundaries retained

- Identity is not permission.
- V0.1 uses locally pinned symmetric HMAC and is not a cross-organization federation system.
- Proof-of-possession and signed approval consumption remain next-protocol work.
- V0.1 Edge is architecture and reference primitives, not a managed distributed service.
- Non-bypassability requires deployment isolation and removal of alternate execution paths.
- AGP-P does not replace an independent physical safety controller or emergency stop.

