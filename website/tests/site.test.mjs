import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

test("production bundle contains the Agent Guard application", () => {
  assert.equal(existsSync("dist/server/index.js"), true);
  assert.equal(existsSync("dist/client/og.png"), true);
  assert.equal(existsSync("dist/client/agentguard-launch-og.png"), true);

  const source = readFileSync("app/site-client.tsx", "utf8");
  assert.match(source, /Agent Identity/);
  assert.match(source, /Agent Guard Protocol/);
  assert.match(source, /Agent Guard Edge/);
  assert.match(source, /Apply for Agent Guard certification/);
  assert.match(source, /Every AI Agent Needs an/);
  assert.match(source, /WHY AGENT GUARD \/ WHY NOW/);
  assert.match(source, /INTEGRATIONS & ECOSYSTEM/);
  assert.match(source, /FREQUENTLY ASKED QUESTIONS/);
  assert.match(source, /Search documentation/);
  assert.match(source, /agentguard-certification-draft/);
});

test("the launch page preserves canonical metadata and the production route", () => {
  const layout = readFileSync("app/layout.tsx", "utf8");
  const config = readFileSync("next.config.ts", "utf8");
  assert.match(layout, /canonical: "\/AgentGuard"/);
  assert.match(layout, /Identity, containment, certification, and platform defense/);
  assert.match(config, /basePath: "\/AgentGuard"/);
});

test("hosting package declares durable certification storage", () => {
  const hosting = JSON.parse(readFileSync(".openai/hosting.json", "utf8"));
  assert.equal(hosting.d1, "DB");
  assert.equal(hosting.r2, null);
  assert.equal(existsSync("drizzle/0000_lethal_marvel_boy.sql"), true);
});

test("visible Cairo logos are self-contained across reverse proxies", () => {
  const source = readFileSync("app/site-client.tsx", "utf8");
  assert.match(source, /function CairoLogo/);
  assert.doesNotMatch(source, /\/AgentGuard\/cairo-logo\.svg/);
});

test("the legacy logo URL returns a dynamic proxy-safe SVG", () => {
  const route = readFileSync("app/cairo-logo.svg/route.ts", "utf8");
  assert.match(route, /image\/svg\+xml/);
  assert.match(route, /new Response\(CAIRO_LOGO_SVG/);
  assert.doesNotMatch(route, /x-vinext-static-file/);
});

test("critical product information uses the readable typography baseline", () => {
  const styles = readFileSync("app/globals.css", "utf8");
  assert.match(styles, /\.topbar nav, \.button \{ font-size: 14px; \}/);
  assert.match(styles, /\.identity-lifecycle b \{ font-size: 14px; \}/);
  assert.match(styles, /\.runtime-targets span,[\s\S]*?font-size: 12px;/);
  assert.match(styles, /\.doc-content p, \.doc-content li \{ font-size: 15px; \}/);
  assert.match(styles, /\.footer-grid p, \.footer-grid span, \.footer-grid a \{ font-size: 13px; \}/);
  assert.doesNotMatch(styles, /\.hero-flow \{[^}]*font-size: 7px;/);
});
