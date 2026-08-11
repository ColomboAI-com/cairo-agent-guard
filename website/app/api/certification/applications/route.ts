import { getDb } from "../../../../db";
import { certificationApplications } from "../../../../db/schema";

const TARGETS = new Set([
  "AI Agent",
  "Agent Runtime / Harness",
  "Platform / API",
  "MCP Server",
  "Physical AI System",
]);

const LEVELS = new Set(["AGP-L1", "AGP-L2", "AGP-L3", "AGP-L4", "AGP-P"]);

function clean(value: unknown, maxLength: number): string {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

export async function POST(request: Request) {
  try {
    const payload = (await request.json()) as Record<string, unknown>;
    const organization = clean(payload.organization, 160);
    const email = clean(payload.email, 254).toLowerCase();
    const target = clean(payload.target, 80);
    const requestedLevel = clean(payload.level, 16);
    const summary = clean(payload.summary, 4000);
    const honeypot = clean(payload.companyWebsite, 200);

    if (honeypot) {
      return Response.json(
        { application_id: `cert_${crypto.randomUUID()}`, status: "received" },
        { status: 201 },
      );
    }

    if (!organization || !email.includes("@") || !TARGETS.has(target)) {
      return Response.json(
        { error: "Complete the required organization, email, and target fields." },
        { status: 400 },
      );
    }
    if (!LEVELS.has(requestedLevel) || summary.length < 40) {
      return Response.json(
        { error: "Select a certification level and provide at least 40 characters of architecture context." },
        { status: 400 },
      );
    }

    const applicationId = `cert_${crypto.randomUUID()}`;
    await getDb().insert(certificationApplications).values({
      id: applicationId,
      organization,
      email,
      target,
      requestedLevel,
      summary,
    });

    return Response.json(
      { application_id: applicationId, status: "received" },
      { status: 201 },
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unexpected error";
    return Response.json(
      {
        error: message.includes("no such table")
          ? "Certification intake is initializing. Please try again shortly."
          : "Application could not be submitted.",
      },
      { status: 500 },
    );
  }
}
