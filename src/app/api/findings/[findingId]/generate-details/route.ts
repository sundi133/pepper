import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getActiveOrgId, requireRole } from "@/lib/auth-guard";
import { getLlmConfig } from "@/lib/llm-gateway";
import {
  generateFindingDetails,
  type GeneratedDetails,
} from "@/lib/generate-finding-details";

/**
 * How long a request waits for the model. Generation keeps running after
 * this and saves its result, so the next request returns it (issue #213:
 * the browser used to wait 100s+ for a slow provider).
 */
const DETAILS_WAIT_MS = 45_000;

type Outcome =
  | { kind: "ok"; details: GeneratedDetails }
  | { kind: "unparseable" }
  | { kind: "provider-error"; message: string };

/**
 * One generation per finding at a time: reopening a finding, or several
 * panels asking at once, joins the running call instead of starting another.
 */
const inFlight = new Map<string, Promise<Outcome>>();

function startGeneration(
  finding: {
    id: string;
    title: string;
    cweId: string | null;
    severity: string;
    filePath: string | null;
    startLine: number | null;
    endLine: number | null;
    description: string | null;
  },
  config: ReturnType<typeof getLlmConfig>,
): Promise<Outcome> {
  const running = inFlight.get(finding.id);
  if (running) return running;

  const job = (async (): Promise<Outcome> => {
    try {
      const details = await generateFindingDetails(finding, config);
      if (!details) return { kind: "unparseable" };
      // Re-read metadata so a status change or other update made while the
      // model was running isn't overwritten.
      const current = await prisma.finding.findUnique({
        where: { id: finding.id },
        select: { metadata: true },
      });
      await prisma.finding.update({
        where: { id: finding.id },
        data: {
          metadata: {
            ...((current?.metadata as Record<string, unknown> | null) ?? {}),
            generatedDetails: details,
          } as object,
        },
      });
      return { kind: "ok", details };
    } catch (error) {
      console.error(`Error generating vulnerability details for ${finding.id}:`, error);
      return {
        kind: "provider-error",
        message: error instanceof Error ? error.message.slice(0, 200) : "AI provider error",
      };
    } finally {
      inFlight.delete(finding.id);
    }
  })();
  inFlight.set(finding.id, job);
  return job;
}

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ findingId: string }> }
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { findingId } = await params;
  const orgId = await getActiveOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const roleAuth = await requireRole(orgId, "DEVELOPER");
  if ("error" in roleAuth) return roleAuth.error;

  const finding = await prisma.finding.findFirst({
    where: { id: findingId },
    include: {
      scan: {
        select: {
          projectId: true,
          project: {
            select: {
              organizationId: true,
              organization: {
                select: {
                  settings: true,
                },
              },
            },
          },
        },
      },
    },
  });

  if (!finding || finding.scan?.project?.organizationId !== orgId) {
    return NextResponse.json({ error: "Finding not found" }, { status: 404 });
  }

  // Details generated at scan completion (or by an earlier request) are
  // returned as-is; ?regenerate=1 asks for a fresh write-up.
  const regenerate = new URL(req.url).searchParams.get("regenerate") === "1";
  const stored = (finding.metadata as Record<string, unknown> | null)?.generatedDetails;
  if (stored && typeof stored === "object" && !regenerate) {
    return NextResponse.json(stored);
  }

  const config = getLlmConfig(
    finding.scan?.project?.organization?.settings as Record<string, unknown> | null
  );
  if (!config.apiKey && config.provider !== "ollama") {
    return NextResponse.json(
      { error: "No AI model is configured. Add one in Settings → AI Models." },
      { status: 409 },
    );
  }

  const job = startGeneration(
    {
      id: finding.id,
      title: finding.title,
      cweId: finding.cweId,
      severity: finding.severity,
      filePath: finding.filePath,
      startLine: finding.startLine,
      endLine: finding.endLine,
      description: finding.description,
    },
    config,
  );

  let timer: ReturnType<typeof setTimeout> | undefined;
  const timedOut = new Promise<"timeout">((resolve) => {
    timer = setTimeout(() => resolve("timeout"), DETAILS_WAIT_MS);
  });
  const outcome = await Promise.race([job, timedOut]);
  clearTimeout(timer);

  if (outcome === "timeout") {
    // Still running; it saves its result when done. Clients retry.
    return NextResponse.json(
      { status: "pending", message: "The AI model is still writing these details." },
      { status: 202, headers: { "Retry-After": "15" } },
    );
  }
  if (outcome.kind === "ok") return NextResponse.json(outcome.details);
  if (outcome.kind === "unparseable") {
    return NextResponse.json(
      { error: "The AI model returned details that couldn't be read. Try again." },
      { status: 502 },
    );
  }
  return NextResponse.json(
    { error: `The AI provider failed: ${outcome.message}` },
    { status: 502 },
  );
}
