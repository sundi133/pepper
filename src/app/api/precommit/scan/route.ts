import { NextRequest, NextResponse } from "next/server";
import { verifyApiKey } from "@/lib/api-key";
import { SECRET_PATTERNS } from "@/lib/precommit-secret-patterns";

interface PrecommitFile {
  path: string;
  content: string;
}

interface PrecommitFinding {
  ruleId: string;
  title: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  filePath: string;
  line: number;
  snippet: string;
  category: "secret" | "sast";
  cweId?: string;
}

function detectInFile(file: PrecommitFile): PrecommitFinding[] {
  const findings: PrecommitFinding[] = [];
  const lines = file.content.split("\n");

  for (const pattern of SECRET_PATTERNS) {
    const regex = pattern.pattern instanceof RegExp
      ? new RegExp(pattern.pattern.source, "gm")
      : new RegExp(pattern.pattern, "gm");
    const matches = file.content.matchAll(regex);
    for (const match of matches) {
      if (pattern.allowlist?.some((allow) => allow.test(match[0]))) continue;
      const lineNum = file.content.substring(0, match.index).split("\n").length - 1;
      const line = lines[lineNum] || "";
      findings.push({
        ruleId: pattern.id,
        title: pattern.title,
        description: pattern.description,
        severity: pattern.severity,
        filePath: file.path,
        line: lineNum + 1,
        snippet: line.slice(0, 100),
        category: "secret",
      });
    }
  }
  return findings;
}

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req.headers.get("authorization"));
  if (!auth) {
    return NextResponse.json({ error: "Invalid or missing API key" }, { status: 401 });
  }

  let body: { files?: PrecommitFile[]; failOn?: string[] };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }
  if (!body.files || !Array.isArray(body.files)) {
    return NextResponse.json(
      { error: "Body must include `files: [{ path, content }, ...]`" },
      { status: 400 },
    );
  }

  const failOn = new Set(
    (body.failOn || ["CRITICAL", "HIGH"]).map((s) => s.toUpperCase()),
  );

  const allFindings: PrecommitFinding[] = [];
  for (const f of body.files) {
    if (!f.path || typeof f.content !== "string") continue;
    if (f.content.length > 2_000_000) continue;
    allFindings.push(...detectInFile(f));
  }

  const shouldFail = allFindings.some((f) => failOn.has(f.severity));

  return NextResponse.json({
    findings: allFindings,
    summary: {
      total: allFindings.length,
      bySeverity: countBySeverity(allFindings),
    },
    block: shouldFail,
    organizationId: auth.organizationId,
  });
}

function countBySeverity(findings: PrecommitFinding[]) {
  const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}
