import { NextRequest, NextResponse } from "next/server";
import { verifyApiKey } from "@/lib/api-key";
import { SECRET_PATTERNS } from "@/lib/precommit-secret-patterns";
import { isCredibleSecretMatch } from "@/scanners/secrets/patterns";

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

function maskMatch(value: string): string {
  return value.length <= 8 ? "****" : `${value.slice(0, 4)}****${value.slice(-2)}`;
}

function detectInFile(file: PrecommitFile): PrecommitFinding[] {
  const findings: PrecommitFinding[] = [];
  const lines = file.content.split("\n");

  // Text already reported: a later, more general detector doesn't report it again.
  const reportedSpans: Array<[number, number]> = [];
  for (const pattern of SECRET_PATTERNS) {
    // Keep the pattern's own flags (e.g. case-insensitive) and add g + m.
    const flags = new Set([...(pattern.pattern.flags ?? ""), "g", "m"]);
    const regex = new RegExp(pattern.pattern.source, [...flags].join(""));
    const matches = file.content.matchAll(regex);
    for (const match of matches) {
      if (pattern.allowlist?.some((allow) => allow.test(match[0]))) continue;
      const lineNum = file.content.substring(0, match.index).split("\n").length - 1;
      // Same bar as the repository scan: no placeholders, examples, templates or local defaults.
      // (A private key header alone still blocks: the content here may be a partial file.)
      const type = pattern.id.replace(/^SECRET-/, "").replace(/-\d+$/, "");
      if (!isCredibleSecretMatch(type, match[0], lines[lineNum] || "", file.path)) continue;
      const span: [number, number] = [match.index ?? 0, (match.index ?? 0) + match[0].length];
      if (reportedSpans.some(([a, b]) => span[0] < b && a < span[1])) continue;
      reportedSpans.push(span);
      // Never echo the secret back: mask it in the reported line.
      const line = (lines[lineNum] || "").split(match[0]).join(maskMatch(match[0]));
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
