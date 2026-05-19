import { NextRequest, NextResponse } from "next/server";
import { verifyApiKey } from "@/lib/api-key";
import { ALL_PATTERN_RULES as PATTERN_RULES } from "@/scanners/sast/pattern-rules";
import { scanLinesForSecrets } from "@/scanners/secrets/engine";

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
  const lines = file.content.split(/\r?\n/);

  for (const hit of scanLinesForSecrets(lines, file.path)) {
    findings.push({
      ruleId: hit.ruleId,
      title: hit.title,
      description: hit.description,
      severity: hit.severity,
      filePath: file.path,
      line: hit.startLine,
      snippet: hit.snippet,
      category: "secret",
      cweId: "CWE-798",
    });
  }
  // SAST pattern rules (lightweight pass)
  for (const rule of PATTERN_RULES) {
    rule.pattern.lastIndex = 0;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!rule.pattern.test(line)) {
        rule.pattern.lastIndex = 0;
        continue;
      }
      rule.pattern.lastIndex = 0;
      if (rule.negative && rule.negative.test(line)) continue;
      findings.push({
        ruleId: rule.id,
        title: rule.title,
        description: rule.description,
        severity: rule.severity,
        filePath: file.path,
        line: i + 1,
        snippet: `${i + 1}: ${line.trim().slice(0, 240)}`,
        category: "sast",
        cweId: rule.cweId,
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
