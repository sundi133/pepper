import { NextRequest, NextResponse } from "next/server";
import { verifyApiKey } from "@/lib/api-key";
import { SECRET_PATTERNS } from "@/scanners/secrets/patterns";
import { ALL_PATTERN_RULES as PATTERN_RULES } from "@/scanners/sast/pattern-rules";
import { isHighEntropy, extractCandidateValues } from "@/scanners/secrets/entropy";
import { maskSnippet } from "@/scanners/secrets/masker";

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
  // Secret patterns
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const p of SECRET_PATTERNS) {
      if (p.pattern.test(line)) {
        if (p.allowlist?.some((al) => al.test(line))) {
          p.pattern.lastIndex = 0;
          continue;
        }
        findings.push({
          ruleId: p.id,
          title: p.title,
          description: p.description,
          severity: p.severity,
          filePath: file.path,
          line: i + 1,
          snippet: maskSnippet(`${i + 1}: ${line}`, [p.pattern]),
          category: "secret",
          cweId: "CWE-798",
        });
        p.pattern.lastIndex = 0;
      }
      p.pattern.lastIndex = 0;
    }
    const candidates = extractCandidateValues(line);
    for (const c of candidates) {
      if (
        isHighEntropy(c) &&
        /(?:key|secret|token|password|credential|auth|api)/i.test(line)
      ) {
        findings.push({
          ruleId: "ENTROPY_SECRET",
          title: "High-Entropy String in Secret Context",
          description:
            "A high-entropy string in a secret-like context. Move to env vars or a secret manager.",
          severity: "MEDIUM",
          filePath: file.path,
          line: i + 1,
          snippet: `${i + 1}: [MASKED HIGH-ENTROPY VALUE]`,
          category: "secret",
          cweId: "CWE-798",
        });
      }
    }
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
