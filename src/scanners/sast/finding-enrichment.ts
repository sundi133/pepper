import * as fs from "fs";
import * as path from "path";
import { RawFinding } from "../types";
import { ArchitectureSummary, matchRouteForFile } from "./architecture";
import { analyzeTaintAroundLine } from "./taint-heuristics";
import {
  cweToOwasp,
  inferOwaspFromText,
  normalizeCweId,
} from "@/lib/owasp-cwe";

export interface SastEngineMetadata {
  owaspCategory?: string;
  owaspTop10Id?: string;
  sourceToSinkExplanation?: string;
  inferredSources?: string[];
  sanitizerNearby?: boolean;
  /** Only populated when heuristic mapping succeeds — never invented URLs */
  httpSurface?: {
    routePattern?: string;
    method?: string;
    parameterHint?: string;
    headerHint?: string;
    cookieHint?: string;
    jsonFieldHint?: string;
    injectionContext?: string;
  };
  falsePositiveReasoning?: string;
  /** When true, UI/report should show "Needs manual validation" */
  needsManualValidation?: boolean;
  safePayloadHint?: string;
}

const XSS_SAFE_PAYLOAD = "<script>alert(1)</script>";

function readLimitedFile(workDir: string, rel: string, maxBytes = 400_000): string | null {
  const full = path.join(workDir, rel);
  try {
    const st = fs.statSync(full);
    if (st.size > maxBytes) return null;
    return fs.readFileSync(full, "utf-8");
  } catch {
    return null;
  }
}

function classifyNeedsManualValidation(f: RawFinding): boolean {
  const conf = f.confidence ?? 0.75;
  if (conf < 0.82) return true;
  if (f.scanner === "SAST_PATTERN") {
    const title = (f.title + f.description).toLowerCase();
    if (/potential|may |might |could /.test(title)) return true;
  }
  return false;
}

function buildFalsePositiveReasoning(
  f: RawFinding,
  taint: { inferredSources: string[]; sanitizerNearby: boolean },
  manual: boolean,
): string {
  const parts: string[] = [];
  parts.push(
    `Evidence is anchored at ${f.filePath || "unknown path"} line ${f.startLine ?? "?"}.`,
  );
  if (taint.sanitizerNearby) {
    parts.push(
      "A sanitizer or validator appears near this sink — treat as lower certainty unless you confirm the sanitizer covers all paths.",
    );
  }
  if (taint.inferredSources.length === 0 && !manual) {
    parts.push(
      "No obvious HTTP input reference in the local window — the finding may still be valid if data crosses files.",
    );
  }
  if (manual) {
    parts.push(
      "Marked as **Needs manual validation** due to confidence or generic pattern match.",
    );
  } else {
    parts.push(
      "Automated reasoning supports prioritizing this issue for manual confirmation on authorized targets.",
    );
  }
  return parts.join(" ");
}

function inferHttpSurface(
  f: RawFinding,
  arch: ArchitectureSummary,
  content: string | null,
  sinkLine: number,
): SastEngineMetadata["httpSurface"] {
  const matched = f.filePath ? matchRouteForFile(f.filePath, arch) : undefined;
  const surface: NonNullable<SastEngineMetadata["httpSurface"]> = {};

  if (matched?.pattern) {
    surface.routePattern = matched.pattern;
    if (matched.method) surface.method = matched.method;
  }

  if (!content) return Object.keys(surface).length ? surface : undefined;

  const lines = content.split(/\r?\n/);
  const idx = Math.min(Math.max(sinkLine - 1, 0), lines.length - 1);
  const line = lines[idx] || "";
  const haystack = lines.slice(Math.max(0, idx - 15), idx + 1).join("\n");

  const paramMatch =
    haystack.match(
      /(?:req|request|params|searchParams|body)\.(?:query\.)?([a-zA-Z0-9_$]+)/,
    ) || line.match(/(?:['"])([a-zA-Z0-9_-]+)(?:['"])\s*:/);
  if (paramMatch?.[1]) surface.parameterHint = paramMatch[1];

  if (/req\.headers|headers\[|getHeader/i.test(haystack)) {
    surface.headerHint = "Review Host, Authorization, X-* headers reaching this code path";
  }
  if (/cookies|cookie|req\.signedCookies/i.test(haystack)) {
    surface.cookieHint = "Session or tracking cookies influencing this path";
  }
  if (/JSON\.parse|request\.json|body\.|z\.object|\.json\s*\(/i.test(haystack)) {
    surface.jsonFieldHint =
      surface.parameterHint || "JSON body field (verify schema vs. usage)";
  }

  const title = `${f.title} ${f.description}`.toLowerCase();
  if (/xss|dangerouslysetinnerhtml|innerhtml/i.test(title)) {
    surface.injectionContext = "HTML/DOM context — verify output encoding and CSP";
    surface.routePattern = surface.routePattern || matched?.pattern;
  }
  if (/sql|query|execute/i.test(title)) {
    surface.injectionContext = "SQL or query string construction";
  }

  return Object.keys(surface).length ? surface : undefined;
}

function safePayloadForFinding(f: RawFinding): string | undefined {
  const t = `${f.title} ${f.description}`.toLowerCase();
  if (/xss|cross-site scripting|cwe-79|innerhtml|dangerouslysetinnerhtml/.test(t)) {
    return XSS_SAFE_PAYLOAD;
  }
  if (/sql|cwe-89|injection/.test(t)) {
    return "' OR '1'='1";
  }
  if (/command|rce|cwe-78|shell/.test(t)) {
    return "Use argv separation tests in a sandbox only; avoid destructive shell probes.";
  }
  return undefined;
}

/**
 * Enrich scanner findings with OWASP mapping, taint hints, and HTTP surface heuristics.
 */
export function enrichFindingsWithSastEngine(
  findings: RawFinding[],
  workDir: string,
  arch: ArchitectureSummary,
): RawFinding[] {
  return findings.map((f) => enrichOne(f, workDir, arch));
}

function enrichOne(
  f: RawFinding,
  workDir: string,
  arch: ArchitectureSummary,
): RawFinding {
  const cweNorm = normalizeCweId(f.cweId);
  const owasp = cweToOwasp(cweNorm) || inferOwaspFromText(`${f.title} ${f.description} ${f.ruleId || ""}`);

  let content: string | null = null;
  if (f.filePath && f.startLine) {
    content = readLimitedFile(workDir, f.filePath);
  }

  const sinkLine = f.startLine ?? 1;
  const taint =
    content && f.startLine
      ? analyzeTaintAroundLine(content, f.startLine, f.title)
      : {
          inferredSources: [] as string[],
          sanitizerNearby: false,
          sourceToSinkSummary: "Source-to-sink trace was not computed (missing file or line).",
        };

  const manual = classifyNeedsManualValidation(f);
  const httpSurface = inferHttpSurface(f, arch, content, sinkLine);

  const engine: SastEngineMetadata = {
    owaspCategory: owasp?.name,
    owaspTop10Id: owasp?.id,
    sourceToSinkExplanation: taint.sourceToSinkSummary,
    inferredSources: taint.inferredSources,
    sanitizerNearby: taint.sanitizerNearby,
    httpSurface,
    falsePositiveReasoning: buildFalsePositiveReasoning(
      f,
      {
        inferredSources: taint.inferredSources,
        sanitizerNearby: taint.sanitizerNearby,
      },
      manual,
    ),
    needsManualValidation: manual,
    safePayloadHint: safePayloadForFinding(f),
  };

  const metadata = {
    ...(typeof f.metadata === "object" && f.metadata ? f.metadata : {}),
    cweId: cweNorm || f.cweId,
    sastEngine: engine,
  };

  return { ...f, cweId: cweNorm || f.cweId, metadata };
}
