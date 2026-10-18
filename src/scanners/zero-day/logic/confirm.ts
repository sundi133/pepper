/**
 * Confirmation of rule candidates (docs/LOGIC_FLAW_DETECTION_SPEC.md §4.4–4.5).
 * Each candidate is judged with only the code that matters to it; only
 * confirmed answers whose cited evidence verifies become findings.
 */
import type { RawFinding } from "../../types";
import { UNTRUSTED_CONTENT_GUARD } from "../../shared/prompts";
import { enrichFinding } from "../../shared/finding-normalize";
import { applySeverityCalibration, SEVERITY_CALIBRATION_PROMPT } from "@/lib/severity-calibration";
import { RULES, type Candidate } from "./rules";
import type { EntryPoint, LogicMap } from "./map";
import { SourceFiles, resolveKnownFile, verifyQuote } from "./source";

export const CONFIRM_SYSTEM_PROMPT = `You are a senior application security engineer. A deterministic comparison of an application's entry points found CANDIDATE authorization gaps: an entry point that lacks a control that related entry points, or the rest of the application, have. Decide for each candidate whether it is a real, exploitable flaw.

${UNTRUSTED_CONTENT_GUARD}

For EACH candidate:
1. EXPLOIT TEST — describe the concrete request (or job payload) a different user, a lower-privileged user or an anonymous caller sends, and what they get or change that they should not. If you cannot describe one from the code shown, the answer is not "confirmed".
2. DEFENCE TEST — look hard for a control the comparison missed: a group-level or global guard (see GROUP AND GLOBAL GUARDS), a base class or decorator on a parent, a check inside a helper the handler calls, a query that is in fact scoped to the caller, a framework default, or an entry point that is intentionally public (for example a public catalog or a login step). If such a control exists, the answer is "rejected" and you cite it.
3. Verdict: "confirmed" (exploit test succeeds and defence test finds nothing), "rejected" (a control exists, or the behaviour is intended), or "unsure" (code needed to decide is not shown).

Evidence for a confirmed candidate:
- "target": the line in the target's HANDLER code where the missing control should be (usually the data access or the first line of the handler) — file, line and a verbatim quote of that line. Use the registration line only when no handler is shown;
- "reference": a line that shows the control exists elsewhere (a guard on a reference entry point, an ownership record, a scoped query) — file, line and a verbatim quote.

Respond with JSON only:
{"results":[{"id":"C1","verdict":"confirmed","confidence":0.9,"severity":"HIGH","title":"…","description":"what is wrong and its impact, in two or three sentences","exploit":"the request and its result","defence":"what you looked for and did not find","recommendation":"the specific fix","evidence":{"target":{"file":"…","line":0,"quote":"…"},"reference":{"file":"…","line":0,"quote":"…"}}}]}

Use one result per candidate id. Titles must name the entry point (method and path, or job name). confidence: 0.90–1.0 when the exploit is fully visible; 0.80–0.89 when one minor detail is inferred; 0.72–0.79 when a control could exist in code that is not shown (then prefer "unsure"). Never invent routes, parameters or files.

${SEVERITY_CALIBRATION_PROMPT}`;

const describe = (e: EntryPoint) => {
  const guards = e.guards.map((g) => `${g.name}[${g.kind},${g.scope}${g.order === "after" ? ",after-handler" : ""}] ${g.file}:${g.line}`).join("; ") || "none found";
  const access = e.dataAccess.map((d) => `${d.op} ${d.resource} filtered by ${d.filteredBy} ${d.file}:${d.line}`).join("; ") || "none found";
  return `${e.kind} ${e.method} ${e.path || "(no path)"} registered ${e.file}:${e.line}${e.handler ? `, handler ${e.handler.name || "?"} ${e.handler.file}:${e.handler.startLine}-${e.handler.endLine}` : ""}\n  guards: ${guards}\n  data access: ${access}${e.privileged ? "\n  privileged: yes" : ""}${e.public ? "\n  public: yes" : ""}`;
};

const MAX_HANDLER_LINES = 120;

function codeFor(src: SourceFiles, e: EntryPoint): string {
  const blocks: string[] = [`${e.file} (registration)\n${src.numbered(e.file, e.line - 3, e.line + 3)}`];
  if (e.handler) {
    const end = Math.min(e.handler.endLine, e.handler.startLine + MAX_HANDLER_LINES);
    blocks.push(`${e.handler.file} (handler)\n${src.numbered(e.handler.file, e.handler.startLine, end)}`);
  }
  return blocks.join("\n\n");
}

export function confirmUserContent(src: SourceFiles, map: LogicMap, batch: Candidate[]): string {
  const wide = map.entryPoints.flatMap((e) => e.guards.filter((g) => g.scope === "group" || g.scope === "global"));
  const wideLines = [...new Map(wide.map((g) => [`${g.file}:${g.line}`, `${g.file}:${g.line}: ${src.line(g.file, g.line)?.trim() ?? g.quote}`])).values()].slice(0, 40);
  const parts = batch.map((c) => {
    const refs = c.references.map((r) => `REFERENCE ${describe(r)}\n${codeFor(src, r)}`).join("\n\n");
    const ev = c.evidence.map((l) => `${l.file}:${l.line}\n${src.numbered(l.file, l.line - 2, l.line + 2)}`).join("\n\n");
    const guardCode = c.target.guards
      .filter((g) => g.scope !== "in-handler")
      .map((g) => `${g.file}:${g.line} (${g.name})\n${src.numbered(g.file, g.line - 2, g.line + 12)}`)
      .join("\n\n");
    return [
      `═══ CANDIDATE ${c.id} — ${c.rule} ${RULES[c.rule].title}`,
      `The target appears to lack ${c.missing}.`,
      `TARGET ${describe(c.target)}`,
      codeFor(src, c.target),
      guardCode ? `TARGET GUARD CODE\n${guardCode}` : "",
      refs,
      ev ? `CONTROL SEEN ELSEWHERE\n${ev}` : "",
    ]
      .filter(Boolean)
      .join("\n\n");
  });
  return `GROUP AND GLOBAL GUARDS IN THE APPLICATION:\n${wideLines.join("\n") || "none found"}\n\n${parts.join("\n\n")}`;
}

export interface ConfirmOutcome { findings: RawFinding[]; confirmed: number; rejected: number; unsure: number; evidenceFailed: number }

const SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW"]);

/** Turn one confirmation answer into findings, verifying the evidence it cites. */
export function findingsFromConfirmation(answer: unknown, batch: Candidate[], src: SourceFiles, known: Set<string>): ConfirmOutcome {
  const out: ConfirmOutcome = { findings: [], confirmed: 0, rejected: 0, unsure: 0, evidenceFailed: 0 };
  const results = Array.isArray((answer as { results?: unknown })?.results) ? ((answer as { results: unknown[] }).results) : [];
  const answered = new Set<string>();
  for (const raw of results) {
    if (!raw || typeof raw !== "object") continue;
    const r = raw as Record<string, unknown>;
    const c = batch.find((x) => x.id === r.id);
    if (!c || answered.has(c.id)) continue;
    answered.add(c.id);
    if (r.verdict === "rejected") { out.rejected++; continue; }
    if (r.verdict !== "confirmed") { out.unsure++; continue; }

    const ev = (r.evidence && typeof r.evidence === "object" ? r.evidence : {}) as Record<string, Record<string, unknown> | undefined>;
    const target = ev.target ?? {};
    const tFile = resolveKnownFile(target.file, known);
    const tLine = Number(target.line);
    // The finding points into the handler when the map found one (so it
    // dedupes with the same flaw found elsewhere), else at the registration.
    const inTarget = (file: string, line: number) => {
      const e = c.target;
      if (e.handler) return file === e.handler.file && line >= e.handler.startLine - 1 && line <= e.handler.endLine + 1;
      return file === e.file && Math.abs(line - e.line) <= 1;
    };
    const targetOk = !!tFile && verifyQuote(src, tFile, tLine, target.quote) && inTarget(tFile, tLine);
    const reference = ev.reference ?? {};
    const rFile = resolveKnownFile(reference.file, known);
    // R1 without siblings and R4 have nothing to compare with: the target's own lines are the evidence.
    const needsReference = c.references.length > 0 || c.evidence.length > 0;
    const referenceOk = !needsReference || (!!rFile && verifyQuote(src, rFile, Number(reference.line), reference.quote));
    if (!targetOk || !referenceOk) { out.evidenceFailed++; continue; }
    out.confirmed++;

    const e = c.target;
    const sev = String(r.severity || "").toUpperCase();
    const title = String(r.title || `${e.method} ${e.path} — ${RULES[c.rule].title}`).slice(0, 200);
    const refText = c.references.map((x) => `${x.method} ${x.path} (${x.file}:${x.line})`).join(", ");
    const lines = src.lines(tFile!) ?? [];
    const snippet = lines.slice(Math.max(0, tLine - 3), Math.min(lines.length, tLine + 2)).map((l, i) => `${Math.max(1, tLine - 2) + i}: ${l}`).join("\n");
    const base = applySeverityCalibration({
      scanner: "ZERO_DAY",
      severity: (SEVERITIES.has(sev) ? sev : "HIGH") as RawFinding["severity"],
      title: `[Zero-Day] ${title}`,
      description: String(r.description || ""),
      filePath: tFile!,
      startLine: tLine,
      endLine: tLine,
      snippet,
      cweId: c.cwe,
      confidence: typeof r.confidence === "number" ? r.confidence : 0.8,
      ruleId: `ZD-AUTHZ-${c.rule}`,
      metadata: {
        category: "Authorization",
        weaknessClass: "Authorization",
        rule: c.rule,
        route: e.path || undefined,
        method: e.method,
        references: refText || undefined,
        handlerRange: e.handler ? `${e.handler.file}:${e.handler.startLine}-${e.handler.endLine}` : undefined,
        remediation: String(r.recommendation || "Apply the same control the related entry points use."),
        severityJustification: `${RULES[c.rule].title} on ${e.method} ${e.path}, confirmed against ${refText || "the application's other entry points"}`,
      },
    });
    out.findings.push(
      enrichFinding(base, base.metadata as Record<string, unknown>, {
        whatIsWrong: title,
        where: `${tFile}:${tLine}`,
        whyExploitable: String(r.exploit || r.description || ""),
        attackPath: String(r.exploit || ""),
        impact: String(r.description || ""),
        fix: String(r.recommendation || ""),
        validation: `Repeat the request as a different or lower-privileged user and confirm it is refused.${r.defence ? ` Checked for: ${String(r.defence).slice(0, 300)}` : ""}`,
      }),
    );
  }
  out.unsure += batch.filter((c) => !answered.has(c.id)).length;
  return out;
}
