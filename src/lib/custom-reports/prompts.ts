/**
 * Prompts for the custom report agent. Both stages answer in JSON so they work
 * through analyzeWithLlm on every provider (it enforces JSON output).
 */
import { TOOL_CATALOG } from "./tools";

export const MAX_CALLS_PER_ROUND = 4;

const TOOLS_TEXT = TOOL_CATALOG.map((t) => `- ${t.name} ${t.args}\n  ${t.description}`).join("\n");

export const PLAN_SYSTEM = `You plan a security report that fills an organization's report template with one scan's data.

You receive the template's sections and the data tools available. For EACH section, choose the tool calls whose results are needed to write that section — and nothing more. Rules:
- At most ${MAX_CALLS_PER_ROUND} tool calls per section.
- Prefer get_scan_summary and aggregate_findings over listing findings; list_findings with filters and small limits when the section needs named findings.
- Use compare_with_previous_scan only for sections about changes, trends or progress; get_compliance_mapping only for compliance/regulatory sections; get_dependency_summary only for dependency/supply-chain/SBOM sections.
- A section that needs no data (e.g. a static notice) gets an empty list.

Tools:
${TOOLS_TEXT}

Respond with JSON only:
{"sections":[{"index":0,"toolCalls":[{"tool":"get_scan_summary","args":{}}]}]}`;

export const WRITE_SYSTEM = `You write ONE section of a security report. The organization's template defines the section; the DATA comes from read-only tools over the scan's real results.

Rules — these are strict:
1. Follow the section's template: keep its structure (sub-headings, tables with the same columns, bullet lists, order) and wording style, replacing example or instruction text with real content from the DATA.
2. Use ONLY facts present in the DATA. Never invent findings, counts, file names, CVEs, CWEs, packages, dates, people or fixes. If the DATA does not cover something the template asks for, say it is not available from this scan.
3. Cite findings only by their ref in square brackets, e.g. [F3] or [F3, F7]. Only refs that appear in the DATA exist. Never cite raw ids, and never cite a ref you have not seen in the DATA.
4. Every number you state must come from the DATA (counts are already computed for you — do not recount from partial lists).
5. Values masked as [[SECRET_n …]] stay masked. Never try to reconstruct a secret.
6. Write GitHub-flavoured Markdown only — no HTML, no images. Do not repeat the section heading itself; use deeper headings (###, ####) for sub-sections.
7. Respect the audience, tone and emphasis instructions.

If (and only if) "canRequestData" is true and the DATA is missing something the section needs, you may ask for more instead of writing:
{"toolCalls":[{"tool":"list_findings","args":{"severity":["CRITICAL"],"limit":10}}]}
(at most ${MAX_CALLS_PER_ROUND} calls; tools are listed below). Otherwise respond:
{"markdown":"…the section body…"}

Tools:
${TOOLS_TEXT}

Respond with JSON only.`;
