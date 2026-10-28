import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonObject,
} from "@/lib/llm-gateway";

/**
 * Output budget. Six Markdown fields with code examples overflowed 4096 and
 * cut the JSON off mid-string (issue #213).
 */
export const FINDING_DETAILS_MAX_TOKENS = 6144;

export interface FindingDetailsInput {
  id: string;
  title: string;
  cweId: string | null;
  severity: string;
  filePath: string | null;
  startLine: number | null;
  endLine: number | null;
  description: string | null;
}

export interface GeneratedDetails {
  summary: string;
  vulnerabilityDetails: string;
  stepsToReproduce: string | string[];
  impact: string;
  remediation: string | string[];
  references: string;
  generatedAt: string;
}

interface LlmDetailsOutput {
  summary?: string;
  vulnerabilityDetails?: string;
  stepsToReproduce?: string | string[];
  impact?: string;
  remediation?: string | string[];
  references?: string;
}

const DETAILS_PROMPT_PREFIX = `Vulnerability: {TITLE}
{cweLine}Severity: {SEVERITY}
{context}

Context:
{description}

Return EXACTLY this JSON structure — no extra fields, no missing fields:

{
  "summary": "One paragraph describing what the vulnerability is and how it works. Direct and specific.",
  "vulnerabilityDetails": "Markdown bullet list with key technical details. Each bullet has a bold label then value. Example:\\n* **Endpoint:** \`POST /api/login\`\\n* **Affected Parameters:** \`email\`, \`password\`\\n* **Vulnerable Function:** \`pool.query()\`\\n* **Issue:** Short description of the root cause.",
  "stepsToReproduce": "Numbered steps (1. 2. 3.) as markdown. Each step's description and its code block MUST be a single list item, with the fenced code block indented under its numbered line with NO blank line between. Format each step as:\\n1. Description of the step\\n   \`\`\`bash\\n   curl command here\\n   \`\`\`\\n2. Next step description with its indented code block",
  "impact": "Markdown bullet list of 3-6 specific consequences. Each bullet is a complete sentence.",
  "remediation": "Markdown bullet list of 3-6 specific fixes. Each bullet is a complete actionable sentence.",
  "references": "Markdown bullet list. Include the CWE and OWASP Top 10 mapping if applicable. Example:\\n* CWE-89 – SQL Injection\\n* OWASP Top 10: A03:2021 – Injection"
}

RULES:
- vulnerabilityDetails MUST be a markdown bullet list with bold labels
- NEVER use "What is wrong", "Where", "Why it is exploitable", "Impact" as labels
- NO generic text — be specific to this exact vulnerability and code context
- references: ALWAYS include at least the CWE reference
- Each bullet in impact and remediation is a complete sentence
- stepsToReproduce: each numbered step is a SINGLE list item with its code block indented directly under it (no blank line between the step text and its code block)
- DO NOT put code blocks as separate paragraphs between numbered items — they must be part of the step
- JSON strings: write every line break as \\n and escape double quotes as \\". Never put a raw line break inside a string value
- Keep each field concise (at most ~200 words) so the whole object fits in the answer`;

export async function generateFindingDetails(
  input: FindingDetailsInput,
  config: { provider: string; baseUrl: string; apiKey: string; model: string },
): Promise<GeneratedDetails | null> {
  const {
    id,
    title,
    cweId,
    severity,
    filePath,
    startLine,
    endLine,
    description,
  } = input;

  if (!config.apiKey && config.provider !== "ollama") {
    return null;
  }

  const appContext = `${filePath ? `File: ${filePath}` : ""}${startLine ? `:${startLine}` : ""}${endLine ? `-${endLine}` : ""}`;
  const cweLine = cweId ? `CWE: ${cweId}\n` : "";

  const prompt = DETAILS_PROMPT_PREFIX
    .replace("{TITLE}", title)
    .replace("{cweLine}", cweLine)
    .replace("{SEVERITY}", severity)
    .replace("{context}", appContext)
    .replace("{description}", description || "");

  const client = createLlmClient(config);
  const responseText = await analyzeWithLlm(
    client,
    config.model,
    "You are a security engineer writing a vulnerability report. Output ONLY valid JSON. No markdown, no code fences.",
    prompt,
    { maxTokens: FINDING_DETAILS_MAX_TOKENS },
  );

  // Repairs raw newlines in string values and a cut-off ending, which were
  // the "Failed to parse vulnerability details" cases in issue #213.
  const parsed = parseLlmJsonObject<LlmDetailsOutput>(responseText);
  const details = parsed?.value;
  if (!details || !(details.summary || details.vulnerabilityDetails || details.impact)) {
    console.error(
      `[generate-finding-details] AI returned an unparseable response for finding ${id} (${responseText.length} chars):`,
      responseText.slice(0, 500),
    );
    return null;
  }
  if (parsed.status === "recovered") {
    console.warn(`[generate-finding-details] Recovered a malformed or cut-off AI response for finding ${id}`);
  }

  return {
    summary: details.summary || "",
    vulnerabilityDetails: details.vulnerabilityDetails || "",
    stepsToReproduce:
      typeof details.stepsToReproduce === "string"
        ? details.stepsToReproduce
        : Array.isArray(details.stepsToReproduce)
          ? details.stepsToReproduce
          : [],
    impact: details.impact || "",
    remediation:
      typeof details.remediation === "string"
        ? details.remediation
        : Array.isArray(details.remediation)
          ? details.remediation
          : [],
    references: details.references || "",
    generatedAt: new Date().toISOString(),
  };
}
