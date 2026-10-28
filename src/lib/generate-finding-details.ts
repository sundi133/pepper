import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";

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
- DO NOT put code blocks as separate paragraphs between numbered items — they must be part of the step`;

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
    { maxTokens: 4096 },
  );

  let details: LlmDetailsOutput = {};
  try {
    details = parseLlmJsonResponse<LlmDetailsOutput>(responseText, {});
    if (!details || Object.keys(details).length === 0) {
      const jsonMatch = responseText.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        details = JSON.parse(jsonMatch[0]) as LlmDetailsOutput;
      }
    }
  } catch {
    console.error(`[generate-finding-details] Failed to parse AI response for finding ${id}:`, responseText);
    return null;
  }

  if (!details || Object.keys(details).length === 0) {
    console.error(`[generate-finding-details] AI returned empty/unparseable response for finding ${id}:`, responseText);
    return null;
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
