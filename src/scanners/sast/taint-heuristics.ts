/**
 * Lightweight intra-file taint hints: looks above the sink line for HTTP/API inputs.
 * Not a full program analyzer — conservative text for reports only.
 */

const SOURCE_PATTERNS: Array<{ label: string; re: RegExp }> = [
  { label: "HTTP request body", re: /\b(?:req|request)\.(?:body|body\.)/ },
  { label: "HTTP query string", re: /\b(?:req|request)\.(?:query|query\.)/ },
  { label: "HTTP route params", re: /\b(?:req|request)\.(?:params|params\.)/ },
  { label: "HTTP headers", re: /\b(?:req|request)\.(?:headers|getHeader|header)/ },
  { label: "HTTP cookies", re: /\b(?:req|request)\.(?:cookies|signedCookies)/ },
  { label: "Next.js searchParams / FormData", re: /\bsearchParams\.|formData\.|request\.json\s*\(/ },
  { label: "Flask/Django request input", re: /\brequest\.(?:args|form|files|json|values)/ },
  { label: "PHP superglobals", re: /\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b/ },
  { label: "Ruby params", re: /\bparams\s*\[/ },
  { label: "Go HTTP input", re: /\br\.(?:FormValue|URL\.Query|PostForm)/ },
  { label: "Java Servlet input", re: /\brequest\.getParameter/i },
];

const SANITIZER_HINTS = [
  /\b(?:escape|encode|sanitize|purify|validate|zod\.|joi\.|validator\.|DOMPurify|he\.encode)/i,
  /\b(?:parameterized|prepared\s*statement|bindParam|\?\s*,)/i,
];

export interface TaintHint {
  inferredSources: string[];
  sanitizerNearby: boolean;
  sourceToSinkSummary: string;
}

export function analyzeTaintAroundLine(
  fileContent: string,
  sinkLine1Indexed: number,
  sinkDescription: string,
): TaintHint {
  const lines = fileContent.split(/\r?\n/);
  const sinkIdx = Math.min(Math.max(sinkLine1Indexed - 1, 0), lines.length - 1);
  const windowStart = Math.max(0, sinkIdx - 80);
  const window = lines.slice(windowStart, sinkIdx + 1).join("\n");

  const inferredSources: string[] = [];
  for (const { label, re } of SOURCE_PATTERNS) {
    if (re.test(window)) inferredSources.push(label);
  }
  const sanitizerNearby = SANITIZER_HINTS.some((re) => re.test(window));

  let sourceToSinkSummary: string;
  if (inferredSources.length === 0) {
    sourceToSinkSummary = sanitizerNearby
      ? `Sink at line ${sinkLine1Indexed} (${sinkDescription}). Upstream context suggests possible validation or encoding; confirm whether untrusted data still reaches this sink.`
      : `Sink at line ${sinkLine1Indexed} (${sinkDescription}). No obvious HTTP input reference in the preceding lines — trace data flow manually or widen scope.`;
  } else {
    sourceToSinkSummary = `Sink at line ${sinkLine1Indexed} (${sinkDescription}). Prior lines reference: ${[...new Set(inferredSources)].join(", ")}. ${sanitizerNearby ? "Sanitization or validation may be present — verify it applies to this path." : "No obvious sanitizer in the local window — higher confidence that untrusted data may reach the sink."}`;
  }

  return {
    inferredSources: [...new Set(inferredSources)],
    sanitizerNearby,
    sourceToSinkSummary,
  };
}
