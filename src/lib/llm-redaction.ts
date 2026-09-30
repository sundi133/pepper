/**
 * Mask secret values before text is sent to an LLM.
 *
 * Every secret value is replaced by a stable token that keeps what a model
 * needs to reason about it, but not the value itself:
 *
 *   [[SECRET_3 type=aws_access_key prefix=AKIA len=20 entropy=3.7]]
 *
 * - `prefix` is only kept for credential types whose prefix is public (AKIA,
 *   ghp_, sk_live_, …); generic passwords never reveal characters.
 * - Tokens never contain newlines and multi-line secrets keep their line
 *   breaks, so line numbers in the model's answer still match the file.
 * - The same value gets the same token within a session, so a secret quoted
 *   in two places reads as the same secret.
 *
 * Output keeps the tokens (so stored AI text never contains a raw secret)
 * unless a caller explicitly restores it — code-fix flows do, so their edits
 * still match the real file.
 */
import { isLikelyPlaceholderSecret } from "@/scanners/secrets/patterns";

export const SECRET_TOKEN_RE = /\[\[SECRET_(\d+)(?:\s[^\]\n]*)?\]\]/g;

/** Instance switch: masking is on unless LLM_MASK_SECRETS=false. */
export function llmMaskingEnabled(env: Record<string, string | undefined> = process.env): boolean {
  return env.LLM_MASK_SECRETS?.trim().toLowerCase() !== "false";
}

interface Rule {
  type: string;
  re: RegExp;
  /** Capture group holding the secret (0 = whole match). */
  group?: number;
  /** Characters of the value that are a public, well-known prefix. */
  prefix?: (value: string) => number;
}

const fixedPrefix = (n: number) => () => n;

/** Credential formats recognisable by shape alone. Order matters (specific first). */
const SHAPE_RULES: Rule[] = [
  { type: "private_key", re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g },
  { type: "aws_access_key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, prefix: fixedPrefix(4) },
  { type: "github_token", re: /\b(?:gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g, prefix: (v) => v.indexOf("_") + 1 },
  { type: "gitlab_token", re: /\bglpat-[A-Za-z0-9_-]{20,}/g, prefix: fixedPrefix(6) },
  { type: "slack_token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g, prefix: fixedPrefix(5) },
  { type: "stripe_key", re: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g, prefix: (v) => v.indexOf("_", 3) + 1 },
  { type: "google_api_key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, prefix: fixedPrefix(4) },
  { type: "sendgrid_key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, prefix: fixedPrefix(3) },
  { type: "npm_token", re: /\bnpm_[A-Za-z0-9]{36}\b/g, prefix: fixedPrefix(4) },
  { type: "anthropic_key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g, prefix: fixedPrefix(7) },
  { type: "openai_key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/g, prefix: (v) => (v.startsWith("sk-proj-") ? 8 : 3) },
  { type: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g, prefix: fixedPrefix(3) },
  { type: "azure_storage_key", re: /AccountKey=([A-Za-z0-9+/=]{40,})/g, group: 1 },
  // scheme://user:PASSWORD@host — only the password is masked.
  { type: "url_password", re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/'"`]+:([^\s@/'"`]+)@/gi, group: 1 },
  // ADO.NET / ODBC connection strings: …;Password=…; (must follow another key=value;)
  { type: "connection_string_password", re: /;\s*(?:Password|Pwd)\s*=\s*([^;'"`\s]{4,})/gi, group: 1 },
];

const SECRET_NAME =
  "[A-Za-z0-9_.-]*(?:passw(?:or)?d|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key|credential|signing[_-]?key|encryption[_-]?key)[A-Za-z0-9_.-]*";

/** Secret-named assignments whose value isn't recognisable by shape. */
const NAME_RULES: Rule[] = [
  // password = "…" · "apiKey": "…" · API_TOKEN => '…' · secret := `…`
  {
    type: "named_secret",
    re: new RegExp(`\\b${SECRET_NAME}["']?[ \\t]*(?::=|=>|[:=])[ \\t]*(["'\`])([^"'\`\\n]{6,}?)\\1`, "gi"),
    group: 2,
  },
  // Config lines: DB_PASSWORD=s3cr3t · api_key: abc123def (unquoted)
  {
    type: "named_secret",
    re: new RegExp(`^(?:\\s*(?:export\\s+)?${SECRET_NAME}\\s*[:=][ \\t]*)([^\\s#'"\`(){}\\[\\];,][^\\s#'"\`(){}\\[\\];,]{5,})[ \\t]*$`, "gim"),
    group: 1,
  },
];

// Variable references in code, shell, CI and templates; plain URLs; placeholders.
const REFERENCE_RE = /^\\?\$[{(A-Za-z_0-9]|\{\{|%\(|process\.env|os\.environ|getenv|^<.*>$|^\*+$|^https?:\/\/[^\s:@]+$|^(null|none|nil|undefined|true|false|changeme|change_me|password|secret|redacted|dummy|sample)$/i;

export function shannonEntropy(value: string): number {
  if (!value) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Name-based matches need a value that looks like a credential, not a variable or a placeholder. */
function plausibleNamedSecret(value: string): boolean {
  if (REFERENCE_RE.test(value) || isLikelyPlaceholderSecret(value) || value.includes("[[SECRET_")) return false;
  if (/\s/.test(value)) return false; // prose / messages
  // Member paths and calls are code references: settings.SECRET_KEY, cfg["token"], getToken()
  if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\[[^\]]*\]|\(\))+$/.test(value)) return false;
  if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(value)) return false; // CONSTANT_NAME
  // Other bare identifiers are references unless they look like a key: 12+ chars mixing letters and digits.
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    const keyLike = value.length >= 12 && /[A-Za-z]/.test(value) && /\d/.test(value);
    if (!keyLike) return false;
  }
  return shannonEntropy(value) >= 2.5;
}

export interface RedactionSession {
  /** Mask secrets in `text`. */
  redact(text: string): string;
  /** Put the original values back (only for code-fix flows). */
  restore(text: string): string;
  /** Distinct secrets masked so far. */
  readonly count: number;
}

export function createRedactionSession(): RedactionSession {
  const idByValue = new Map<string, number>();
  const valueById = new Map<number, string>();

  function tokenFor(value: string, type: string, prefixLen: number): string {
    let id = idByValue.get(value);
    if (id === undefined) {
      id = idByValue.size + 1;
      idByValue.set(value, id);
      valueById.set(id, value);
    }
    const oneLine = value.replace(/\s+/g, "");
    const prefix = prefixLen > 0 ? ` prefix=${value.slice(0, prefixLen)}` : "";
    return `[[SECRET_${id} type=${type}${prefix} len=${oneLine.length} entropy=${shannonEntropy(oneLine).toFixed(1)}]]`;
  }

  function apply(text: string, rule: Rule, named: boolean): string {
    return text.replace(rule.re, (...args) => {
      const match = args[0] as string;
      const groups = args.slice(1, -2) as Array<string | undefined>;
      const value = rule.group ? groups[rule.group - 1] : match;
      if (!value || value.includes("[[SECRET_")) return match;
      if (named ? !plausibleNamedSecret(value) : REFERENCE_RE.test(value) || isLikelyPlaceholderSecret(value)) return match;
      const prefixLen = rule.prefix ? Math.max(0, rule.prefix(value)) : 0;
      // Keep the line count: a multi-line secret leaves its line breaks behind.
      const breaks = "\n".repeat((value.match(/\n/g) ?? []).length);
      const token = tokenFor(value, rule.type, prefixLen) + breaks;
      const at = match.lastIndexOf(value);
      return match.slice(0, at) + token + match.slice(at + value.length);
    });
  }

  function redactPlain(text: string): string {
    let out = text;
    for (const rule of SHAPE_RULES) out = apply(out, rule, false);
    for (const rule of NAME_RULES) out = apply(out, rule, true);
    return out;
  }

  // Code inside a JSON payload has escaped quotes and newlines, which hides
  // `password = "…"` from the rules; mask each string value on its own.
  function redactJsonStrings(value: unknown): { value: unknown; changed: boolean } {
    if (typeof value === "string") {
      const out = redactPlain(value);
      return { value: out, changed: out !== value };
    }
    if (Array.isArray(value)) {
      let changed = false;
      const out = value.map((v) => {
        const r = redactJsonStrings(v);
        changed ||= r.changed;
        return r.value;
      });
      return { value: out, changed };
    }
    if (value && typeof value === "object") {
      let changed = false;
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) {
        const r = redactJsonStrings(v);
        changed ||= r.changed;
        out[k] = r.value;
      }
      return { value: out, changed };
    }
    return { value, changed: false };
  }

  return {
    redact(text: string) {
      if (!text) return text;
      let out = text;
      if (/^\s*[{[]/.test(text)) {
        try {
          const r = redactJsonStrings(JSON.parse(text));
          if (r.changed) out = JSON.stringify(r.value, null, /^[{[]\s*\n(\s+)/.exec(text)?.[1]);
        } catch {
          // not JSON
        }
      }
      // Also the whole text: catches top-level pairs such as {"password": "…"}.
      return redactPlain(out);
    },
    restore(text: string) {
      if (!text) return text;
      return text.replace(SECRET_TOKEN_RE, (whole, id: string) => valueById.get(Number(id)) ?? whole);
    },
    get count() {
      return idByValue.size;
    },
  };
}

/** Appended to the system prompt when a request contains masked values. */
export const MASKED_SECRETS_NOTE =
  "Note: some values in the input have been masked for confidentiality as [[SECRET_n type=… len=… entropy=…]]. " +
  "Each token stands for the real value it replaced; its type, length and entropy describe that value. " +
  "Treat it exactly as that value when analysing the code, refer to it by the same token in your answer, and never try to reconstruct it.";

/** One-off masking for a single prompt sent outside the gateway. */
export function maskForLlm(text: string): string {
  if (!llmMaskingEnabled()) return text;
  const s = createRedactionSession();
  const out = s.redact(text);
  return s.count > 0 ? `${out}\n\n${MASKED_SECRETS_NOTE}` : out;
}
