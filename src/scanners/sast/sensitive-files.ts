import * as fs from "fs";
import * as path from "path";
import { RawFinding, ScanContext } from "../types";

/** Glob-like basename patterns for sensitive artifacts (presence-only reporting). */
const SENSITIVE_BASENAME_RE =
  /^(\.env|\.env\.[^/]+|\.pem|id_rsa|id_ed25519|id_ecdsa|\.pfx|\.p12|\.keychain|credentials\.json|service-account.*\.json|google-services\.json|firebase-adminsdk.*\.json|\.htpasswd|\.netrc|\.pgpass|dump\.sql|backup\.sql|\.sql\.gz|\.bak~?)$/i;

const SENSITIVE_DIR_PARTS = new Set([
  ".ssh",
  ".aws",
  ".azure",
  ".kube",
  ".docker",
  "secrets",
  "private_keys",
]);

const EXT_HINTS = new Set([
  ".pem",
  ".key",
  ".p12",
  ".pfx",
  ".keystore",
  ".jks",
  ".sql",
  ".sqlite",
  ".db",
]);

/**
 * Reports presence of sensitive paths without embedding secret values.
 */
export function scanSensitivePaths(ctx: ScanContext): RawFinding[] {
  const findings: RawFinding[] = [];

  for (const rel of ctx.fileList) {
    if (ctx.signal?.aborted) break;

    const norm = rel.split(path.sep).join("/");
    const base = path.basename(norm);
    const parts = norm.split("/");

    let matchReason: string | null = null;
    if (SENSITIVE_BASENAME_RE.test(base)) {
      matchReason = "Filename matches a sensitive credential or environment pattern";
    }
    if (!matchReason && parts.some((p) => SENSITIVE_DIR_PARTS.has(p))) {
      matchReason = "Path segment suggests credentials or cloud configuration directory";
    }
    if (!matchReason) {
      const ext = path.extname(base).toLowerCase();
      if (EXT_HINTS.has(ext) && /key|secret|priv|credential|dump|backup/i.test(norm)) {
        matchReason = "Extension and path suggest keys or database artifacts";
      }
    }

    if (!matchReason) continue;

    const full = path.join(ctx.workDir, rel);
    let size = 0;
    try {
      size = fs.statSync(full).size;
    } catch {
      continue;
    }

    findings.push({
      scanner: "SAST_PATTERN",
      severity: "INFO",
      title: `Sensitive file path: ${base}`,
      description:
        `${matchReason}. Verify the file is not web-accessible, not committed unintentionally, and access is restricted. Secret contents are not shown.`,
      filePath: rel,
      startLine: 1,
      endLine: 1,
      snippet: `${1}: [REDACTED — ${size} bytes; verify access controls on authorized systems only]`,
      ruleId: "PEPPER-SENSITIVE-PATH",
      cweId: "CWE-538",
      confidence: 0.95,
      masked: true,
      metadata: {
        sastEngine: {
          owaspTop10Id: "A05:2021",
          owaspCategory: "Security Misconfiguration",
          falsePositiveReasoning:
            "This finding only confirms path naming — not that secrets are exposed at runtime.",
          needsManualValidation: false,
        },
      },
    });
  }

  return findings;
}
