/**
 * License policy evaluation over SPDX license expressions.
 *
 * deps.dev returns declared licenses as SPDX *expressions*, not bare IDs —
 * "Apache-2.0 OR MIT", "BSD-3-Clause OR GPL-2.0", "(MIT AND CC0-1.0)". Naive
 * substring matching on those produces false positives: a package offered as
 * "BSD-3-Clause OR GPL-2.0" may be taken under BSD, so a GPL ban does not
 * apply to it. This module evaluates the expression tree properly:
 *
 *   OR  → the best branch wins   (the consumer may choose any single branch)
 *   AND → the worst branch wins  (every obligation applies simultaneously)
 */

import {
  LICENSE_POLICY_DENY,
  LICENSE_POLICY_WARN,
  LICENSE_POLICY_FLAG_UNKNOWN,
} from "@/lib/constants";
import { NON_STANDARD_LICENSE } from "./deps-dev-client";

export type LicenseVerdict = "allowed" | "warn" | "denied" | "unknown";

export interface LicensePolicy {
  /** Patterns that fail the policy. Exact SPDX ID or a `PREFIX-*` wildcard. */
  deny: string[];
  /** Patterns that pass but are worth surfacing (weak copyleft, etc.). */
  warn: string[];
  /** Emit a finding when the license cannot be determined. Off by default. */
  flagUnknown: boolean;
}

export interface LicenseEvaluation {
  verdict: LicenseVerdict;
  /** The expression evaluated, as declared upstream. */
  expression: string;
  /** Which policy pattern drove a denied/warn verdict. */
  matchedPattern?: string;
  /** The specific license ID that matched the pattern. */
  matchedLicense?: string;
}

export function defaultLicensePolicy(): LicensePolicy {
  return {
    deny: LICENSE_POLICY_DENY,
    warn: LICENSE_POLICY_WARN,
    flagUnknown: LICENSE_POLICY_FLAG_UNKNOWN,
  };
}

// ─── Pattern matching ────────────────────────────────────────────────────────

/**
 * Match a license ID against a policy pattern. Patterns are case-insensitive
 * and may end in `*` to cover a family: `GPL-*` matches `GPL-2.0-only` but not
 * `LGPL-3.0` (different prefix) and not `AGPL-3.0`.
 *
 * A bare pattern also matches the SPDX `-only` / `-or-later` / `+` variants, so
 * `GPL-2.0` covers `GPL-2.0-only` without needing a wildcard.
 */
function matchesPattern(licenseId: string, pattern: string): boolean {
  const id = licenseId.trim().toLowerCase();
  const pat = pattern.trim().toLowerCase();
  if (!id || !pat) return false;

  if (pat.endsWith("*")) {
    return id.startsWith(pat.slice(0, -1));
  }
  if (id === pat) return true;

  // SPDX version-qualifier variants of the same license.
  return (
    id === `${pat}-only` || id === `${pat}-or-later` || id === `${pat}+`
  );
}

function classifyLicenseId(
  licenseId: string,
  policy: LicensePolicy,
): { verdict: LicenseVerdict; pattern?: string } {
  const id = licenseId.trim();
  if (!id || id.toLowerCase() === NON_STANDARD_LICENSE) {
    return { verdict: "unknown" };
  }
  if (id.toUpperCase() === "NOASSERTION" || id.toUpperCase() === "NONE") {
    return { verdict: "unknown" };
  }

  for (const pattern of policy.deny) {
    if (matchesPattern(id, pattern)) return { verdict: "denied", pattern };
  }
  for (const pattern of policy.warn) {
    if (matchesPattern(id, pattern)) return { verdict: "warn", pattern };
  }
  return { verdict: "allowed" };
}

// ─── Expression parsing ──────────────────────────────────────────────────────

type Node =
  | { kind: "license"; id: string }
  | { kind: "or"; children: Node[] }
  | { kind: "and"; children: Node[] };

/**
 * Parse the subset of SPDX expression syntax that appears in real registry
 * metadata: IDs, `WITH` exceptions, `AND`/`OR`, and parentheses.
 * Unparseable input yields a single license node so it classifies as unknown.
 */
export function parseSpdxExpression(expression: string): Node {
  const tokens = expression
    .replace(/\(/g, " ( ")
    .replace(/\)/g, " ) ")
    .split(/\s+/)
    .filter(Boolean);

  let pos = 0;

  function parseOr(): Node {
    const children = [parseAnd()];
    while (pos < tokens.length && tokens[pos].toUpperCase() === "OR") {
      pos++;
      children.push(parseAnd());
    }
    return children.length === 1 ? children[0] : { kind: "or", children };
  }

  function parseAnd(): Node {
    const children = [parseAtom()];
    while (pos < tokens.length && tokens[pos].toUpperCase() === "AND") {
      pos++;
      children.push(parseAtom());
    }
    return children.length === 1 ? children[0] : { kind: "and", children };
  }

  function parseAtom(): Node {
    if (pos >= tokens.length) return { kind: "license", id: "" };

    if (tokens[pos] === "(") {
      pos++;
      const inner = parseOr();
      if (pos < tokens.length && tokens[pos] === ")") pos++;
      return inner;
    }

    const id = tokens[pos++];
    // "MIT WITH Exception" — the exception does not change the base license's
    // policy classification, so consume and ignore it.
    if (pos < tokens.length && tokens[pos].toUpperCase() === "WITH") {
      pos += 2;
    }
    return { kind: "license", id };
  }

  const tree = parseOr();
  return tree;
}

// ─── Verdict combination ─────────────────────────────────────────────────────

const BEST_FIRST: LicenseVerdict[] = ["allowed", "warn", "unknown", "denied"];
const WORST_FIRST: LicenseVerdict[] = ["denied", "unknown", "warn", "allowed"];

function pickBy(
  order: LicenseVerdict[],
  results: Array<{ verdict: LicenseVerdict; pattern?: string; license?: string }>,
) {
  for (const verdict of order) {
    const hit = results.find((r) => r.verdict === verdict);
    if (hit) return hit;
  }
  return { verdict: "unknown" as LicenseVerdict };
}

function evaluateNode(
  node: Node,
  policy: LicensePolicy,
): { verdict: LicenseVerdict; pattern?: string; license?: string } {
  if (node.kind === "license") {
    const { verdict, pattern } = classifyLicenseId(node.id, policy);
    return { verdict, pattern, license: node.id };
  }

  const results = node.children.map((c) => evaluateNode(c, policy));
  // OR: the consumer may pick the most favourable branch.
  // AND: every branch's obligations bind, so the least favourable governs.
  return node.kind === "or"
    ? pickBy(BEST_FIRST, results)
    : pickBy(WORST_FIRST, results);
}

/**
 * Evaluate one SPDX expression against the policy.
 */
export function evaluateLicenseExpression(
  expression: string,
  policy: LicensePolicy = defaultLicensePolicy(),
): LicenseEvaluation {
  const trimmed = (expression || "").trim();
  if (!trimmed) {
    return { verdict: "unknown", expression: "" };
  }

  const result = evaluateNode(parseSpdxExpression(trimmed), policy);
  return {
    verdict: result.verdict,
    expression: trimmed,
    matchedPattern: result.pattern,
    matchedLicense: result.verdict === "allowed" ? undefined : result.license,
  };
}

/**
 * Evaluate the license list deps.dev returns for a version.
 *
 * Multiple array entries are treated as alternatives (OR): registries use the
 * array for dual-licensed packages, and the permissive reading avoids flagging
 * a package the consumer could legitimately take under an allowed license.
 */
export function evaluateLicenses(
  licenses: string[] | undefined,
  policy: LicensePolicy = defaultLicensePolicy(),
): LicenseEvaluation {
  const present = (licenses || []).filter((l) => l && l.trim());
  if (present.length === 0) {
    return { verdict: "unknown", expression: "" };
  }

  const evaluations = present.map((l) => evaluateLicenseExpression(l, policy));
  const best = pickBy(
    BEST_FIRST,
    evaluations.map((e) => ({
      verdict: e.verdict,
      pattern: e.matchedPattern,
      license: e.matchedLicense,
    })),
  );

  return {
    verdict: best.verdict,
    expression: present.join(", "),
    matchedPattern: best.pattern,
    matchedLicense: best.license,
  };
}

/** Whether this verdict should produce a finding under the policy. */
export function shouldReport(
  verdict: LicenseVerdict,
  policy: LicensePolicy = defaultLicensePolicy(),
): boolean {
  if (verdict === "denied" || verdict === "warn") return true;
  if (verdict === "unknown") return policy.flagUnknown;
  return false;
}
