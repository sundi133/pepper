/**
 * Deterministic plausibility check for typosquat claims.
 *
 * Typosquatting is a *lexical* attack inside a *single registry*: an attacker
 * publishes a name a human might mistype or misread for a popular one, so the
 * wrong package gets installed. Two properties follow, and a model asked to
 * spot "suspiciously similar" names does not reliably respect either.
 *
 * The case this was written for: `mcp` on PyPI — the official Model Context
 * Protocol SDK published by Anthropic — was reported as a typosquat of
 * `@modelcontextprotocol/sdk` on npm, because "mcp is a common abbreviation for
 * Model Context Protocol". That is semantic association, not typosquatting. No
 * one types `pip install mcp` intending to install an npm package, and an
 * abbreviation is not a misspelling.
 */

/** Registry identity, normalised across the labels the parsers emit. */
function normaliseEcosystem(ecosystem: string | undefined): string {
  const eco = (ecosystem || "").toLowerCase().trim();
  if (eco === "pip") return "pypi";
  if (eco === "crates" || eco === "cargo") return "crates.io";
  if (eco === "gem") return "rubygems";
  if (eco === "golang") return "go";
  if (eco === "gradle") return "maven";
  if (eco === "packagist") return "composer";
  return eco;
}

/**
 * Comparable form of a package name: scope, common language affixes and
 * separators removed, so `@scope/name`, `node-name` and `name_x` compare on
 * their distinctive part.
 */
export function normalisePackageName(name: string): string {
  let n = (name || "").toLowerCase().trim();
  // Drop an npm scope: @scope/name -> name
  if (n.startsWith("@")) {
    const slash = n.indexOf("/");
    if (slash > -1) n = n.slice(slash + 1);
    else n = n.slice(1);
  }
  // Maven group:artifact -> artifact
  const colon = n.lastIndexOf(":");
  if (colon > -1) n = n.slice(colon + 1);
  return n.replace(/[-_.\s]/g, "");
}

/** Levenshtein distance, iterative with a single row. */
export function editDistance(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;

  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const curr = [i];
    for (let j = 1; j <= b.length; j++) {
      curr[j] = Math.min(
        prev[j] + 1,
        curr[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
    prev = curr;
  }
  return prev[b.length];
}

/** Affixes attackers bolt onto a real name (combosquatting). */
const COMBOSQUAT_AFFIXES = [
  "js",
  "node",
  "py",
  "python",
  "dev",
  "core",
  "lib",
  "util",
  "utils",
  "cli",
  "sdk",
  "api",
  "official",
  "new",
  "latest",
];

/**
 * Similarity above which two names are close enough that a human could confuse
 * them. `reqeusts` vs `requests` scores 0.875; `mcp` vs `modelcontextprotocolsdk`
 * scores about 0.09.
 */
const MIN_SIMILARITY = 0.75;

/**
 * Edits a human plausibly makes in one attempt. Applied only between names of
 * comparable length, so it cannot rescue an abbreviation-versus-full-name claim.
 */
const MAX_TYPO_EDITS = 2;

export interface TyposquatClaim {
  packageName: string;
  ecosystem?: string;
  /** The popular package it is claimed to imitate. */
  similarTo: string;
  /** Ecosystem of the imitated package, when the model supplied one. */
  similarToEcosystem?: string;
}

export interface PlausibilityResult {
  plausible: boolean;
  /** Why it was rejected, for logging and for the finding's evidence. */
  reason?: string;
  similarity?: number;
}

/**
 * Whether a typosquat claim is lexically and structurally possible.
 * Rejecting here does not mean the package is safe — only that *this* claim
 * does not describe typosquatting.
 */
export function isPlausibleTyposquat(claim: TyposquatClaim): PlausibilityResult {
  const candidate = normalisePackageName(claim.packageName);
  const target = normalisePackageName(claim.similarTo);

  if (!candidate || !target) {
    return { plausible: false, reason: "missing package name" };
  }

  // A package in one registry cannot be typosquatted by a package in another:
  // the install commands are different and users never confuse them.
  const candidateEco = normaliseEcosystem(claim.ecosystem);
  const targetEco = normaliseEcosystem(claim.similarToEcosystem);

  if (candidate === target) {
    // Separator confusion is judged on the raw names with only case and
    // separators folded — scopes and group ids must stay, otherwise
    // `@scope/sdk` and `sdk` look like the same name when they are two
    // different packages.
    const separatorForm = (n: string) =>
      n.trim().toLowerCase().replace(/[-_.]/g, "");
    const sameIgnoringSeparators =
      separatorForm(claim.packageName) === separatorForm(claim.similarTo);
    const rawDiffers =
      claim.packageName.trim().toLowerCase() !==
      claim.similarTo.trim().toLowerCase();

    // Differing only by separators or case is a real squatting technique on
    // registries that treat those as distinct names — but not on PyPI, where
    // PEP 503 normalises them, so the two names resolve to one package.
    if (sameIgnoringSeparators && rawDiffers && candidateEco !== "pypi") {
      return { plausible: true, reason: "separator or case confusion", similarity: 1 };
    }
    return { plausible: false, reason: "name resolves to the target package" };
  }

  if (candidateEco && targetEco && candidateEco !== targetEco) {
    return {
      plausible: false,
      reason: `different registries (${candidateEco} vs ${targetEco})`,
    };
  }
  // An npm-style scoped target compared against a non-npm package is the same
  // mistake even when the model did not label the ecosystem.
  if (claim.similarTo.trim().startsWith("@") && candidateEco && candidateEco !== "npm") {
    return {
      plausible: false,
      reason: `scoped npm target compared against a ${candidateEco} package`,
    };
  }

  // Combosquatting: the real name carrying an extra affix.
  const longer = candidate.length >= target.length ? candidate : target;
  const shorter = candidate.length >= target.length ? target : candidate;
  if (longer.startsWith(shorter) || longer.endsWith(shorter)) {
    const extra = longer.slice(
      longer.startsWith(shorter) ? shorter.length : 0,
      longer.startsWith(shorter) ? undefined : longer.length - shorter.length,
    );
    if (extra.length <= 8 && COMBOSQUAT_AFFIXES.includes(extra)) {
      return { plausible: true, similarity: 1 - extra.length / longer.length };
    }
  }

  const distance = editDistance(candidate, target);
  const similarity = 1 - distance / Math.max(candidate.length, target.length);

  // A relative threshold alone is too strict for short names, where typosquats
  // actually live: `lodahs` vs `lodash` is a transposition — the archetypal
  // squat — yet scores only 0.67. One or two edits is a mistype at any length,
  // provided the names are of comparable length so an abbreviation such as
  // `mcp` cannot qualify against a much longer name.
  const comparableLength =
    Math.min(candidate.length, target.length) /
      Math.max(candidate.length, target.length) >=
    0.6;
  if (distance <= MAX_TYPO_EDITS && comparableLength) {
    return { plausible: true, similarity };
  }

  if (similarity < MIN_SIMILARITY) {
    return {
      plausible: false,
      reason:
        `names are not lexically similar (${similarity.toFixed(2)} similarity); ` +
        `an abbreviation or a related project is not a typosquat`,
      similarity,
    };
  }

  return { plausible: true, similarity };
}
