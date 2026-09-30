/**
 * Guard against unauthorised writes: every API handler that changes data
 * must check the caller's role (requireRole / a helper that calls it), or
 * be an explicitly listed public endpoint that authenticates another way.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const API_ROOT = join(process.cwd(), "src/app/api");

/** Handlers that authenticate without a session role, with the reason. */
const PUBLIC_WRITES: Record<string, string> = {
  "auth/register POST": "self-service sign-up (rate limited, captcha)",
  "auth/saml/acs POST": "SAML assertion consumer — signed IdP response",
  "precommit/scan POST": "API-key authenticated (verifyApiKey)",
  "webhooks/azure-devops POST": "shared-secret Basic auth",
  "webhooks/bitbucket POST": "HMAC signature",
  "webhooks/github POST": "HMAC signature",
  "webhooks/gitlab POST": "secret token header",
};

/** Session-authenticated writes that are safe for every member (incl. VIEWER). */
const MEMBER_WRITES: Record<string, string> = {
  "notifications/[id] PATCH": "the caller's own notification",
  "notifications/[id] DELETE": "the caller's own notification",
  "notifications/mark-all-read POST": "the caller's own notifications",
  "scans/[scanId]/chat POST": "read-only Q&A about a scan",
};

/** GET handlers that change state. */
const STATEFUL_GETS = new Set(["integrations/github/connect GET"]);

const ROLE_CHECK = /requireRole\(|requireRiskDecisionRole\(|authorizeProject\(projectId, "/;

function routeFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return routeFiles(p);
    return name === "route.ts" ? [p] : [];
  });
}

function handlers(): Array<{ key: string; body: string }> {
  const out: Array<{ key: string; body: string }> = [];
  for (const file of routeFiles(API_ROOT)) {
    const src = readFileSync(file, "utf8");
    const route = relative(API_ROOT, file).replace(/\/route\.ts$/, "");
    const re = /export async function (GET|POST|PUT|PATCH|DELETE)\b/g;
    const starts: Array<{ method: string; index: number }> = [];
    let m: RegExpExecArray | null;
    while ((m = re.exec(src))) starts.push({ method: m[1], index: m.index });
    starts.forEach((s, i) => {
      const body = src.slice(s.index, starts[i + 1]?.index ?? src.length);
      out.push({ key: `${route} ${s.method}`, body });
    });
  }
  return out;
}

describe("API route authorization", () => {
  const all = handlers();

  it("finds the API routes", () => {
    expect(all.length).toBeGreaterThan(50);
  });

  it("every data-changing handler checks the caller's role (or is an allowlisted exception)", () => {
    const unguarded = all
      .filter(({ key }) => !key.endsWith(" GET") || STATEFUL_GETS.has(key))
      .filter(({ key, body }) => !(key in PUBLIC_WRITES) && !(key in MEMBER_WRITES) && !ROLE_CHECK.test(body))
      .map(({ key }) => key);
    expect(unguarded).toEqual([]);
  });

  it("allowlisted exceptions still exist (no stale entries)", () => {
    const keys = new Set(all.map((h) => h.key));
    for (const k of [...Object.keys(PUBLIC_WRITES), ...Object.keys(MEMBER_WRITES), ...STATEFUL_GETS]) {
      expect(keys.has(k), k).toBe(true);
    }
  });

  it("risk decisions (false positive / accepted risk) require the Security role", () => {
    for (const key of [
      "findings/[findingId] PATCH",
      "findings/bulk PATCH",
      "findings/[findingId]/verify POST",
      "findings/verify-batch POST",
    ]) {
      const h = all.find((x) => x.key === key);
      expect(h?.body, key).toMatch(/requireRiskDecisionRole\(/);
    }
  });
});
