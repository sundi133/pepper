/**
 * Inconsistency rules over the verified map (docs/LOGIC_FLAW_DETECTION_SPEC.md
 * §4.3). Deterministic and language-independent: they compare entry points
 * with their siblings and with the rest of the application, and only propose
 * candidates — the confirmation pass decides.
 */
import { normalizePath, normalizeResource, type EntryPoint, type LogicMap, type Loc } from "./map";

export type RuleId = "R1" | "R2" | "R3" | "R4" | "R5";

export interface Candidate {
  id: string;
  rule: RuleId;
  cwe: string;
  /** What the target lacks, in words the confirmation prompt uses. */
  missing: string;
  target: EntryPoint;
  /** Entry points that have the control the target lacks. */
  references: EntryPoint[];
  /** Lines that show the control exists (a reference guard, an ownership record…). */
  evidence: Loc[];
}

export const RULES: Record<RuleId, { cwe: string; title: string }> = {
  R1: { cwe: "CWE-306", title: "missing authentication" },
  R2: { cwe: "CWE-862", title: "missing role check" },
  R3: { cwe: "CWE-639", title: "missing ownership check" },
  R4: { cwe: "CWE-696", title: "guard runs after the handler" },
  R5: { cwe: "CWE-639", title: "job skips the API's ownership check" },
};

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const SERVER_KINDS = new Set(["http", "graphql", "rpc", "webhook"]);
const JOB_KINDS = new Set(["job", "consumer", "cron"]);

const effective = (e: EntryPoint) => e.guards.filter((g) => g.order !== "after");
const hasAuthn = (e: EntryPoint) => effective(e).some((g) => g.kind === "authn" || g.kind === "role" || g.kind === "owner");
const hasRole = (e: EntryPoint) => effective(e).some((g) => g.kind === "role");
const hasOwner = (e: EntryPoint) => effective(e).some((g) => g.kind === "owner");
const isMutating = (e: EntryPoint) => MUTATING.has(e.method) || e.dataAccess.some((d) => d.op !== "read");
const resources = (e: EntryPoint) => new Set(e.dataAccess.map((d) => normalizeResource(d.resource)).filter(Boolean));
const handlerFile = (e: EntryPoint) => e.handler?.file ?? e.file;

/** First non-parameter segment of the path: "/notes/:p" → "notes". */
const pathResource = (e: EntryPoint) => normalizeResource(normalizePath(e.path).split("/").find((s) => s && s !== ":p") ?? "");

function sameResource(a: EntryPoint, b: EntryPoint): boolean {
  const ra = resources(a);
  for (const r of resources(b)) if (ra.has(r)) return true;
  const pa = pathResource(a);
  return pa !== "" && pa === pathResource(b);
}

function siblings(e: EntryPoint, all: EntryPoint[]): EntryPoint[] {
  return all.filter((o) => o !== e && SERVER_KINDS.has(o.kind) && (o.file === e.file || handlerFile(o) === handlerFile(e) || sameResource(o, e)));
}

const firstGuard = (e: EntryPoint, pred: (k: string) => boolean): Loc[] => {
  const g = effective(e).find((x) => pred(x.kind));
  return g ? [g] : [];
};

export function findCandidates(map: Pick<LogicMap, "entryPoints" | "ownership">, max: number): { candidates: Candidate[]; byRule: Record<RuleId, number>; capped: number } {
  const all = map.entryPoints;
  const server = all.filter((e) => SERVER_KINDS.has(e.kind));
  const nonPublic = server.filter((e) => !e.public);
  const authnShare = nonPublic.length ? nonPublic.filter(hasAuthn).length / nonPublic.length : 0;
  const appHasRoles = server.some(hasRole);
  const ownedBy = new Map<string, Loc>();
  for (const o of map.ownership) {
    const r = normalizeResource(o.resource);
    if (r && !ownedBy.has(r)) ownedBy.set(r, o);
  }
  // A resource is owned when some access to it is filtered by the caller.
  for (const e of all) {
    for (const d of e.dataAccess) {
      const r = normalizeResource(d.resource);
      if (r && (d.filteredBy === "caller-identity" || d.filteredBy === "both") && !ownedBy.has(r)) ownedBy.set(r, d);
    }
  }

  const out: Array<Omit<Candidate, "id"> & { rank: number }> = [];
  const add = (c: Omit<Candidate, "id" | "cwe">, rank: number) => out.push({ ...c, cwe: RULES[c.rule].cwe, rank });

  for (const e of all) {
    // Mutating and privileged entry points first, then rule order.
    const weight = ((isMutating(e) ? 0 : 2) + (e.privileged ? 0 : 1)) * 100;

    // R4: a guard that only runs after the handler has acted.
    const late = e.guards.filter((g) => g.order === "after" && g.kind !== "other");
    if (late.length && !late.every((g) => effective(e).some((x) => x.kind === g.kind))) {
      add({ rule: "R4", missing: `the ${late[0].kind} check "${late[0].name}" runs only after the handler has acted`, target: e, references: [], evidence: late }, 0 + weight);
    }

    if (!SERVER_KINDS.has(e.kind)) continue;

    // R1: no authentication where the application otherwise requires it.
    if (!e.public && !hasAuthn(e)) {
      const refs = siblings(e, all).filter(hasAuthn);
      if (refs.length || ((isMutating(e) || e.privileged) && authnShare >= 0.5)) {
        add({ rule: "R1", missing: "authentication (no check that a caller is logged in)", target: e, references: refs.slice(0, 2), evidence: refs.slice(0, 2).flatMap((r) => firstGuard(r, (k) => k !== "other")) }, 10 + weight);
      }
    }

    // R2: privileged operation behind authentication only.
    if (e.privileged && hasAuthn(e) && !hasRole(e) && (appHasRoles || /(?:^|\/)admin(?:\/|$)/i.test(e.path))) {
      const refs = server.filter((o) => o !== e && hasRole(o));
      add({ rule: "R2", missing: "a role or permission check (it only checks that the caller is logged in)", target: e, references: refs.slice(0, 2), evidence: refs.slice(0, 2).flatMap((r) => firstGuard(r, (k) => k === "role")) }, 40 + weight);
    }

    // R3: object selected by request input on a resource that has owners.
    if (e.takesObjectId && !hasOwner(e)) {
      const byInput = e.dataAccess.filter((d) => d.filteredBy === "request-input");
      for (const d of byInput) {
        const r = normalizeResource(d.resource);
        const owned = r ? ownedBy.get(r) : undefined;
        if (!owned) continue;
        const refs = all.filter((o) => o !== e && o.dataAccess.some((x) => normalizeResource(x.resource) === r && (x.filteredBy === "caller-identity" || x.filteredBy === "both")));
        add({ rule: "R3", missing: `an ownership check: ${d.resource} is looked up by request input only, but the application records who owns it`, target: e, references: refs.slice(0, 2), evidence: [owned] }, 20 + weight);
        break;
      }
    }
  }

  // R5: jobs that look records up by payload where the API scopes them by the caller.
  for (const e of all.filter((x) => JOB_KINDS.has(x.kind))) {
    for (const d of e.dataAccess.filter((x) => x.filteredBy === "request-input")) {
      const r = normalizeResource(d.resource);
      const refs = server.filter((o) => o.dataAccess.some((x) => normalizeResource(x.resource) === r && (x.filteredBy === "caller-identity" || x.filteredBy === "both")));
      if (refs.length) {
        add({ rule: "R5", missing: `the ownership or tenant scoping that the API applies to ${d.resource}`, target: e, references: refs.slice(0, 2), evidence: refs.slice(0, 2).flatMap((x) => x.dataAccess.filter((a) => normalizeResource(a.resource) === r).slice(0, 1)) }, 50 + 300);
        break;
      }
    }
  }

  // One candidate per (rule, target).
  const seen = new Set<string>();
  const unique = out.filter((c) => {
    const k = `${c.rule}|${c.target.id}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  unique.sort((a, b) => a.rank - b.rank);
  const byRule = { R1: 0, R2: 0, R3: 0, R4: 0, R5: 0 } as Record<RuleId, number>;
  for (const c of unique) byRule[c.rule]++;
  const kept = unique.slice(0, max).map(({ rank: _r, ...c }, i) => ({ ...c, id: `C${i + 1}` }));
  return { candidates: kept, byRule, capped: unique.length - kept.length };
}
