import { Dependency, RawFinding } from "../types";
import { logger } from "@/lib/logger";
import { findPackageUsageWithLines } from "./find-package-usage";
import { osvFixVersion, osvSeverity, type OsvRecord } from "./osv-severity";

const DETAIL_CONCURRENCY = 8;
const DETAIL_TIMEOUT_MS = 15_000;
const DETAIL_CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const DETAIL_CACHE_MAX = 5000;
const detailCache = new Map<string, { record: OsvVulnerability; at: number }>();

/**
 * `/v1/querybatch` returns only `id` + `modified` per vulnerability, so fetch
 * each full record (`/v1/vulns/{id}`) for severity, aliases, fix versions,
 * CWEs and descriptions. Cached per worker process; on any failure the
 * id-only record is kept so a scan never loses findings.
 */
async function fetchVulnDetails(ids: string[], apiUrl: string): Promise<Map<string, OsvVulnerability>> {
  const out = new Map<string, OsvVulnerability>();
  const now = Date.now();
  const todo: string[] = [];
  for (const id of ids) {
    const hit = detailCache.get(id);
    if (hit && now - hit.at < DETAIL_CACHE_TTL_MS) out.set(id, hit.record);
    else todo.push(id);
  }
  let next = 0;
  let failed = 0;
  const worker = async () => {
    while (next < todo.length) {
      const id = todo[next++];
      try {
        const res = await fetch(`${apiUrl}/v1/vulns/${encodeURIComponent(id)}`, {
          signal: AbortSignal.timeout(DETAIL_TIMEOUT_MS),
        });
        if (!res.ok) {
          failed++;
          continue;
        }
        const record = (await res.json()) as OsvVulnerability;
        out.set(id, record);
        if (detailCache.size >= DETAIL_CACHE_MAX) {
          const oldest = detailCache.keys().next().value;
          if (oldest !== undefined) detailCache.delete(oldest);
        }
        detailCache.set(id, { record, at: Date.now() });
      } catch {
        failed++;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(DETAIL_CONCURRENCY, todo.length) }, worker));
  if (failed) {
    logger.warn({ failed, requested: todo.length }, "OSV: some vulnerability details could not be fetched; using summary data");
  }
  return out;
}

/**
 * POST one querybatch. OSV rejects the WHOLE batch (400) when any query is
 * invalid (e.g. an unknown ecosystem), which used to drop every result — so
 * on a 400 retry each ecosystem separately and skip only the bad one.
 */
async function postQueryBatch(
  apiUrl: string,
  queries: OsvQuery[],
): Promise<Array<{ vulns?: OsvVulnerability[] }> | null> {
  const send = async (qs: OsvQuery[]) =>
    fetch(`${apiUrl}/v1/querybatch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries: qs }),
      signal: AbortSignal.timeout(30000),
    });

  const response = await send(queries);
  if (response.ok) return ((await response.json()) as OsvBatchResponse).results;
  if (response.status !== 400) {
    logger.warn({ status: response.status, batchSize: queries.length }, "OSV vulnerability batch request failed");
    return null;
  }

  const results: Array<{ vulns?: OsvVulnerability[] }> = queries.map(() => ({}));
  const byEcosystem = new Map<string, number[]>();
  queries.forEach((q, idx) => {
    byEcosystem.set(q.package.ecosystem, [...(byEcosystem.get(q.package.ecosystem) ?? []), idx]);
  });
  for (const [ecosystem, idxs] of byEcosystem) {
    const r = await send(idxs.map((k) => queries[k]));
    if (!r.ok) {
      logger.warn({ status: r.status, ecosystem, count: idxs.length }, "OSV rejected queries for this ecosystem; skipping them");
      continue;
    }
    const part = ((await r.json()) as OsvBatchResponse).results;
    idxs.forEach((k, pos) => {
      results[k] = part[pos] ?? {};
    });
  }
  return results;
}

interface OsvQuery {
  package: { name: string; ecosystem: string };
  version: string;
}

type OsvVulnerability = OsvRecord;

interface OsvBatchResponse {
  results: Array<{ vulns?: OsvVulnerability[] }>;
}

/**
 * One record per vulnerability. Databases publish the same issue under their
 * own ids (GHSA-…, RUSTSEC-…, PYSEC-…, GO-…), linked through `aliases`; each
 * came back as its own finding, so one bug in one package was reported twice.
 * The record with the highest CVSS score is kept (GitHub's, usually), and the
 * others' ids are added to its aliases.
 */
export function mergeAliasedVulns(vulns: OsvVulnerability[]): OsvVulnerability[] {
  const groups: OsvVulnerability[][] = [];
  for (const vuln of vulns) {
    const ids = new Set([vuln.id, ...(vuln.aliases ?? [])]);
    const matches = groups.filter((g) => g.some((o) => ids.has(o.id) || (o.aliases ?? []).some((a) => ids.has(a))));
    if (matches.length === 0) {
      groups.push([vuln]);
      continue;
    }
    matches[0].push(vuln);
    // This record links groups that were separate until now.
    for (const other of matches.slice(1)) {
      matches[0].push(...other);
      groups.splice(groups.indexOf(other), 1);
    }
  }
  // Highest score first, so merging never lowers the reported severity.
  const rank = (v: OsvVulnerability) => (osvSeverity(v).cvssScore ?? -1) * 10 + (v.id.startsWith("GHSA-") ? 1 : 0);
  return groups.map((group) => {
    if (group.length === 1) return group[0];
    const best = group.reduce((a, b) => (rank(b) > rank(a) ? b : a));
    const aliases = new Set(group.flatMap((v) => [v.id, ...(v.aliases ?? [])]));
    aliases.delete(best.id);
    return { ...best, aliases: [...aliases] };
  });
}

export async function queryOsvBatch(
  dependencies: Dependency[],
  apiUrl = "https://api.osv.dev",
  ctx?: { workDir: string; fileList: string[] },
): Promise<RawFinding[]> {
  if (dependencies.length === 0) return [];

  const findings: RawFinding[] = [];
  const batchSize = 1000;

  for (let i = 0; i < dependencies.length; i += batchSize) {
    const batch = dependencies.slice(i, i + batchSize);
    const queries: OsvQuery[] = batch.map((dep) => ({
      package: { name: dep.name, ecosystem: dep.ecosystem },
      version: dep.version,
    }));

    try {
      const batchResults = await postQueryBatch(apiUrl, queries);
      if (!batchResults) continue;

      const ids = [
        ...new Set(batchResults.flatMap((r) => (r?.vulns ?? []).map((v) => v.id))),
      ];
      const details = await fetchVulnDetails(ids, apiUrl);

      for (let j = 0; j < batchResults.length; j++) {
        const vulns = batchResults[j]?.vulns;
        if (!vulns || vulns.length === 0) continue;

        const dep = batch[j];

        for (const vuln of mergeAliasedVulns(vulns.map((v) => details.get(v.id) ?? v))) {
          const { severity, cvssScore } = osvSeverity(vuln);
          const cveId =
            vuln.aliases?.find((a) => a.startsWith("CVE-")) ??
            (vuln.id.startsWith("CVE-") ? vuln.id : undefined);
          const fixVersion = osvFixVersion(vuln, dep);

          // Find where this package is used in source code
          let usageLocations: Array<{ filePath: string; line: number; usage: string }> = [];
          if (ctx) {
            try {
              usageLocations = await findPackageUsageWithLines(
                ctx.workDir,
                ctx.fileList,
                dep.name,
              );
            } catch {
              // Silently continue if usage analysis fails
            }
          }

          findings.push({
            scanner: "SCA",
            severity,
            title: `${vuln.id}: ${vuln.summary || "Vulnerability in " + dep.name}`,
            description: buildDescription(vuln, dep, fixVersion),
            filePath: dep.sourceFile || undefined,
            ruleId: vuln.id,
            cveId,
            cweId: vuln.database_specific?.cwe_ids?.[0],
            confidence: 1.0,
            metadata: {
              packageName: dep.name,
              packageVersion: dep.version,
              ecosystem: dep.ecosystem,
              osvId: vuln.id,
              fixVersion,
              cvssScore: cvssScore ?? undefined,
              aliases: vuln.aliases?.length ? vuln.aliases : undefined,
              references: vuln.references?.map((r) => r.url),
              usageLocations: usageLocations.length > 0 ? usageLocations : undefined,
            },
          });
        }
      }
    } catch (error) {
      logger.warn(
        {
          err: error,
          batchStart: i,
          batchSize: batch.length,
        },
        "OSV vulnerability batch request errored",
      );
      continue;
    }
  }

  return findings;
}

function buildDescription(
  vuln: OsvVulnerability,
  dep: Dependency,
  fixVersion?: string,
): string {
  let desc = vuln.details || vuln.summary || "No description available.";
  desc += `\n\nPackage: ${dep.name}@${dep.version} (${dep.ecosystem})`;
  if (fixVersion) {
    desc += `\nFix: Upgrade to version ${fixVersion} or later.`;
  }
  return desc;
}
