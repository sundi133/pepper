/**
 * EPSS (Exploit Prediction Scoring System) and CISA KEV (Known Exploited
 * Vulnerabilities) enrichment for SCA findings.
 *
 * Purely additive — if either API is unreachable the findings pass through
 * unchanged. All errors are logged and swallowed.
 */

import type { RawFinding } from "@/scanners/types";
import { logger } from "@/lib/logger";

// ─── Types ───────────────────────────────────────────────────────────────────

interface EpssEntry {
  cve: string;
  epss: string; // API returns string, e.g. "0.97131"
  percentile: string;
}

interface EpssApiResponse {
  status: string;
  "status-code": number;
  data: EpssEntry[];
}

interface KevVulnerability {
  cveID: string;
  knownRansomwareCampaignUse: string;
  dateAdded: string;
}

interface KevApiResponse {
  catalogVersion: string;
  vulnerabilities: KevVulnerability[];
}

// ─── Configuration ───────────────────────────────────────────────────────────

const EPSS_API_URL = "https://api.first.org/data/v1/epss";
const KEV_API_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_BATCH_SIZE = 100;
const EPSS_API_TIMEOUT = parseInt(
  process.env.EPSS_API_TIMEOUT || "10000",
  10,
);

// ─── KEV Cache ───────────────────────────────────────────────────────────────

let _kevCache: {
  data: Map<string, { dateAdded: string; ransomwareUse: string }>;
  fetchedAt: number;
} | null = null;

const KEV_CACHE_TTL = 60 * 60 * 1000; // 1 hour

// ─── EPSS Fetching ───────────────────────────────────────────────────────────

async function fetchEpssScores(
  cveIds: string[],
): Promise<Map<string, { epss: number; percentile: number }>> {
  const result = new Map<string, { epss: number; percentile: number }>();
  if (cveIds.length === 0) return result;

  for (let i = 0; i < cveIds.length; i += EPSS_BATCH_SIZE) {
    const batch = cveIds.slice(i, i + EPSS_BATCH_SIZE);
    try {
      const url = `${EPSS_API_URL}?cve=${batch.join(",")}`;
      const response = await fetch(url, {
        signal: AbortSignal.timeout(EPSS_API_TIMEOUT),
      });

      if (!response.ok) {
        logger.warn(
          { status: response.status, batchStart: i },
          "EPSS API request failed",
        );
        continue;
      }

      const data: EpssApiResponse = await response.json();
      for (const entry of data.data || []) {
        result.set(entry.cve, {
          epss: parseFloat(entry.epss),
          percentile: parseFloat(entry.percentile),
        });
      }
    } catch (err) {
      logger.warn({ err, batchStart: i }, "EPSS API batch request errored");
      continue;
    }
  }

  return result;
}

// ─── CISA KEV Fetching ───────────────────────────────────────────────────────

async function fetchCisaKev(): Promise<
  Map<string, { dateAdded: string; ransomwareUse: string }>
> {
  // Return cached data if fresh
  if (_kevCache && Date.now() - _kevCache.fetchedAt < KEV_CACHE_TTL) {
    return _kevCache.data;
  }

  try {
    const response = await fetch(KEV_API_URL, {
      signal: AbortSignal.timeout(15_000),
    });

    if (!response.ok) {
      logger.warn({ status: response.status }, "CISA KEV request failed");
      return _kevCache?.data ?? new Map();
    }

    const data: KevApiResponse = await response.json();
    const map = new Map<
      string,
      { dateAdded: string; ransomwareUse: string }
    >();
    for (const v of data.vulnerabilities || []) {
      map.set(v.cveID, {
        dateAdded: v.dateAdded,
        ransomwareUse: v.knownRansomwareCampaignUse,
      });
    }

    _kevCache = { data: map, fetchedAt: Date.now() };
    logger.info(
      { kevEntries: map.size },
      "CISA KEV catalog loaded",
    );
    return map;
  } catch (err) {
    logger.warn({ err }, "CISA KEV fetch errored");
    return _kevCache?.data ?? new Map();
  }
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Enrich SCA findings with EPSS scores and CISA KEV status.
 * Returns findings unchanged if enrichment is disabled or APIs fail.
 */
export async function enrichFindingsWithEpssKev(
  findings: RawFinding[],
): Promise<RawFinding[]> {
  if (process.env.ENABLE_EPSS_KEV === "false") return findings;

  // Collect unique CVE IDs
  const cveIds: string[] = [];
  for (const f of findings) {
    if (f.cveId && !cveIds.includes(f.cveId)) {
      cveIds.push(f.cveId);
    }
  }
  if (cveIds.length === 0) return findings;

  // Fetch both in parallel — graceful on failure
  const [epssMap, kevMap] = await Promise.all([
    fetchEpssScores(cveIds).catch(() => new Map()),
    fetchCisaKev().catch(() => new Map()),
  ]);

  // Enrich findings with new metadata (no mutation of originals)
  return findings.map((f) => {
    if (!f.cveId) return f;

    const epss = epssMap.get(f.cveId);
    const kev = kevMap.get(f.cveId);

    if (!epss && !kev) return f;

    return {
      ...f,
      metadata: {
        ...f.metadata,
        ...(epss
          ? { epssScore: epss.epss, epssPercentile: epss.percentile }
          : {}),
        ...(kev
          ? {
              cisaKevListed: true,
              cisaKevDateAdded: kev.dateAdded,
              cisaKevRansomwareUse: kev.ransomwareUse,
            }
          : { cisaKevListed: false }),
      },
    };
  });
}
