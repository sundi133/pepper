/**
 * Pepper API client for the language server. Errors are classified so the
 * client can react (sign in, pick a repository, show "offline") and never
 * carry the API key.
 */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface IdeFinding {
  id: string;
  severity: Severity;
  title: string;
  description: string | null;
  filePath: string | null;
  startLine: number | null;
  endLine: number | null;
  ruleId: string | null;
  cveId: string | null;
  cweId: string | null;
  scanner: string;
  confidence: number | null;
  status: string;
  snippet: string | null;
  riskScore: number | null;
  remediation: string | null;
  attackPath: string | null;
  validation: string | null;
  url: string | null;
}

export interface RepositoryRef { id: string; name: string; repoUrl: string | null; defaultBranch: string }
export interface ScanRef { id: string; completedAt: string | null; commitSha: string | null; branch: string | null }

export interface PrecommitFinding {
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  filePath: string;
  line: number;
  snippet: string;
  category: "secret" | "sast";
  cweId?: string;
}

export type ApiErrorKind = "auth" | "forbidden" | "not-found" | "bad-request" | "server" | "network" | "insecure";

export class PepperApiError extends Error {
  constructor(public kind: ApiErrorKind, message: string, public status?: number) {
    super(message);
  }
}

export type Fetch = (url: string, init: { method?: string; headers: Record<string, string>; body?: unknown; signal?: AbortSignal }) => Promise<{ status: number; ok: boolean; json(): Promise<unknown>; text(): Promise<string> }>;

/** http:// is only allowed for the local machine (spec §7). */
export function checkServerUrl(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    throw new PepperApiError("bad-request", `"${raw}" is not a valid Pepper server URL`);
  }
  const local = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(u.hostname) || u.hostname.endsWith(".localhost");
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) {
    throw new PepperApiError("insecure", "The Pepper server URL must use https:// (http:// is allowed only for localhost)");
  }
  return u.toString().replace(/\/+$/, "");
}

export class PepperApi {
  readonly base: string;
  constructor(serverUrl: string, private apiKey: string, private fetchImpl: Fetch = globalThis.fetch as unknown as Fetch, private timeoutMs = 30_000) {
    this.base = checkServerUrl(serverUrl);
  }

  private redact(s: string): string {
    return this.apiKey ? s.split(this.apiKey).join("[api key]") : s;
  }

  async request<T>(method: string, path: string, body?: unknown, extraHeaders: Record<string, string> = {}): Promise<T> {
    if (!this.apiKey) throw new PepperApiError("auth", "Sign in to Pepper: no API key is set");
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    let res: Awaited<ReturnType<Fetch>>;
    try {
      const isRaw = body instanceof Uint8Array || (typeof FormData !== "undefined" && body instanceof FormData);
      res = await this.fetchImpl(`${this.base}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${this.apiKey}`,
          accept: "application/json",
          ...(body !== undefined && !isRaw ? { "content-type": "application/json" } : {}),
          ...extraHeaders,
        },
        body: body === undefined ? undefined : isRaw ? body : JSON.stringify(body),
        signal: ctrl.signal,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new PepperApiError("network", this.redact(`Can't reach Pepper at ${this.base}: ${msg}`));
    } finally {
      clearTimeout(timer);
    }
    if (res.ok) return (await res.json()) as T;
    let detail = "";
    try {
      const j = (await res.json()) as { error?: string };
      detail = typeof j?.error === "string" ? j.error : "";
    } catch {
      // not JSON
    }
    detail = this.redact(detail).slice(0, 300);
    if (res.status === 401) throw new PepperApiError("auth", "Pepper API key is missing or invalid", 401);
    if (res.status === 403) throw new PepperApiError("forbidden", `This API key can't do that${detail ? `: ${detail}` : ""}`, 403);
    if (res.status === 404) throw new PepperApiError("not-found", detail || "Not found", 404);
    if (res.status >= 400 && res.status < 500) throw new PepperApiError("bad-request", detail || `Request failed (${res.status})`, res.status);
    throw new PepperApiError("server", `Pepper returned an error (${res.status})${detail ? `: ${detail}` : ""}`, res.status);
  }

  repository(remote: string | null, name: string | null) {
    const q = new URLSearchParams();
    if (remote) q.set("remote", remote);
    if (name) q.set("name", name);
    return this.request<{ repository: RepositoryRef | null; matchedBy: string | null; candidates: RepositoryRef[] }>("GET", `/api/ide/repository?${q}`);
  }

  repositories() {
    return this.request<{ candidates: RepositoryRef[] }>("GET", "/api/ide/repository?all=true");
  }

  findings(repositoryId: string, branch: string | null) {
    const q = new URLSearchParams({ repositoryId });
    if (branch) q.set("branch", branch);
    return this.request<{ scan: ScanRef | null; findings: IdeFinding[]; truncated?: boolean; webBaseUrl?: string | null }>("GET", `/api/ide/findings?${q}`);
  }

  precommit(files: Array<{ path: string; content: string }>) {
    return this.request<{ findings: PrecommitFinding[] }>("POST", "/api/precommit/scan", { files, failOn: [] });
  }

  rescan(scanId: string) {
    return this.request<{ scanId: string }>("POST", `/api/scans/${encodeURIComponent(scanId)}/rescan`, {});
  }

  scan(scanId: string) {
    return this.request<ScanStatus>("GET", `/api/scans/${encodeURIComponent(scanId)}`);
  }

  setStatus(findingId: string, status: "OPEN" | "IN_PROGRESS" | "RESOLVED", note?: string) {
    return this.request<unknown>("PATCH", `/api/findings/${encodeURIComponent(findingId)}`, { status, ...(note ? { statusNote: note } : {}) });
  }

  /** Upload a zip of the working tree as a new SAST scan of `projectName`. */
  uploadScan(zip: Uint8Array, fileName: string, projectName: string) {
    const form = new FormData();
    form.set("file", new Blob([zip as BlobPart], { type: "application/zip" }), fileName);
    form.set("data", JSON.stringify({ scanType: "SAST_ONLY", projectName }));
    return this.request<{ scanId: string; projectId: string }>("POST", "/api/scans", form);
  }
}

export interface ScanStatus {
  id: string;
  status: string;
  errorMessage?: string | null;
  scannerProgress?: Record<string, { status?: string }> | null;
}

/** Percentage of scanners done, from the scan's per-scanner progress. */
export function scanPercent(s: ScanStatus): number {
  const parts = Object.values(s.scannerProgress ?? {});
  if (!parts.length) return 0;
  return Math.round((parts.filter((p) => p?.status === "DONE").length / parts.length) * 100);
}

export const TERMINAL_SCAN_STATES = new Set(["COMPLETED", "FAILED", "CANCELLED", "STOPPED"]);
