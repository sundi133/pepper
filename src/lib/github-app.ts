/**
 * GitHub App: configuration, App JWTs, installation tokens and the user check
 * that guards installation linking (docs/GITHUB_APP_SPEC.md §4–6).
 *
 * Installation tokens are minted on demand from the App's private key and
 * cached in memory until shortly before they expire; they are never stored.
 */
import { createPrivateKey, sign, type KeyObject } from "crypto";
import { logger } from "@/lib/logger";

const GITHUB_API = "https://api.github.com";

/** Cookie carrying the signed install state between Pepper and GitHub. */
export const GITHUB_APP_STATE_COOKIE = "pepper_github_app_state";
const GITHUB_WEB = "https://github.com";

export interface GithubAppConfig {
  appId: string;
  slug: string;
  privateKey: KeyObject;
  clientId: string;
  clientSecret: string;
  webhookSecret: string | null;
}

let cachedKey: { raw: string; key: KeyObject } | null = null;

/** PEM, PEM with literal "\n", or base64 of the PEM. */
export function parsePrivateKey(raw: string): KeyObject {
  let pem = raw.trim();
  if (!pem.includes("-----BEGIN")) pem = Buffer.from(pem, "base64").toString("utf8").trim();
  pem = pem.replace(/\\n/g, "\n");
  return createPrivateKey(pem);
}

/** The App's settings, or null when any required one is missing (then only OAuth is offered). */
export function githubAppConfig(env: Record<string, string | undefined> = process.env): GithubAppConfig | null {
  const appId = env.GITHUB_APP_ID?.trim();
  const slug = env.GITHUB_APP_SLUG?.trim();
  const rawKey = env.GITHUB_APP_PRIVATE_KEY?.trim();
  const clientId = env.GITHUB_APP_CLIENT_ID?.trim();
  const clientSecret = env.GITHUB_APP_CLIENT_SECRET?.trim();
  if (!appId || !slug || !rawKey || !clientId || !clientSecret) return null;
  try {
    if (cachedKey?.raw !== rawKey) cachedKey = { raw: rawKey, key: parsePrivateKey(rawKey) };
  } catch (err) {
    logger.error({ err: err instanceof Error ? err.message : String(err) }, "GITHUB_APP_PRIVATE_KEY is not a valid private key; the GitHub App is disabled");
    return null;
  }
  return { appId, slug, privateKey: cachedKey.key, clientId, clientSecret, webhookSecret: env.GITHUB_APP_WEBHOOK_SECRET?.trim() || null };
}

export const isGithubAppConfigured = () => githubAppConfig() !== null;

const b64url = (v: string | Buffer) => Buffer.from(v).toString("base64url");

/** RS256 JWT identifying the App (valid ≤10 minutes; issued 60 s early for clock skew). */
export function createAppJwt(cfg: Pick<GithubAppConfig, "appId" | "privateKey">, nowSec = Math.floor(Date.now() / 1000)): string {
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify({ iat: nowSec - 60, exp: nowSec + 540, iss: cfg.appId }));
  const signature = sign("RSA-SHA256", Buffer.from(`${header}.${payload}`), cfg.privateKey).toString("base64url");
  return `${header}.${payload}.${signature}`;
}

type Fetch = typeof fetch;

async function ghJson<T>(fetchImpl: Fetch, url: string, init: RequestInit & { token: string }): Promise<{ ok: boolean; status: number; data: T }> {
  const { token, ...rest } = init;
  const res = await fetchImpl(url, {
    ...rest,
    headers: {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      Authorization: `Bearer ${token}`,
      ...(rest.body ? { "Content-Type": "application/json" } : {}),
    },
  });
  let data = {} as T;
  try {
    data = (await res.json()) as T;
  } catch {
    // empty body
  }
  return { ok: res.ok, status: res.status, data };
}

export interface InstallationInfo {
  id: number;
  account: { login: string; type: string } | null;
  repository_selection: "all" | "selected";
  suspended_at: string | null;
}

export async function getInstallation(cfg: GithubAppConfig, installationId: number, fetchImpl: Fetch = fetch): Promise<InstallationInfo | null> {
  const res = await ghJson<InstallationInfo>(fetchImpl, `${GITHUB_API}/app/installations/${installationId}`, { token: createAppJwt(cfg) });
  return res.ok ? res.data : null;
}

// ─── Installation tokens ────────────────────────────────────────────────────

const REFRESH_MARGIN_MS = 5 * 60_000;
const tokenCache = new Map<string, { token: string; expiresAt: number }>();

export type InstallationTokenResult =
  | { ok: true; token: string; expiresAt: number }
  | { ok: false; reason: "removed" | "suspended" | "error"; status?: number };

/** A token for the installation, from the cache or freshly minted. */
export async function getInstallationToken(cfg: GithubAppConfig, installationId: bigint | number, fetchImpl: Fetch = fetch, now = Date.now()): Promise<InstallationTokenResult> {
  const key = String(installationId);
  const hit = tokenCache.get(key);
  if (hit && hit.expiresAt - REFRESH_MARGIN_MS > now) return { ok: true, token: hit.token, expiresAt: hit.expiresAt };
  const res = await ghJson<{ token?: string; expires_at?: string; message?: string }>(fetchImpl, `${GITHUB_API}/app/installations/${key}/access_tokens`, {
    method: "POST",
    token: createAppJwt(cfg),
  });
  if (res.ok && res.data.token) {
    const expiresAt = res.data.expires_at ? Date.parse(res.data.expires_at) : now + 3_600_000;
    tokenCache.set(key, { token: res.data.token, expiresAt });
    return { ok: true, token: res.data.token, expiresAt };
  }
  tokenCache.delete(key);
  if (res.status === 404) return { ok: false, reason: "removed", status: 404 };
  if (res.status === 403 && /suspend/i.test(res.data.message ?? "")) return { ok: false, reason: "suspended", status: 403 };
  logger.warn({ installationId: key, status: res.status }, "GitHub App: could not mint an installation token");
  return { ok: false, reason: "error", status: res.status };
}

export function forgetInstallationToken(installationId: bigint | number): void {
  tokenCache.delete(String(installationId));
}

/** For tests. */
export function clearInstallationTokenCache(): void {
  tokenCache.clear();
}

export interface InstallationRepo {
  id: number;
  name: string;
  full_name: string;
  private: boolean;
  default_branch: string;
  html_url: string;
  clone_url: string;
  owner: { login: string };
  language?: string | null;
  updated_at?: string;
}

/** Repositories the installation can access (paged; capped). */
export async function listInstallationRepositories(token: string, fetchImpl: Fetch = fetch, maxPages = 10): Promise<InstallationRepo[]> {
  const out: InstallationRepo[] = [];
  for (let page = 1; page <= maxPages; page++) {
    const res = await ghJson<{ repositories?: InstallationRepo[]; total_count?: number }>(fetchImpl, `${GITHUB_API}/installation/repositories?per_page=100&page=${page}`, { token });
    if (!res.ok) break;
    const batch = res.data.repositories ?? [];
    out.push(...batch);
    if (batch.length < 100) break;
  }
  return out;
}

// ─── Installing: who may link an installation ───────────────────────────────

export function githubAppInstallUrl(cfg: Pick<GithubAppConfig, "slug">, state: string): string {
  return `${GITHUB_WEB}/apps/${encodeURIComponent(cfg.slug)}/installations/new?state=${encodeURIComponent(state)}`;
}

/** Exchange the setup redirect's `code` for a short-lived user token (used once, then dropped). */
export async function exchangeAppUserCode(cfg: GithubAppConfig, code: string, fetchImpl: Fetch = fetch): Promise<string | null> {
  const res = await fetchImpl(`${GITHUB_WEB}/login/oauth/access_token`, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ client_id: cfg.clientId, client_secret: cfg.clientSecret, code }),
  });
  try {
    const data = (await res.json()) as { access_token?: string };
    return res.ok && data.access_token ? data.access_token : null;
  } catch {
    return null;
  }
}

/**
 * Whether the user behind `userToken` can access `installationId` — the check
 * that stops anyone linking another company's installation by editing the
 * setup URL (spec §5).
 */
export async function userCanAccessInstallation(userToken: string, installationId: number, fetchImpl: Fetch = fetch, maxPages = 10): Promise<boolean> {
  for (let page = 1; page <= maxPages; page++) {
    const res = await ghJson<{ installations?: Array<{ id: number }> }>(fetchImpl, `${GITHUB_API}/user/installations?per_page=100&page=${page}`, { token: userToken });
    if (!res.ok) return false;
    const list = res.data.installations ?? [];
    if (list.some((i) => i.id === installationId)) return true;
    if (list.length < 100) return false;
  }
  return false;
}

/** Clone URL with an installation token (GitHub requires the x-access-token user). */
export function withGithubAppCredentials(repoUrl: string, token: string): string {
  try {
    const u = new URL(repoUrl);
    if (u.protocol !== "https:" && u.protocol !== "http:") return repoUrl;
    u.username = "x-access-token";
    u.password = encodeURIComponent(token.trim());
    return u.toString();
  } catch {
    return repoUrl;
  }
}
