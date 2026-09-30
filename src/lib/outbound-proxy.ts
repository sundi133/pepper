/**
 * Outbound (egress) proxy support.
 *
 * Every outbound HTTP call Pepper makes — LLM providers (Anthropic / OpenAI /
 * OpenRouter / Azure SDKs), OSV, deps.dev, EPSS/KEV, package registries and
 * the GitHub / Azure DevOps / Bitbucket / GitLab APIs — goes through Node's
 * global fetch or http(s) modules. Node only routes those through
 * HTTP(S)_PROXY when NODE_USE_ENV_PROXY=1 (Node >= 22.21 / 24.5), which the
 * Docker images set. git, svn and Trivy read the proxy variables themselves.
 *
 * This module only reports the effective configuration (credentials
 * redacted) so operators can see it at startup.
 */

export interface ProxyReport {
  /** A proxy variable is set. */
  configured: boolean;
  /** Node's fetch/http will actually use it. */
  active: boolean;
  httpProxy: string | null;
  httpsProxy: string | null;
  noProxy: string[];
  warnings: string[];
}

type Env = Record<string, string | undefined>;

function pick(env: Env, name: string): string | null {
  const v = env[name.toUpperCase()] ?? env[name.toLowerCase()];
  return v && v.trim() ? v.trim() : null;
}

/** Strip userinfo so a proxy URL is safe to log. */
export function redactProxyUrl(url: string): string {
  try {
    const u = new URL(url);
    if (u.username || u.password) {
      u.username = "***";
      u.password = "";
    }
    return u.toString().replace(/\/$/, "");
  } catch {
    return "(unparseable proxy URL)";
  }
}

function nodeSupportsEnvProxy(version: string): boolean {
  const [major, minor] = version.replace(/^v/, "").split(".").map(Number);
  if (major > 24) return true;
  if (major === 24) return minor >= 5;
  if (major === 22) return minor >= 21;
  return false;
}

export function describeOutboundProxy(
  env: Env = process.env,
  nodeVersion: string = process.version,
): ProxyReport {
  const httpProxy = pick(env, "http_proxy");
  const httpsProxy = pick(env, "https_proxy");
  const noProxy = (pick(env, "no_proxy") ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const configured = Boolean(httpProxy || httpsProxy);
  const flag = env.NODE_USE_ENV_PROXY === "1";
  const supported = nodeSupportsEnvProxy(nodeVersion);
  const warnings: string[] = [];

  if (configured && !flag) {
    warnings.push(
      "HTTP(S)_PROXY is set but NODE_USE_ENV_PROXY=1 is not — Node's fetch (LLM, OSV, repository APIs) will connect directly and fail in an egress-restricted network.",
    );
  }
  if (configured && flag && !supported) {
    warnings.push(
      `Node ${nodeVersion} ignores NODE_USE_ENV_PROXY; use Node >= 22.21 or >= 24.5 (the Docker images already do).`,
    );
  }
  if (configured && !noProxy.some((h) => h === "localhost" || h === "127.0.0.1")) {
    warnings.push("NO_PROXY does not include localhost / 127.0.0.1; internal calls may be sent to the proxy.");
  }

  return {
    configured,
    active: configured && flag && supported,
    httpProxy: httpProxy ? redactProxyUrl(httpProxy) : null,
    httpsProxy: httpsProxy ? redactProxyUrl(httpsProxy) : null,
    noProxy,
    warnings,
  };
}

/** One-line startup log of the proxy configuration (no credentials). */
export function logOutboundProxy(
  log: (msg: string) => void = console.log,
  warn: (msg: string) => void = console.warn,
): void {
  const r = describeOutboundProxy();
  if (!r.configured) return;
  log(
    `[proxy] outbound proxy ${r.active ? "active" : "NOT active"}: https=${r.httpsProxy ?? "-"} http=${r.httpProxy ?? "-"} no_proxy=${r.noProxy.join(",") || "-"}`,
  );
  for (const w of r.warnings) warn(`[proxy] ${w}`);
}
