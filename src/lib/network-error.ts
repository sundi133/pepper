/**
 * Turn a failed outbound request into something an admin can act on. Node's
 * fetch reports every network problem as "fetch failed" with the real reason
 * on `cause` (sometimes nested in an AggregateError).
 */

function causeCodes(err: unknown): string[] {
  const codes: string[] = [];
  const visit = (e: unknown, depth: number) => {
    if (!e || typeof e !== "object" || depth > 4) return;
    const o = e as { code?: unknown; cause?: unknown; errors?: unknown };
    if (typeof o.code === "string") codes.push(o.code);
    if (Array.isArray(o.errors)) for (const inner of o.errors) visit(inner, depth + 1);
    visit(o.cause, depth + 1);
  };
  visit(err, 0);
  return codes;
}

const CERT_CODES = new Set([
  "SELF_SIGNED_CERT_IN_CHAIN",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "CERT_HAS_EXPIRED",
  "ERR_TLS_CERT_ALTNAME_INVALID",
]);

/** True for errors thrown because the request never got an HTTP response. */
export function isNetworkError(err: unknown): boolean {
  return err instanceof TypeError && /fetch failed/i.test(err.message) ? true : causeCodes(err).length > 0;
}

/**
 * A readable reason for a request to `target` (a URL or host) failing, or the
 * error's own message when it isn't a network failure.
 */
export function explainFetchError(err: unknown, target?: string): string {
  const fallback = err instanceof Error ? err.message : String(err);
  if (!isNetworkError(err)) return fallback;

  let host = target ?? "the server";
  let isLocalhost = false;
  let isShortName = false;
  try {
    if (target) {
      const u = new URL(target);
      host = u.host;
      isLocalhost = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
      // "tfs", "ado-server": relies on a DNS search suffix.
      isShortName = !isLocalhost && !u.hostname.includes(".") && !u.hostname.includes(":");
    }
  } catch {
    /* target wasn't a URL; use it as given */
  }
  const codes = causeCodes(err);
  const has = (...c: string[]) => c.some((x) => codes.includes(x));
  const fromServer = isLocalhost
    ? " Pepper connects from its own server, where \"localhost\" is Pepper itself: use the address the Pepper server reaches it by."
    : " Check the address, and that the Pepper server can reach it (firewall, NO_PROXY for internal hosts).";

  if (has("ECONNREFUSED")) return `Could not connect to ${host}: connection refused.${fromServer}`;
  if (has("ENOTFOUND", "EAI_AGAIN")) {
    return isShortName
      ? `Could not find ${host}: short host names aren't resolved inside Pepper's containers (no DNS search suffix). Use the fully qualified name, e.g. ${host}.yourcompany.local, or the IP address.`
      : `Could not find ${host}: the name doesn't resolve from the Pepper server. Check the address and DNS.`;
  }
  if (has("ETIMEDOUT", "UND_ERR_CONNECT_TIMEOUT", "UND_ERR_HEADERS_TIMEOUT")) return `Timed out connecting to ${host}.${fromServer}`;
  if (codes.some((c) => CERT_CODES.has(c))) {
    return `${host} presented a certificate Pepper doesn't trust. Add your internal CA (NODE_EXTRA_CA_CERTS; see the install guide's certificate section).`;
  }
  if (has("ECONNRESET", "UND_ERR_SOCKET")) return `The connection to ${host} was closed unexpectedly. A proxy or firewall may be blocking it.`;
  return `Could not reach ${host}${codes[0] ? ` (${codes[0]})` : ""}.${fromServer}`;
}
