import { createHmac, randomBytes, timingSafeEqual } from "crypto";

const COOKIE_NAME = "pepper_github_oauth_state";
const MAX_AGE_SEC = 600;

export { COOKIE_NAME as GITHUB_OAUTH_STATE_COOKIE };

export type GithubOAuthStatePayload = {
  orgId: string;
  userId: string;
  nonce: string;
  exp: number;
  /** Relative path to return to after OAuth (e.g. /scans/abc?openPr=findingId). */
  returnTo?: string;
};

/** Only allow same-app relative paths (prevents open redirects). */
export function sanitizeOAuthReturnTo(raw: string | null | undefined): string | undefined {
  if (!raw?.trim()) return undefined;
  let path: string;
  try {
    path = decodeURIComponent(raw.trim());
  } catch {
    return undefined;
  }
  if (!path.startsWith("/") || path.startsWith("//")) return undefined;
  if (path.includes("\n") || path.includes("\r") || path.length > 512) return undefined;
  return path;
}

function stateSecret(): string {
  const s =
    process.env.TOKEN_ENCRYPTION_KEY?.trim() ||
    process.env.NEXTAUTH_SECRET?.trim();
  if (!s) throw new Error("NEXTAUTH_SECRET required for OAuth state signing");
  return s;
}

function sign(payloadB64: string): string {
  return createHmac("sha256", stateSecret())
    .update(payloadB64)
    .digest("base64url");
}

export function createGithubOAuthState(
  orgId: string,
  userId: string,
  options?: { returnTo?: string },
): { state: string; cookieValue: string } {
  const payload: GithubOAuthStatePayload = {
    orgId,
    userId,
    nonce: randomBytes(16).toString("hex"),
    exp: Math.floor(Date.now() / 1000) + MAX_AGE_SEC,
    returnTo: options?.returnTo,
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = sign(payloadB64);
  const state = `${payloadB64}.${signature}`;
  return { state, cookieValue: state };
}

export function verifyGithubOAuthState(
  stateParam: string,
  cookieValue: string | undefined,
): GithubOAuthStatePayload | null {
  if (!stateParam || !cookieValue || stateParam !== cookieValue) {
    return null;
  }
  const dot = stateParam.lastIndexOf(".");
  if (dot < 0) return null;
  const payloadB64 = stateParam.slice(0, dot);
  const sig = stateParam.slice(dot + 1);
  const expected = sign(payloadB64);
  try {
    const a = Buffer.from(sig, "base64url");
    const b = Buffer.from(expected, "base64url");
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  } catch {
    return null;
  }
  try {
    const payload = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8"),
    ) as GithubOAuthStatePayload;
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    if (!payload.orgId || !payload.userId || !payload.nonce) return null;
    return payload;
  } catch {
    return null;
  }
}

export function oauthStateCookieOptions(): {
  httpOnly: true;
  secure: boolean;
  sameSite: "lax";
  path: string;
  maxAge: number;
} {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: MAX_AGE_SEC,
  };
}
