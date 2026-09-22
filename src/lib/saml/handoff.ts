/**
 * Short-lived, signed handoff token that bridges a validated SAML assertion into
 * a NextAuth session.
 *
 * NextAuth (JWT strategy) is the session authority, so our ACS route cannot mint
 * a session cookie directly. Instead, after validating the SAML assertion and
 * provisioning the user, the ACS route issues this HMAC-signed token carrying
 * only the resolved userId. The browser then calls signIn("saml", { token }),
 * and the "saml" Credentials provider verifies the token and returns the user —
 * so the assertion is validated server-side and the token is never a bearer
 * credential the client can forge. It is single-use in practice (60s TTL) and
 * signed with the app secret, exactly like the GitHub OAuth state token.
 */

import { createHmac, timingSafeEqual } from "crypto";

const MAX_AGE_SEC = 60;

interface HandoffPayload {
  userId: string;
  exp: number;
}

function secret(): string {
  const s =
    process.env.TOKEN_ENCRYPTION_KEY?.trim() ||
    process.env.NEXTAUTH_SECRET?.trim();
  if (!s) throw new Error("NEXTAUTH_SECRET required for SAML handoff signing");
  return s;
}

function sign(payloadB64: string): string {
  return createHmac("sha256", secret()).update(payloadB64).digest("base64url");
}

export function createSamlHandoffToken(userId: string): string {
  const payload: HandoffPayload = {
    userId,
    exp: Math.floor(Date.now() / 1000) + MAX_AGE_SEC,
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${payloadB64}.${sign(payloadB64)}`;
}

/** Returns the userId if the token is authentic and unexpired, else null. */
export function verifySamlHandoffToken(token: string | undefined | null): string | null {
  if (!token) return null;
  const dot = token.lastIndexOf(".");
  if (dot < 0) return null;
  const payloadB64 = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  try {
    const a = Buffer.from(sig, "base64url");
    const b = Buffer.from(sign(payloadB64), "base64url");
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  } catch {
    return null;
  }
  try {
    const payload = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8"),
    ) as HandoffPayload;
    if (!payload.userId || typeof payload.userId !== "string") return null;
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload.userId;
  } catch {
    return null;
  }
}
