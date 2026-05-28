import { NextRequest, NextResponse } from "next/server";
import { checkRateLimit } from "./lib/rate-limit";

// ---------------------------------------------------------------------------
// 1. CORS / trusted-origin allowlist
// ---------------------------------------------------------------------------
const ALLOWED_ORIGINS = new Set([
  process.env.NEXTAUTH_URL || "https://sast.votal.ai",
]);

// Also allow the current deployment URL if set
if (process.env.NEXT_PUBLIC_APP_URL) {
  ALLOWED_ORIGINS.add(process.env.NEXT_PUBLIC_APP_URL);
}

function isAllowedOrigin(origin: string | null): boolean {
  if (!origin) return true; // same-origin requests have no Origin header
  return ALLOWED_ORIGINS.has(origin);
}

/** Parse the origin (scheme://host:port) out of a full URL, or null. */
function originOf(url: string | null): string | null {
  if (!url) return null;
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// 2. Rate limiting (Redis-backed, shared across instances)
//    Protects login / register from brute-force / credential stuffing.
// ---------------------------------------------------------------------------
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX_REQUESTS = 20; // max attempts per window per IP

const RATE_LIMITED_PATHS = new Set([
  "/api/auth/callback/credentials",
  "/api/auth/signin",
  "/api/auth/signin/credentials",
  "/api/auth/register",
]);

// ---------------------------------------------------------------------------
// 3. Allowed HTTP methods + CSRF-relevant (state-changing) methods
// ---------------------------------------------------------------------------
const API_ALLOWED_METHODS = new Set([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
]);
const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/** True when the request carries a NextAuth session cookie (browser auth). */
function hasSessionCookie(req: NextRequest): boolean {
  return req.cookies
    .getAll()
    .some((c) => c.name.includes("next-auth.session-token"));
}

// ---------------------------------------------------------------------------
// 4. Content-Security-Policy (per-request nonce)
//    A fresh nonce per request lets us drop 'unsafe-inline' from script-src so
//    injected inline scripts cannot execute (VA-02). Next.js automatically
//    propagates the nonce to its own framework scripts when it finds it in the
//    Content-Security-Policy *request* header.
// ---------------------------------------------------------------------------
const IS_DEV = process.env.NODE_ENV !== "production";

function buildCsp(nonce: string): string {
  return [
    "default-src 'self'",
    // 'unsafe-eval' is only required by the React Refresh runtime in dev; it is
    // never emitted in production builds.
    `script-src 'self' 'nonce-${nonce}'${
      IS_DEV ? " 'unsafe-eval'" : ""
    } https://hcaptcha.com https://*.hcaptcha.com`,
    // Styles still allow 'unsafe-inline': Next.js and several UI libs inject
    // inline <style> tags, and style injection is not a script-execution vector.
    "style-src 'self' 'unsafe-inline' https://hcaptcha.com https://*.hcaptcha.com",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self' https://hcaptcha.com https://*.hcaptcha.com",
    "frame-src https://hcaptcha.com https://*.hcaptcha.com",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "upgrade-insecure-requests",
  ].join("; ");
}

// ---------------------------------------------------------------------------
// 5. Authenticated / dynamic page routes that must never be edge-cached (VA-07)
// ---------------------------------------------------------------------------
const NO_STORE_PREFIXES = [
  "/dashboard",
  "/projects",
  "/repositories",
  "/scans",
  "/trends",
  "/notifications",
  "/settings",
];

function isNoStorePath(pathname: string): boolean {
  return NO_STORE_PREFIXES.some(
    (p) => pathname === p || pathname.startsWith(`${p}/`),
  );
}

/** Apply hardening headers that must be present on every response (VA-06/VA-07). */
function applyResponseHardening(
  response: NextResponse,
  pathname: string,
  csp: string,
): NextResponse {
  response.headers.set("Content-Security-Policy", csp);
  // Defense in depth: guarantee nosniff regardless of route (VA-06).
  response.headers.set("X-Content-Type-Options", "nosniff");
  // Authenticated/dynamic content and all API responses must not be cached by
  // shared/CDN caches (VA-07).
  if (pathname.startsWith("/api/") || isNoStorePath(pathname)) {
    response.headers.set("Cache-Control", "no-store, private");
  }
  return response;
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------
export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const method = req.method;
  const origin = req.headers.get("origin");

  // Generate a per-request nonce and the CSP up front so it can be attached to
  // every response (including the early error returns below).
  const nonce = crypto.randomUUID().replace(/-/g, "");
  const csp = buildCsp(nonce);

  if (pathname.startsWith("/api/")) {
    // --- CORS preflight ---
    if (method === "OPTIONS") {
      if (!isAllowedOrigin(origin)) {
        return new NextResponse(null, { status: 403 });
      }
      const preflightHeaders = new Headers();
      preflightHeaders.set(
        "Access-Control-Allow-Origin",
        origin || (ALLOWED_ORIGINS.values().next().value as string),
      );
      preflightHeaders.set(
        "Access-Control-Allow-Methods",
        "GET, POST, PUT, PATCH, DELETE",
      );
      preflightHeaders.set(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization",
      );
      preflightHeaders.set("Access-Control-Max-Age", "86400");
      preflightHeaders.set("Access-Control-Allow-Credentials", "true");
      return new NextResponse(null, { status: 204, headers: preflightHeaders });
    }

    // --- Block disallowed HTTP methods ---
    if (!API_ALLOWED_METHODS.has(method)) {
      return NextResponse.json(
        { error: "Method not allowed" },
        { status: 405 },
      );
    }

    // --- CSRF: cookie-authenticated state-changing requests must originate
    //     from a trusted origin. NextAuth's own routes carry their own CSRF
    //     token, and API-key clients (no session cookie) are exempt. ---
    if (
      MUTATING_METHODS.has(method) &&
      !pathname.startsWith("/api/auth/") &&
      hasSessionCookie(req)
    ) {
      const sourceOrigin = origin ?? originOf(req.headers.get("referer"));
      if (sourceOrigin && !isAllowedOrigin(sourceOrigin)) {
        return NextResponse.json(
          { error: "Cross-origin request blocked" },
          { status: 403 },
        );
      }
    }
  }

  // --- Rate-limit login / register endpoints ---
  if (RATE_LIMITED_PATHS.has(pathname) && method === "POST") {
    const ip =
      req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
      req.headers.get("x-real-ip") ||
      "unknown";

    const { limited } = await checkRateLimit(`auth:${ip}`, {
      windowMs: RATE_LIMIT_WINDOW_MS,
      max: RATE_LIMIT_MAX_REQUESTS,
    });
    if (limited) {
      return NextResponse.json(
        { error: "Too many attempts. Please try again later." },
        { status: 429 },
      );
    }
  }

  // --- Forward the nonce to the app so Next.js can stamp its inline scripts. ---
  // Next.js reads the nonce from the Content-Security-Policy *request* header.
  const requestHeaders = new Headers(req.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  // --- Apply CORS headers on API responses (allowlisted origins only) ---
  const response = NextResponse.next({ request: { headers: requestHeaders } });

  if (pathname.startsWith("/api/") && origin && isAllowedOrigin(origin)) {
    response.headers.set("Access-Control-Allow-Origin", origin);
    response.headers.set("Access-Control-Allow-Credentials", "true");
    response.headers.set(
      "Access-Control-Allow-Methods",
      "GET, POST, PUT, PATCH, DELETE",
    );
    response.headers.set(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization",
    );
  }

  return applyResponseHardening(response, pathname, csp);
}

export const config = {
  runtime: "nodejs",
  matcher: [
    // Match all API routes and pages (skip static files, _next, favicon)
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)",
  ],
};
