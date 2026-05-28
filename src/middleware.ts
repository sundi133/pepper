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
// Middleware
// ---------------------------------------------------------------------------
export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const method = req.method;
  const origin = req.headers.get("origin");

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

  // --- Apply CORS headers on API responses (allowlisted origins only) ---
  const response = NextResponse.next();

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

  return response;
}

export const config = {
  runtime: "nodejs",
  matcher: [
    // Match all API routes and pages (skip static files, _next, favicon)
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)",
  ],
};
