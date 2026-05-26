import { NextRequest, NextResponse } from "next/server";

// ---------------------------------------------------------------------------
// 1. CORS allowlist
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

// ---------------------------------------------------------------------------
// 2. Rate limiting (in-memory, per-IP)
//    Protects login and auth callback from brute-force / credential stuffing.
// ---------------------------------------------------------------------------
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX_REQUESTS = 20; // max login attempts per window

const rateLimitMap = new Map<
  string,
  { count: number; resetAt: number }
>();

// Periodically clean up expired entries (every 5 minutes)
let lastCleanup = Date.now();
function cleanupRateLimits() {
  const now = Date.now();
  if (now - lastCleanup < 5 * 60 * 1000) return;
  lastCleanup = now;
  for (const [key, entry] of rateLimitMap) {
    if (now > entry.resetAt) rateLimitMap.delete(key);
  }
}

function isRateLimited(ip: string): boolean {
  cleanupRateLimits();
  const now = Date.now();
  const entry = rateLimitMap.get(ip);

  if (!entry || now > entry.resetAt) {
    rateLimitMap.set(ip, {
      count: 1,
      resetAt: now + RATE_LIMIT_WINDOW_MS,
    });
    return false;
  }

  entry.count++;
  return entry.count > RATE_LIMIT_MAX_REQUESTS;
}

// ---------------------------------------------------------------------------
// 3. Allowed HTTP methods per route pattern
// ---------------------------------------------------------------------------
const API_ALLOWED_METHODS = new Set([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
]);

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------
export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const method = req.method;
  const origin = req.headers.get("origin");

  // --- Block disallowed HTTP methods on API routes ---
  if (pathname.startsWith("/api/")) {
    if (method === "OPTIONS") {
      // Handle CORS preflight
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

    if (!API_ALLOWED_METHODS.has(method)) {
      return NextResponse.json(
        { error: "Method not allowed" },
        { status: 405 },
      );
    }
  }

  // --- Rate-limit login / auth callback endpoints ---
  if (
    (pathname === "/api/auth/callback/credentials" ||
      pathname === "/api/auth/signin" ||
      pathname === "/api/auth/signin/credentials") &&
    method === "POST"
  ) {
    const ip =
      req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
      req.headers.get("x-real-ip") ||
      "unknown";

    if (isRateLimited(ip)) {
      return NextResponse.json(
        {
          error:
            "Too many login attempts. Please try again later.",
        },
        { status: 429 },
      );
    }
  }

  // --- Apply CORS headers on API responses ---
  const response = NextResponse.next();

  if (pathname.startsWith("/api/")) {
    if (origin && isAllowedOrigin(origin)) {
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
    // Do not set CORS headers for disallowed origins
  }

  return response;
}

export const config = {
  matcher: [
    // Match all API routes and pages (skip static files, _next, favicon)
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)",
  ],
};
