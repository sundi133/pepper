import type { NextConfig } from "next";

// Largest scan upload in MB. Mirrors maxUploadMb / proxyBodySizeLimit in
// src/lib/upload-limits.ts (next.config.ts cannot import project modules;
// next-config.test.ts keeps the two in step).
const parsedUploadMb = Math.floor(Number(process.env.MAX_UPLOAD_MB?.trim()));
const maxUploadMb = Number.isFinite(parsedUploadMb) && parsedUploadMb > 0 ? parsedUploadMb : 500;

// Static security headers applied to every response. The Content-Security-Policy
// is intentionally NOT set here: it is generated per-request in middleware.ts so
// that a fresh nonce can be injected, which lets us drop 'unsafe-inline' /
// 'unsafe-eval' from script-src (see VA-02).
const securityHeaders = [
  {
    key: "X-Content-Type-Options",
    value: "nosniff",
  },
  {
    key: "X-Frame-Options",
    value: "DENY",
  },
  {
    // Intentionally disabled: the legacy XSS auditor can introduce its own
    // vulnerabilities and is superseded by the nonce-based CSP. Per OWASP
    // guidance, "0" is the correct value for modern apps (VA-08).
    key: "X-XSS-Protection",
    value: "0",
  },
  {
    key: "Strict-Transport-Security",
    value: "max-age=31536000; includeSubDomains; preload",
  },
  {
    key: "Referrer-Policy",
    value: "strict-origin-when-cross-origin",
  },
  {
    key: "Permissions-Policy",
    value:
      "camera=(), microphone=(), geolocation=(), browsing-topics=()",
  },
];

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: securityHeaders,
      },
    ];
  },
  poweredByHeader: false,
  serverExternalPackages: ["pdfkit", "fontkit", "linebreak", "png-js"],
  // One upload limit for the form, the API and the middleware body buffer
  // (MAX_UPLOAD_MB, default 500; see src/lib/upload-limits.ts).
  env: {
    MAX_UPLOAD_MB: String(maxUploadMb),
  },
  experimental: {
    proxyClientMaxBodySize: `${maxUploadMb + Math.max(50, Math.ceil(maxUploadMb / 10))}mb`,
  },
};

export default nextConfig;
