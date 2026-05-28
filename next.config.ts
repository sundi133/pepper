import type { NextConfig } from "next";

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
};

export default nextConfig;
