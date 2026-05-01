import type { NextConfig } from "next";

// LAN dev: allow loading /_next/* from your machine IP (see Next.js allowedDevOrigins). Comma-separated.
const extraDevOrigins = (process.env.ALLOWED_DEV_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const nextConfig: NextConfig = {
  ...(extraDevOrigins.length > 0
    ? { allowedDevOrigins: extraDevOrigins }
    : {}),
};

export default nextConfig;
