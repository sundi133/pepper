import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Ensure pre-commit installer can read scripts/pepper-precommit.sh in production.
  outputFileTracingIncludes: {
    "/api/precommit/install.sh": ["./scripts/pepper-precommit.sh"],
  },
};

export default nextConfig;
