import type { SecretPattern } from "@/scanners/types";
import { PATTERN_DETECTORS } from "@/scanners/secrets/patterns";

const TITLES: Record<string, string> = {
  AWS_ACCESS_KEY: "AWS access key",
  GITHUB_TOKEN: "GitHub token",
  GITLAB_TOKEN: "GitLab personal access token",
  SLACK_TOKEN: "Slack token",
  STRIPE_KEY: "Stripe API key",
  PRIVATE_KEY: "Private key",
  JWT_TOKEN: "JSON Web Token",
  GOOGLE_API_KEY: "Google API key",
  SENDGRID_KEY: "SendGrid API key",
  DATABASE_URL: "Database URL with credentials",
  NPM_TOKEN: "npm access token",
  OPENAI_API_KEY: "OpenAI API key",
  API_KEY: "Hard-coded API key",
  SECRET_KEY: "Hard-coded secret key",
  AWS_SECRET_ACCESS_KEY: "AWS secret access key",
  SLACK_WEBHOOK: "Slack webhook URL",
  AZURE_STORAGE_KEY: "Azure storage account key",
  ANTHROPIC_API_KEY: "Anthropic API key",
  GENERIC_SECRET: "Hard-coded secret",
};

/**
 * Pre-commit secret detectors: the same patterns the SECRETS_PATTERN scanner
 * uses, so a commit is blocked for exactly what a scan would report.
 */
export const SECRET_PATTERNS: SecretPattern[] = Object.entries(PATTERN_DETECTORS).flatMap(
  ([type, detector]) =>
    detector.patterns.map((pattern, i) => ({
      id: `SECRET-${type}${detector.patterns.length > 1 ? `-${i + 1}` : ""}`,
      title: `${TITLES[type] ?? type} committed`,
      description: `A ${TITLES[type] ?? type} appears in this file. Remove it, rotate it, and load it from a secret store or environment variable instead.`,
      severity: detector.severity,
      pattern,
    })),
);
