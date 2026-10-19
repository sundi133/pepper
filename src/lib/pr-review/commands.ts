/**
 * `@pepper` commands in pull-request comments (docs/PR_REVIEW_BOT_SPEC.md §4).
 */

export type PrCommand = "review" | "full-review" | "pause" | "resume" | "fix" | "help";

const COMMANDS: Array<[RegExp, PrCommand]> = [
  [/^full\s+review\b/i, "full-review"],
  [/^review\b/i, "review"],
  [/^pause\b/i, "pause"],
  [/^resume\b/i, "resume"],
  [/^fix\b/i, "fix"],
  [/^help\b/i, "help"],
];

/** Handles the bot answers to: always `pepper`, plus the App's slug when there is one. */
export function botHandles(appSlug: string | null | undefined): string[] {
  const handles = new Set(["pepper"]);
  if (appSlug?.trim()) handles.add(appSlug.trim().toLowerCase());
  return [...handles];
}

/**
 * The command in a comment, or null. Only the first non-empty line counts, and
 * it must start with a mention of the bot; "unknown" means the bot was
 * addressed with something it doesn't understand.
 */
export function parsePrCommand(body: string | null | undefined, handles: string[]): PrCommand | "unknown" | null {
  const first = (body ?? "").split("\n").map((l) => l.trim()).find(Boolean);
  if (!first) return null;
  const m = /^@([\w.-]+?)(?:\[bot\])?(?:\s+|$)(.*)$/i.exec(first);
  if (!m || !handles.includes(m[1].toLowerCase())) return null;
  const rest = m[2].trim();
  if (!rest) return "help";
  for (const [re, cmd] of COMMANDS) if (re.test(rest)) return cmd;
  return "unknown";
}

const TRUSTED = new Set(["OWNER", "MEMBER", "COLLABORATOR"]);

/** Only repository collaborators run commands; bots (including Pepper) are ignored. */
export function commandAuthorization(comment: { author_association?: string; user?: { type?: string; login?: string } }): "allowed" | "bot" | "not-collaborator" {
  const user = comment.user ?? {};
  if (user.type === "Bot" || /\[bot\]$/i.test(user.login ?? "")) return "bot";
  return TRUSTED.has((comment.author_association ?? "").toUpperCase()) ? "allowed" : "not-collaborator";
}

export const isTrustedAssociation = (a: string | null | undefined) => TRUSTED.has((a ?? "").toUpperCase());

export const HELP_TEXT = [
  "**Pepper commands** (repository collaborators):",
  "",
  "| Comment | |",
  "|---|---|",
  "| `@pepper review` | Review this PR's latest commit now |",
  "| `@pepper full review` | Full scan (all scanners, all files) of this PR's branch |",
  "| `@pepper pause` / `@pepper resume` | Stop or restart automatic reviews of this PR |",
  "| `@pepper fix` | In reply to a Pepper inline comment: open a fix pull request for that finding |",
  "| `@pepper help` | This list |",
  "",
  "Settings live in `.pepper.yaml` on the base branch.",
].join("\n");
