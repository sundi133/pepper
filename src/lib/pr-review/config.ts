/**
 * `.pepper.yaml`: a repository's pull-request review settings
 * (docs/PR_REVIEW_BOT_SPEC.md §5). Read from the PR's base branch, so a PR
 * can't switch its own review off. Missing or invalid files give the defaults.
 */
import { parse } from "yaml";
import { z } from "zod";

const SEVERITY = z.enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);

export const repoConfigSchema = z
  .object({
    reviews: z
      .object({
        auto: z.boolean().default(true),
        // true keeps what Pepper did before .pepper.yaml: drafts and bot PRs
        // (Dependabot/Renovate dependency bumps) are reviewed too.
        drafts: z.boolean().default(true),
        bots: z.boolean().default(true),
        forks: z.enum(["collaborators", "all", "none"]).default("collaborators"),
        base_branches: z.array(z.string().min(1).max(200)).max(50).default(["*"]),
        scan: z.enum(["incremental", "full"]).default("incremental"),
      })
      .prefault({}),
    comments: z
      .object({
        summary: z.boolean().default(true),
        inline: z.boolean().default(true),
        // INFO keeps every inline comment Pepper posted before .pepper.yaml existed.
        inline_min_severity: SEVERITY.default("INFO"),
        max_inline: z.number().int().min(0).max(50).default(30),
      })
      .prefault({}),
    paths: z
      .object({
        exclude: z.array(z.string().min(1).max(300)).max(200).default([]),
      })
      .prefault({}),
  })
  .passthrough();

export type RepoConfig = z.infer<typeof repoConfigSchema>;

export const DEFAULT_REPO_CONFIG: RepoConfig = repoConfigSchema.parse({});

export const CONFIG_FILE_NAMES = [".pepper.yaml", ".pepper.yml"];

/** Parse a `.pepper.yaml`; invalid content gives the defaults and an error to report. */
export function parseRepoConfig(text: string | null | undefined): { config: RepoConfig; error: string | null } {
  if (!text || !text.trim()) return { config: DEFAULT_REPO_CONFIG, error: null };
  let raw: unknown;
  try {
    raw = parse(text, { maxAliasCount: 50 });
  } catch (e) {
    return { config: DEFAULT_REPO_CONFIG, error: `.pepper.yaml is not valid YAML: ${e instanceof Error ? e.message.split("\n")[0] : String(e)}` };
  }
  if (raw == null) return { config: DEFAULT_REPO_CONFIG, error: null };
  const parsed = repoConfigSchema.safeParse(raw);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    return { config: DEFAULT_REPO_CONFIG, error: `.pepper.yaml: ${issue.path.join(".") || "(root)"}: ${issue.message}` };
  }
  return { config: parsed.data, error: null };
}

/** Glob to RegExp: `**` any path, `*` within a segment, `?` one character. */
export function globToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        const slash = glob[i + 2] === "/";
        re += slash ? "(?:.*/)?" : ".*";
        i += slash ? 2 : 1;
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp(`^${re}$`);
}

export function matchesAny(value: string, globs: string[]): boolean {
  const v = value.replace(/\\/g, "/").replace(/^\.?\//, "");
  return globs.some((g) => globToRegExp(g.replace(/^\.?\//, "")).test(v));
}
