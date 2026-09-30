/**
 * Files whose content is never sent to an LLM.
 *
 * Built in: private key and keystore files (masking already hides the key
 * material, but there's nothing in them for a model to analyse). Admins add
 * their own with LLM_EXCLUDE_PATHS, a comma-separated list of globs:
 *
 *   LLM_EXCLUDE_PATHS="config/prod/**,*.tfvars,deploy/secrets.yaml"
 *
 * `*` matches within one path segment, `**` across segments, `?` one
 * character. A pattern without `/` matches the file name in any directory,
 * like .gitignore. Rule-based scanners still scan these files.
 */
import path from "path";

export const BUILTIN_LLM_EXCLUDES = [
  "*.pem",
  "*.key",
  "*.p12",
  "*.pfx",
  "*.jks",
  "*.keystore",
  "*.ppk",
  "*.kdbx",
  "id_rsa",
  "id_dsa",
  "id_ecdsa",
  "id_ed25519",
];

function globToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        // "**/" matches zero or more directories; a trailing "**" matches everything below.
        if (glob[i + 2] === "/") {
          re += "(?:.*/)?";
          i += 2;
        } else {
          re += ".*";
          i += 1;
        }
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp(`^${re}$`, "i");
}

/** Admin-configured patterns from LLM_EXCLUDE_PATHS. */
export function configuredLlmExcludes(env: Record<string, string | undefined> = process.env): string[] {
  return (env.LLM_EXCLUDE_PATHS ?? "")
    .split(",")
    .map((p) => p.trim().replace(/^\.\//, ""))
    .filter(Boolean);
}

let cache: { key: string; matchers: Array<{ re: RegExp; basename: boolean }> } | null = null;

function matchersFor(env: Record<string, string | undefined>) {
  const key = env.LLM_EXCLUDE_PATHS ?? "";
  if (cache?.key !== key) {
    cache = {
      key,
      matchers: [...BUILTIN_LLM_EXCLUDES, ...configuredLlmExcludes(env)].map((p) => {
        const anchored = p.replace(/^\//, "");
        return { re: globToRegExp(anchored), basename: !p.includes("/") };
      }),
    };
  }
  return cache.matchers;
}

/** True when the file at `filePath` (relative to the repository root) must not be sent to an LLM. */
export function llmExcludedPath(filePath: string, env: Record<string, string | undefined> = process.env): boolean {
  if (!filePath) return false;
  const rel = filePath.split(path.sep).join("/").replace(/^\.?\/+/, "");
  const base = rel.slice(rel.lastIndexOf("/") + 1);
  return matchersFor(env).some((m) => m.re.test(m.basename ? base : rel));
}
