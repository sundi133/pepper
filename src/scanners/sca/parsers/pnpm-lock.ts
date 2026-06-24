import { Dependency, DependencyParser } from "../../types";

/**
 * Parse pnpm-lock.yaml to extract all resolved packages with exact versions.
 * Handles pnpm lockfile v5, v6, and v9 formats.
 */
export const pnpmLockParser: DependencyParser = {
  filePatterns: ["pnpm-lock.yaml"],
  ecosystem: "npm",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];
    const seen = new Set<string>();

    // pnpm-lock.yaml v6+ uses a "packages:" section with entries like:
    //   /@scope/name@version:
    //   /name@version:
    // pnpm-lock.yaml v9 uses entries like:
    //   '@scope/name@version':
    //   'name@version':

    const lines = content.split("\n");
    let inPackages = false;

    for (const rawLine of lines) {
      const line = rawLine.trimEnd();

      // Detect the packages: section
      if (line === "packages:" || line === "snapshots:") {
        inPackages = true;
        continue;
      }

      // Exit packages section when we hit another top-level key
      if (inPackages && !line.startsWith(" ") && !line.startsWith("'") && line !== "" && !line.startsWith("#")) {
        if (!line.startsWith("/") && !line.startsWith("'")) {
          inPackages = false;
          continue;
        }
      }

      if (!inPackages) continue;

      // Match package entries:
      // v6: "  /@scope/name@version:" or "  /name@version:"
      // v9: "  '@scope/name@version':" or "  'name@version':" or "  name@version:"
      const entry = extractPackageEntry(line);
      if (entry) {
        const key = `npm:${entry.name}@${entry.version}`;
        if (!seen.has(key)) {
          seen.add(key);
          deps.push({
            name: entry.name,
            version: entry.version,
            ecosystem: "npm",
            isDev: false,
          });
        }
      }
    }

    return deps;
  },
};

function extractPackageEntry(
  line: string,
): { name: string; version: string } | null {
  const trimmed = line.trim();
  if (!trimmed) return null;

  // Strip quotes and trailing colon
  let entry = trimmed;
  if (entry.startsWith("'") || entry.startsWith('"')) {
    entry = entry.slice(1);
  }
  if (entry.endsWith("':") || entry.endsWith('":')) {
    entry = entry.slice(0, -2);
  } else if (entry.endsWith(":")) {
    entry = entry.slice(0, -1);
  } else {
    return null; // Not a package entry line
  }

  // Strip leading / (v5/v6 format)
  if (entry.startsWith("/")) {
    entry = entry.slice(1);
  }

  // Parse @scope/name@version or name@version
  // Also handle pnpm v9 format: name@version(peer-info)
  const parenIdx = entry.indexOf("(");
  if (parenIdx > 0) {
    entry = entry.slice(0, parenIdx);
  }

  if (entry.startsWith("@")) {
    // Scoped: @scope/name@version
    const slashIdx = entry.indexOf("/");
    if (slashIdx < 0) return null;
    const rest = entry.slice(slashIdx + 1);
    const atIdx = rest.lastIndexOf("@");
    if (atIdx <= 0) return null;
    return {
      name: entry.slice(0, slashIdx + 1 + atIdx),
      version: rest.slice(atIdx + 1),
    };
  }

  // Unscoped: name@version
  const atIdx = entry.lastIndexOf("@");
  if (atIdx <= 0) return null;
  return {
    name: entry.slice(0, atIdx),
    version: entry.slice(atIdx + 1),
  };
}
