import { Dependency } from "@/scanners/types";

export function parseYarnLock(content: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n");

  // yarn.lock format (simplified for v1):
  // package-name@version-range:
  //   version "1.2.3"
  //   resolved "https://registry.yarnpkg.com/..."
  //   dependencies:
  //     other-package "^1.0.0"
  //
  // yarn.lock v2+ uses different format (lockfileVersion: 6)
  // For MVP, we focus on v1 format

  let i = 0;
  const seenVersions = new Set<string>();

  while (i < lines.length) {
    const line = lines[i];

    // Entry header: "package-name@constraint:" (often with space/quotes)
    // Format can be:
    //   package@1.0.0:
    //   "package-name@^1.0.0":
    //   @scope/package@>=1.0.0:
    if (line.trim().endsWith(":") && !line.startsWith(" ") && !line.startsWith("\t")) {
      const entry = line.trim().slice(0, -1); // Remove trailing :

      // Remove quotes if present
      const cleanEntry = entry.replace(/^"/, "").replace(/"$/, "");

      // Extract name and constraint: "package-name@1.2.3"
      // Handle scoped packages: "@scope/package-name@1.2.3"
      let name = "";
      let constraint = "";

      // Scoped package
      if (cleanEntry.startsWith("@")) {
        const secondAt = cleanEntry.indexOf("@", 1);
        if (secondAt !== -1) {
          name = cleanEntry.substring(0, secondAt);
          constraint = cleanEntry.substring(secondAt + 1);
        }
      } else {
        // Non-scoped
        const lastAt = cleanEntry.lastIndexOf("@");
        if (lastAt !== -1) {
          name = cleanEntry.substring(0, lastAt);
          constraint = cleanEntry.substring(lastAt + 1);
        }
      }

      // Now extract the actual resolved version from next lines
      i++;
      let resolvedVersion = "";

      while (i < lines.length) {
        const metaLine = lines[i];

        // End of entry (next entry or blank)
        if (!metaLine.startsWith(" ") && !metaLine.startsWith("\t") && metaLine.trim()) {
          break;
        }

        const trimmed = metaLine.trim();

        // Look for "version" field
        if (trimmed.startsWith("version ")) {
          const versionMatch = trimmed.match(/version\s+"([^"]+)"/);
          if (versionMatch) {
            resolvedVersion = versionMatch[1];
          }
        }

        // Also check for "resolved" field (contains version info in URL)
        if (trimmed.startsWith("resolved ")) {
          const resolvedMatch = trimmed.match(/resolved\s+"([^"]+)"/);
          if (resolvedMatch) {
            const url = resolvedMatch[1];
            // Extract version from URL: https://registry.yarnpkg.com/package/-/package-1.2.3.tgz
            const urlVersion = url.match(/-(\d+\.\d+\.\d+)/);
            if (urlVersion && !resolvedVersion) {
              resolvedVersion = urlVersion[1];
            }
          }
        }

        i++;
      }

      if (name && resolvedVersion) {
        const key = `${name}@${resolvedVersion}`;
        if (!seenVersions.has(key)) {
          seenVersions.add(key);
          deps.push({
            name,
            version: resolvedVersion,
            ecosystem: "npm",
            isDev: false,
          });
        }
      }

      continue;
    }

    i++;
  }

  return deps;
}
