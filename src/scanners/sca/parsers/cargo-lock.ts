import { Dependency, DependencyParser } from "../../types";

/**
 * Parse Cargo.lock to extract all resolved crates with exact versions
 * (including transitive dependencies).
 */
export const cargoLockParser: DependencyParser = {
  filePatterns: ["Cargo.lock"],
  ecosystem: "crates.io",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];
    const seen = new Set<string>();

    // Cargo.lock uses [[package]] sections:
    // [[package]]
    // name = "serde"
    // version = "1.0.188"
    let currentName: string | null = null;
    let currentVersion: string | null = null;

    for (const rawLine of content.split("\n")) {
      const line = rawLine.trim();

      if (line === "[[package]]") {
        // Flush previous
        if (currentName && currentVersion) {
          const key = `crates.io:${currentName}@${currentVersion}`;
          if (!seen.has(key)) {
            seen.add(key);
            deps.push({
              name: currentName,
              version: currentVersion,
              ecosystem: "crates.io",
            });
          }
        }
        currentName = null;
        currentVersion = null;
        continue;
      }

      const nameMatch = line.match(/^name\s*=\s*"([^"]+)"/);
      if (nameMatch) {
        currentName = nameMatch[1];
        continue;
      }

      const versionMatch = line.match(/^version\s*=\s*"([^"]+)"/);
      if (versionMatch) {
        currentVersion = versionMatch[1];
      }
    }

    // Flush last entry
    if (currentName && currentVersion) {
      const key = `crates.io:${currentName}@${currentVersion}`;
      if (!seen.has(key)) {
        seen.add(key);
        deps.push({
          name: currentName,
          version: currentVersion,
          ecosystem: "crates.io",
        });
      }
    }

    return deps;
  },
};
