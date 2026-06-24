import { Dependency, DependencyParser } from "../../types";

/**
 * Parse poetry.lock to extract all resolved Python packages with exact versions
 * (including transitive dependencies).
 */
export const poetryLockParser: DependencyParser = {
  filePatterns: ["poetry.lock"],
  ecosystem: "PyPI",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];
    const seen = new Set<string>();

    // poetry.lock uses [[package]] sections:
    // [[package]]
    // name = "requests"
    // version = "2.31.0"
    let currentName: string | null = null;
    let currentVersion: string | null = null;

    for (const rawLine of content.split("\n")) {
      const line = rawLine.trim();

      if (line === "[[package]]") {
        if (currentName && currentVersion) {
          const key = `PyPI:${currentName}@${currentVersion}`;
          if (!seen.has(key)) {
            seen.add(key);
            deps.push({
              name: currentName,
              version: currentVersion,
              ecosystem: "PyPI",
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

    if (currentName && currentVersion) {
      const key = `PyPI:${currentName}@${currentVersion}`;
      if (!seen.has(key)) {
        seen.add(key);
        deps.push({
          name: currentName,
          version: currentVersion,
          ecosystem: "PyPI",
        });
      }
    }

    return deps;
  },
};
