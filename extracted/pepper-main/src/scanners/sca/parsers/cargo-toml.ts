import { Dependency, DependencyParser } from "../../types";

export const cargoTomlParser: DependencyParser = {
  filePatterns: ["Cargo.toml"],
  ecosystem: "crates.io",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];
    let currentSection = "";

    for (const rawLine of content.split("\n")) {
      const line = rawLine.trim();

      const sectionMatch = line.match(/^\[(.+)\]$/);
      if (sectionMatch) {
        currentSection = sectionMatch[1];
        continue;
      }

      if (
        currentSection === "dependencies" ||
        currentSection === "dev-dependencies" ||
        currentSection === "build-dependencies"
      ) {
        const isDev =
          currentSection === "dev-dependencies" ||
          currentSection === "build-dependencies";

        // Simple form: name = "version"
        const simpleMatch = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/);
        if (simpleMatch) {
          deps.push({
            name: simpleMatch[1],
            version: simpleMatch[2].replace(/^[\^~>=<]+/, ""),
            ecosystem: "crates.io",
            isDev,
          });
          continue;
        }

        // Table form: name = { version = "..." }
        const tableMatch = line.match(
          /^([a-zA-Z0-9_-]+)\s*=\s*\{.*version\s*=\s*"([^"]+)"/,
        );
        if (tableMatch) {
          deps.push({
            name: tableMatch[1],
            version: tableMatch[2].replace(/^[\^~>=<]+/, ""),
            ecosystem: "crates.io",
            isDev,
          });
        }
      }
    }

    return deps;
  },
};
