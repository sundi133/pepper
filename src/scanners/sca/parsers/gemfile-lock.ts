import { Dependency, DependencyParser } from "../../types";

export const gemfileLockParser: DependencyParser = {
  filePatterns: ["Gemfile.lock"],
  ecosystem: "RubyGems",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];
    let inSpecs = false;

    for (const rawLine of content.split("\n")) {
      const line = rawLine;

      if (line.trim() === "specs:") {
        inSpecs = true;
        continue;
      }

      if (inSpecs && line.match(/^\S/)) {
        inSpecs = false;
        continue;
      }

      if (inSpecs) {
        // Match: "    gem-name (1.2.3)"
        const match = line.match(/^\s{4}(\S+)\s+\(([^)]+)\)/);
        if (match) {
          deps.push({
            name: match[1],
            version: match[2],
            ecosystem: "RubyGems",
          });
        }
      }
    }

    return deps;
  },
};
