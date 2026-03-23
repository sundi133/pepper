import { Dependency, DependencyParser } from "../../types";

/**
 * Parser for Elixir mix.lock
 * Format: "package_name": {:hex, :name, "version", ...}
 */
export const mixLockParser: DependencyParser = {
  filePatterns: ["mix.lock"],
  ecosystem: "Hex",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];

    // Match: "name": {:hex, :name, "1.2.3", ...}
    const pattern =
      /"([a-z_][a-z0-9_]*)"\s*:\s*\{:hex,\s*:(?:\w+),\s*"([^"]+)"/g;
    let match;

    while ((match = pattern.exec(content)) !== null) {
      deps.push({
        name: match[1],
        version: match[2],
        ecosystem: "Hex",
      });
    }

    return deps;
  },
};
