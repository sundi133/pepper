import { Dependency, DependencyParser } from "../../types";

/**
 * Parser for Dart/Flutter pubspec.yaml
 */
export const pubspecYamlParser: DependencyParser = {
  filePatterns: ["pubspec.yaml"],
  ecosystem: "Pub",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];
    const sections = ["dependencies:", "dev_dependencies:"];

    for (const section of sections) {
      const idx = content.indexOf(section);
      if (idx === -1) continue;

      const isDev = section.startsWith("dev_");
      const lines = content.slice(idx + section.length).split("\n");

      for (const line of lines) {
        // Stop at next top-level key
        if (/^[a-z_]+:/i.test(line) && !line.startsWith(" ")) break;

        // Match: "  package_name: ^1.2.3" or "  package_name: 1.2.3"
        const match = line.match(
          /^\s{2}([a-z_][a-z0-9_]*)\s*:\s*\^?([0-9][^\s#]*)/,
        );
        if (match) {
          deps.push({
            name: match[1],
            version: match[2],
            ecosystem: "Pub",
            isDev,
          });
        }
      }
    }

    return deps;
  },
};
