import { Dependency, DependencyParser } from "../../types";

export const goModParser: DependencyParser = {
  filePatterns: ["go.mod"],
  ecosystem: "Go",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];
    let inRequireBlock = false;

    for (const rawLine of content.split("\n")) {
      const line = rawLine.trim();

      if (line === "require (") {
        inRequireBlock = true;
        continue;
      }
      if (line === ")") {
        inRequireBlock = false;
        continue;
      }

      if (inRequireBlock) {
        const match = line.match(/^(\S+)\s+(v[\d.]+\S*)/);
        if (match) {
          deps.push({
            name: match[1],
            version: match[2],
            ecosystem: "Go",
            isDev: line.includes("// indirect"),
          });
        }
      } else if (line.startsWith("require ")) {
        const match = line.match(/^require\s+(\S+)\s+(v[\d.]+\S*)/);
        if (match) {
          deps.push({
            name: match[1],
            version: match[2],
            ecosystem: "Go",
          });
        }
      }
    }

    return deps;
  },
};
