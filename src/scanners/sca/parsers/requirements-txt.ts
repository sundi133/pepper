import { Dependency, DependencyParser } from "../../types";

export const requirementsTxtParser: DependencyParser = {
  filePatterns: ["requirements.txt", "requirements-dev.txt", "requirements-test.txt"],
  ecosystem: "PyPI",
  parse(content: string, filePath: string): Dependency[] {
    const deps: Dependency[] = [];
    const isDev = filePath.includes("dev") || filePath.includes("test");

    for (const rawLine of content.split("\n")) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#") || line.startsWith("-")) continue;

      const match = line.match(/^([a-zA-Z0-9_.-]+)\s*(?:==|>=|<=|~=|!=)\s*([^\s;,#]+)/);
      if (match) {
        deps.push({
          name: match[1],
          version: match[2],
          ecosystem: "PyPI",
          isDev,
        });
      }
    }

    return deps;
  },
};

export const pipfileLockParser: DependencyParser = {
  filePatterns: ["Pipfile.lock"],
  ecosystem: "PyPI",
  parse(content: string): Dependency[] {
    try {
      const lock = JSON.parse(content);
      const deps: Dependency[] = [];

      for (const [section, packages] of Object.entries(lock)) {
        if (section !== "default" && section !== "develop") continue;
        const isDev = section === "develop";

        for (const [name, info] of Object.entries(
          packages as Record<string, { version?: string }>
        )) {
          if (info.version) {
            deps.push({
              name,
              version: info.version.replace(/^==/, ""),
              ecosystem: "PyPI",
              isDev,
            });
          }
        }
      }

      return deps;
    } catch {
      return [];
    }
  },
};
