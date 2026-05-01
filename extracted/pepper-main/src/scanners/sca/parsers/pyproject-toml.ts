import { Dependency, DependencyParser } from "../../types";

/**
 * Parser for Python pyproject.toml (PEP 621 + Poetry)
 */
export const pyprojectTomlParser: DependencyParser = {
  filePatterns: ["pyproject.toml"],
  ecosystem: "PyPI",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];

    // PEP 621 format: [project] dependencies = ["pkg>=1.0", ...]
    const projDepsMatch = content.match(
      /\[project\][\s\S]*?dependencies\s*=\s*\[([\s\S]*?)\]/,
    );
    if (projDepsMatch) {
      extractFromArray(projDepsMatch[1], false, deps);
    }

    // PEP 621 optional-dependencies
    const optDepsMatch = content.match(
      /\[project\.optional-dependencies\]([\s\S]*?)(?:\[|$)/,
    );
    if (optDepsMatch) {
      const arrayMatches = optDepsMatch[1].matchAll(
        /\w+\s*=\s*\[([\s\S]*?)\]/g,
      );
      for (const m of arrayMatches) {
        extractFromArray(m[1], true, deps);
      }
    }

    // Poetry format: [tool.poetry.dependencies]
    const poetryDeps = content.match(
      /\[tool\.poetry\.dependencies\]([\s\S]*?)(?:\[|$)/,
    );
    if (poetryDeps) {
      extractFromTomlSection(poetryDeps[1], false, deps);
    }

    const poetryDevDeps = content.match(
      /\[tool\.poetry\.(?:dev-dependencies|group\.dev\.dependencies)\]([\s\S]*?)(?:\[|$)/,
    );
    if (poetryDevDeps) {
      extractFromTomlSection(poetryDevDeps[1], true, deps);
    }

    return deps;
  },
};

function extractFromArray(
  arrayContent: string,
  isDev: boolean,
  deps: Dependency[],
) {
  // Match "package>=1.0.0" or "package==1.0.0" or "package~=1.0"
  const pattern =
    /["']([a-zA-Z0-9_-]+)(?:\[[^\]]*\])?\s*([><=~!]+)\s*([0-9][^"'\s,]*)["']/g;
  let match;
  while ((match = pattern.exec(arrayContent)) !== null) {
    deps.push({
      name: match[1],
      version: match[3],
      ecosystem: "PyPI",
      isDev,
    });
  }
}

function extractFromTomlSection(
  section: string,
  isDev: boolean,
  deps: Dependency[],
) {
  for (const line of section.split("\n")) {
    // Skip python version constraint
    if (line.trim().startsWith("python")) continue;

    // Simple: name = "^1.2.3"
    const simpleMatch = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/);
    if (simpleMatch) {
      const version = simpleMatch[2].replace(/^[\^~>=<]+/, "");
      if (/^\d/.test(version)) {
        deps.push({
          name: simpleMatch[1],
          version,
          ecosystem: "PyPI",
          isDev,
        });
      }
      continue;
    }

    // Table: name = { version = "^1.2.3", ... }
    const tableMatch = line.match(
      /^([a-zA-Z0-9_-]+)\s*=\s*\{.*version\s*=\s*"([^"]+)"/,
    );
    if (tableMatch) {
      const version = tableMatch[2].replace(/^[\^~>=<]+/, "");
      if (/^\d/.test(version)) {
        deps.push({
          name: tableMatch[1],
          version,
          ecosystem: "PyPI",
          isDev,
        });
      }
    }
  }
}
