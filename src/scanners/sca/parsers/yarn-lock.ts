import { Dependency, DependencyParser } from "../../types";

/**
 * Parse yarn.lock (both v1 and v2/berry format) to extract all resolved
 * packages with exact versions — including transitive dependencies.
 */
export const yarnLockParser: DependencyParser = {
  filePatterns: ["yarn.lock"],
  ecosystem: "npm",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];
    const seen = new Set<string>();

    // Detect v2/berry format (starts with __metadata)
    if (content.includes("__metadata:")) {
      return parseYarnBerry(content, deps, seen);
    }

    return parseYarnClassic(content, deps, seen);
  },
};

/** Yarn v1 (classic) format */
function parseYarnClassic(
  content: string,
  deps: Dependency[],
  seen: Set<string>,
): Dependency[] {
  const lines = content.split("\n");
  let currentPkgNames: string[] = [];
  let currentVersion: string | null = null;

  for (const rawLine of lines) {
    // Skip comments and empty lines
    if (rawLine.startsWith("#") || rawLine.trim() === "") {
      if (currentPkgNames.length > 0 && currentVersion) {
        addDeps(deps, seen, currentPkgNames, currentVersion);
      }
      currentPkgNames = [];
      currentVersion = null;
      continue;
    }

    // Package header line (not indented): "package@version", "package@version:"
    if (!rawLine.startsWith(" ") && !rawLine.startsWith("\t")) {
      if (currentPkgNames.length > 0 && currentVersion) {
        addDeps(deps, seen, currentPkgNames, currentVersion);
      }
      currentPkgNames = parsePackageHeader(rawLine);
      currentVersion = null;
      continue;
    }

    // Indented line: look for "version" field
    const versionMatch = rawLine.match(/^\s+version\s+"?([^"\s]+)"?/);
    if (versionMatch) {
      currentVersion = versionMatch[1];
    }
  }

  // Flush last entry
  if (currentPkgNames.length > 0 && currentVersion) {
    addDeps(deps, seen, currentPkgNames, currentVersion);
  }

  return deps;
}

/** Yarn v2/v3/v4 (berry) format — YAML-like */
function parseYarnBerry(
  content: string,
  deps: Dependency[],
  seen: Set<string>,
): Dependency[] {
  const lines = content.split("\n");
  let currentPkgNames: string[] = [];
  let currentVersion: string | null = null;

  for (const rawLine of lines) {
    // Top-level key: "package@npm:version":
    if (!rawLine.startsWith(" ") && rawLine.includes("@npm:")) {
      if (currentPkgNames.length > 0 && currentVersion) {
        addDeps(deps, seen, currentPkgNames, currentVersion);
      }
      currentPkgNames = parseBerryHeader(rawLine);
      currentVersion = null;
      continue;
    }

    // Indented "version:" field
    const versionMatch = rawLine.match(/^\s+version:\s+"?([^"\s]+)"?/);
    if (versionMatch) {
      currentVersion = versionMatch[1];
    }
  }

  if (currentPkgNames.length > 0 && currentVersion) {
    addDeps(deps, seen, currentPkgNames, currentVersion);
  }

  return deps;
}

function parsePackageHeader(line: string): string[] {
  // Classic format: "lodash@^4.17.0, lodash@^4.17.21:"
  const headerStr = line.replace(/:$/, "").trim();
  const parts = headerStr.split(",").map((s) => s.trim().replace(/^"/, "").replace(/"$/, ""));
  const names: string[] = [];
  for (const part of parts) {
    const name = extractPackageName(part);
    if (name) names.push(name);
  }
  return names;
}

function parseBerryHeader(line: string): string[] {
  // Berry format: "lodash@npm:^4.17.0, lodash@npm:^4.17.21":
  const headerStr = line.replace(/:$/, "").trim().replace(/^"/, "").replace(/"$/, "");
  const parts = headerStr.split(",").map((s) => s.trim());
  const names: string[] = [];
  for (const part of parts) {
    const atNpm = part.indexOf("@npm:");
    if (atNpm >= 0) {
      names.push(part.slice(0, atNpm));
    }
  }
  return names;
}

function extractPackageName(specifier: string): string | null {
  // "@scope/pkg@version" or "pkg@version"
  const s = specifier.trim();
  if (!s) return null;
  if (s.startsWith("@")) {
    const idx = s.indexOf("@", 1);
    return idx > 0 ? s.slice(0, idx) : null;
  }
  const idx = s.indexOf("@");
  return idx > 0 ? s.slice(0, idx) : null;
}

function addDeps(
  deps: Dependency[],
  seen: Set<string>,
  names: string[],
  version: string,
): void {
  for (const name of names) {
    const key = `npm:${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deps.push({ name, version, ecosystem: "npm", isDev: false });
  }
}
