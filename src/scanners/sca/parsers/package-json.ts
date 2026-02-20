import { Dependency, DependencyParser } from "../../types";

export const packageJsonParser: DependencyParser = {
  filePatterns: ["package.json"],
  ecosystem: "npm",
  parse(content: string): Dependency[] {
    try {
      const pkg = JSON.parse(content);
      const deps: Dependency[] = [];

      if (pkg.dependencies) {
        for (const [name, version] of Object.entries(pkg.dependencies)) {
          deps.push({
            name,
            version: cleanVersion(version as string),
            ecosystem: "npm",
            isDev: false,
          });
        }
      }

      if (pkg.devDependencies) {
        for (const [name, version] of Object.entries(pkg.devDependencies)) {
          deps.push({
            name,
            version: cleanVersion(version as string),
            ecosystem: "npm",
            isDev: true,
          });
        }
      }

      return deps;
    } catch {
      return [];
    }
  },
};

export const packageLockParser: DependencyParser = {
  filePatterns: ["package-lock.json"],
  ecosystem: "npm",
  parse(content: string): Dependency[] {
    try {
      const lock = JSON.parse(content);
      const deps: Dependency[] = [];

      if (lock.packages) {
        for (const [pkgPath, info] of Object.entries(
          lock.packages as Record<string, { version?: string; dev?: boolean }>,
        )) {
          if (!pkgPath || pkgPath === "") continue;
          const name = pkgPath.replace(/^node_modules\//, "");
          if (info.version) {
            deps.push({
              name,
              version: info.version,
              ecosystem: "npm",
              isDev: info.dev ?? false,
              lockfileVersion: "3",
            });
          }
        }
      } else if (lock.dependencies) {
        for (const [name, info] of Object.entries(
          lock.dependencies as Record<
            string,
            { version?: string; dev?: boolean }
          >,
        )) {
          if (info.version) {
            deps.push({
              name,
              version: info.version,
              ecosystem: "npm",
              isDev: info.dev ?? false,
              lockfileVersion: "1",
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

function cleanVersion(version: string): string {
  return version.replace(/^[\^~>=<]+/, "").trim();
}
