import { Dependency, DependencyParser } from "../../types";

export const composerJsonParser: DependencyParser = {
  filePatterns: ["composer.json"],
  ecosystem: "Packagist",
  parse(content: string): Dependency[] {
    try {
      const pkg = JSON.parse(content);
      const deps: Dependency[] = [];

      if (pkg.require) {
        for (const [name, version] of Object.entries(pkg.require)) {
          if (name === "php" || name.startsWith("ext-")) continue;
          deps.push({
            name,
            version: cleanVersion(version as string),
            ecosystem: "Packagist",
            isDev: false,
          });
        }
      }

      if (pkg["require-dev"]) {
        for (const [name, version] of Object.entries(pkg["require-dev"])) {
          deps.push({
            name,
            version: cleanVersion(version as string),
            ecosystem: "Packagist",
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

export const composerLockParser: DependencyParser = {
  filePatterns: ["composer.lock"],
  ecosystem: "Packagist",
  parse(content: string): Dependency[] {
    try {
      const lock = JSON.parse(content);
      const deps: Dependency[] = [];

      for (const pkg of lock.packages || []) {
        if (pkg.name && pkg.version) {
          deps.push({
            name: pkg.name,
            version: pkg.version.replace(/^v/, ""),
            ecosystem: "Packagist",
            isDev: false,
          });
        }
      }

      for (const pkg of lock["packages-dev"] || []) {
        if (pkg.name && pkg.version) {
          deps.push({
            name: pkg.name,
            version: pkg.version.replace(/^v/, ""),
            ecosystem: "Packagist",
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

function cleanVersion(version: string): string {
  return version.replace(/^[\^~>=<*]+/, "").trim();
}
