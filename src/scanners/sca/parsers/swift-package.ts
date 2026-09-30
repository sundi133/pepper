import { Dependency, DependencyParser } from "../../types";

/**
 * OSV's Swift ecosystem is "SwiftURL", keyed by the package's source URL
 * without scheme or ".git" (e.g. `github.com/vapor/vapor`). Any other
 * ecosystem label makes OSV reject the whole query batch.
 */
export const SWIFT_ECOSYSTEM = "SwiftURL";

/** `https://github.com/Vapor/vapor.git` → `github.com/Vapor/vapor`. */
export function swiftPackageUrlName(location: string): string | null {
  const trimmed = location.trim();
  if (!trimmed) return null;
  // scp-style git@github.com:owner/repo(.git)
  const scp = trimmed.match(/^[\w.-]+@([^:]+):(.+)$/);
  const raw = scp ? `${scp[1]}/${scp[2]}` : trimmed.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/^[^@/]+@/, "");
  const name = raw.replace(/\.git$/i, "").replace(/\/+$/, "");
  return name.includes("/") ? name : null;
}

/**
 * Parser for Swift Package.resolved (v1 `object.pins[].repositoryURL`,
 * v2/v3 `pins[].location`).
 */
export const swiftPackageResolvedParser: DependencyParser = {
  filePatterns: ["Package.resolved"],
  ecosystem: SWIFT_ECOSYSTEM,
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];

    try {
      const data = JSON.parse(content);
      const pins = data.pins || data.object?.pins || [];

      for (const pin of pins) {
        const location: string | undefined = pin.location || pin.repositoryURL;
        const version = pin.state?.version;
        if (!version) continue;
        const name =
          (location && swiftPackageUrlName(location)) ||
          pin.identity ||
          pin.package ||
          location?.split("/").pop()?.replace(".git", "");

        if (name) {
          deps.push({ name, version, ecosystem: SWIFT_ECOSYSTEM });
        }
      }
    } catch {
      // Not valid JSON
    }

    return deps;
  },
};
