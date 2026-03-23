import { Dependency, DependencyParser } from "../../types";

/**
 * Parser for Swift Package.resolved (v2 format)
 * JSON format with pins array
 */
export const swiftPackageResolvedParser: DependencyParser = {
  filePatterns: ["Package.resolved"],
  ecosystem: "SwiftPM",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];

    try {
      const data = JSON.parse(content);

      // v2 format
      const pins = data.pins || data.object?.pins || [];

      for (const pin of pins) {
        const name =
          pin.identity ||
          pin.package ||
          pin.repositoryURL?.split("/").pop()?.replace(".git", "");
        const version = pin.state?.version;

        if (name && version) {
          deps.push({
            name,
            version,
            ecosystem: "SwiftPM",
          });
        }
      }
    } catch {
      // Not valid JSON
    }

    return deps;
  },
};
