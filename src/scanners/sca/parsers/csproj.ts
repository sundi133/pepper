import { Dependency, DependencyParser } from "../../types";

/**
 * Parser for .NET .csproj / .fsproj / .vbproj files
 * Extracts PackageReference elements
 */
export const csprojParser: DependencyParser = {
  filePatterns: [], // Matched by extension in parseDependencies
  ecosystem: "NuGet",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];

    // Match: <PackageReference Include="Name" Version="1.0.0" />
    // Also: <PackageReference Include="Name" Version="1.0.0"></PackageReference>
    const pattern =
      /<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"/gi;
    let match;

    while ((match = pattern.exec(content)) !== null) {
      deps.push({
        name: match[1],
        version: match[2],
        ecosystem: "NuGet",
      });
    }

    // Also match reversed attribute order: Version before Include
    const reversePattern =
      /<PackageReference\s+Version="([^"]+)"\s+Include="([^"]+)"/gi;
    while ((match = reversePattern.exec(content)) !== null) {
      deps.push({
        name: match[2],
        version: match[1],
        ecosystem: "NuGet",
      });
    }

    return deps;
  },
};

/**
 * Parser for NuGet packages.config (older .NET format)
 */
export const packagesConfigParser: DependencyParser = {
  filePatterns: ["packages.config"],
  ecosystem: "NuGet",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];

    // Match: <package id="Name" version="1.0.0" />
    const pattern = /<package\s+id="([^"]+)"\s+version="([^"]+)"/gi;
    let match;

    while ((match = pattern.exec(content)) !== null) {
      deps.push({
        name: match[1],
        version: match[2],
        ecosystem: "NuGet",
      });
    }

    return deps;
  },
};
