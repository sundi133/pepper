import { Dependency, DependencyParser } from "../../types";

export const pomXmlParser: DependencyParser = {
  filePatterns: ["pom.xml"],
  ecosystem: "Maven",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];

    // Simple regex-based XML parsing (no XML parser dependency needed)
    const depRegex =
      /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*(?:<version>([^<]+)<\/version>)?\s*(?:<scope>([^<]+)<\/scope>)?/g;

    let match;
    while ((match = depRegex.exec(content)) !== null) {
      const groupId = match[1].trim();
      const artifactId = match[2].trim();
      const version = match[3]?.trim();
      const scope = match[4]?.trim();

      if (version && !version.startsWith("${")) {
        deps.push({
          name: `${groupId}:${artifactId}`,
          version,
          ecosystem: "Maven",
          isDev: scope === "test" || scope === "provided",
        });
      }
    }

    return deps;
  },
};

export const buildGradleParser: DependencyParser = {
  filePatterns: ["build.gradle", "build.gradle.kts"],
  ecosystem: "Maven",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];

    // Match: implementation 'group:artifact:version'
    // Match: implementation "group:artifact:version"
    // Match: testImplementation(...)
    const depRegex =
      /(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\s*[\('"]+([^:'"]+):([^:'"]+):([^'")\s]+)/g;

    let match;
    while ((match = depRegex.exec(content)) !== null) {
      const isDev =
        match[0].includes("test") || match[0].includes("compileOnly");
      deps.push({
        name: `${match[1].trim()}:${match[2].trim()}`,
        version: match[3].trim(),
        ecosystem: "Maven",
        isDev,
      });
    }

    return deps;
  },
};
