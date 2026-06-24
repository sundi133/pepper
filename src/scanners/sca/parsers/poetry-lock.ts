import { Dependency } from "@/scanners/types";

export function parsePoetryLock(content: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n");

  let i = 0;
  while (i < lines.length) {
    const line = lines[i].trim();

    // Poetry lock format: [[package]] section header
    if (line.startsWith("[[package]]")) {
      const pkg: { name?: string; version?: string } = {};
      i++;

      // Parse package metadata until next [[ or [
      while (i < lines.length) {
        const metaLine = lines[i].trim();
        if (metaLine.startsWith("[[") || metaLine.startsWith("[")) break;

        // Parse name = "value" or version = "value"
        const nameMatch = metaLine.match(/^name\s*=\s*"([^"]+)"/);
        if (nameMatch) pkg.name = nameMatch[1];

        const versionMatch = metaLine.match(/^version\s*=\s*"([^"]+)"/);
        if (versionMatch) pkg.version = versionMatch[1];

        i++;
      }

      if (pkg.name && pkg.version) {
        deps.push({
          name: pkg.name,
          version: pkg.version,
          ecosystem: "pip",
          isDev: false, // Poetry lock doesn't distinguish dev deps by default
        });
      }
      continue;
    }

    i++;
  }

  return deps;
}
