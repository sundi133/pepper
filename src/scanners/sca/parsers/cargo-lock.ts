import { Dependency } from "@/scanners/types";

export function parsCargoLock(content: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n");

  // Cargo.lock format (TOML):
  // [[package]]
  // name = "lodash"
  // version = "0.1.0"
  // dependencies = ["serde"]
  //
  // [[package]]
  // name = "serde"
  // version = "1.0.0"

  let i = 0;
  while (i < lines.length) {
    const line = lines[i].trim();

    if (line === "[[package]]") {
      const pkg: { name?: string; version?: string } = {};
      i++;

      // Parse package metadata
      while (i < lines.length) {
        const metaLine = lines[i].trim();

        // End of package section
        if (metaLine === "[[package]]" || metaLine === "") {
          break;
        }

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
          ecosystem: "cargo",
          isDev: false,
        });
      }

      continue;
    }

    i++;
  }

  return deps;
}
