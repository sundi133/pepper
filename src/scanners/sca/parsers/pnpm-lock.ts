import { Dependency } from "@/scanners/types";

export function parsePnpmLock(content: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n");

  // pnpm-lock.yaml format:
  // lockfileVersion: 5 or 6+
  // packages:
  //   /lodash/4.17.21:
  //     resolution: {integrity: sha...}
  //     dev: false
  // dependencies:
  //   lodash: 4.17.21

  let i = 0;

  // Skip header to find dependencies section
  while (i < lines.length) {
    const line = lines[i].trim();

    // v5 format: packages section
    if (line === "packages:" || line === "packages:") {
      i++;
      while (i < lines.length) {
        const pkgLine = lines[i];
        if (!pkgLine.startsWith("  /") && pkgLine.trim() && !pkgLine.startsWith(" ")) {
          break; // End of packages section
        }

        // Format: /name/version: or /name@scope/version:
        const match = pkgLine.match(/^\s+\/([^/]+)\/([^/:]+):/);
        if (match) {
          const name = match[1];
          const version = match[2];
          deps.push({
            name,
            version,
            ecosystem: "npm",
            isDev: false,
          });
        }

        i++;
      }
    }

    // v6+ format: dependencies / devDependencies
    if (line.startsWith("dependencies:") || line.startsWith("devDependencies:")) {
      const isDev = line.includes("devDependencies");
      i++;

      while (i < lines.length && lines[i].startsWith("  ")) {
        const depLine = lines[i];

        // Format: "  lodash": "4.17.21"
        const depMatch = depLine.match(/^\s+"([^"]+)":\s+"([^"]+)"/);
        if (depMatch) {
          const name = depMatch[1];
          let version = depMatch[2];

          // pnpm sometimes stores "link:" or "workspace:" — skip these
          if (!version.startsWith("link:") && !version.startsWith("workspace:")) {
            // Clean version: remove ^ ~ >= etc (store exact version if available)
            version = version.replace(/^[\^~><=]+/, "").trim();

            if (version) {
              deps.push({
                name,
                version,
                ecosystem: "npm",
                isDev,
              });
            }
          }
        }

        i++;
      }

      continue;
    }

    i++;
  }

  return deps;
}
