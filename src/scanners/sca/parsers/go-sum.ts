import { Dependency } from "@/scanners/types";

export function parseGoSum(content: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n");
  const seenVersions = new Set<string>();

  // go.sum format (one entry per line):
  // module.go.dev v1.0.0 h1:...
  // module.go.dev v1.0.0/go.mod h1:...
  //
  // Extract unique module@version pairs (skip /go.mod variants)

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("//")) continue;

    // Format: "module version hash" (tab or space separated)
    const parts = trimmed.split(/\s+/);
    if (parts.length < 2) continue;

    const module = parts[0];
    const version = parts[1];

    // Skip /go.mod entries (redundant with main module entry)
    if (version.includes("/go.mod")) continue;

    // Deduplicate: if we've seen module@version, skip
    const key = `${module}@${version}`;
    if (seenVersions.has(key)) continue;
    seenVersions.add(key);

    // Version format: v1.2.3 or v1.2.3-pre.0+meta
    if (!version.startsWith("v")) continue;

    deps.push({
      name: module,
      version: version.split("+")[0], // Remove build metadata if present
      ecosystem: "go",
      isDev: false,
    });
  }

  return deps;
}
