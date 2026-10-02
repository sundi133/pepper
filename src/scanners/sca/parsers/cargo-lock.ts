import { Dependency, DependencyParser } from "../../types";

/**
 * Parse Cargo.lock to extract all resolved crates with exact versions
 * (including transitive dependencies).
 *
 * The workspace's own crates are listed too, without a `source`. They are not
 * dependencies, and looking them up by name finds whatever unrelated crate on
 * crates.io happens to share it (its license, its advisories), so they are
 * left out.
 */
export const cargoLockParser: DependencyParser = {
  filePatterns: ["Cargo.lock"],
  ecosystem: "crates.io",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];
    const seen = new Set<string>();
    // Only trust a missing `source` to mean "first-party" in a lock file that records sources at all.
    const recordsSources = /^source\s*=/m.test(content);

    // Cargo.lock uses [[package]] sections:
    // [[package]]
    // name = "serde"
    // version = "1.0.188"
    // source = "registry+https://github.com/rust-lang/crates.io-index"
    for (const section of content.split(/^\[\[package\]\]\s*$/m).slice(1)) {
      const name = section.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
      const version = section.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
      if (!name || !version) continue;
      if (recordsSources && !/^\s*source\s*=/m.test(section)) continue;

      const key = `crates.io:${name}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      deps.push({ name, version, ecosystem: "crates.io" });
    }

    return deps;
  },
};
