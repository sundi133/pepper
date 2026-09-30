import { Dependency, DependencyParser } from "../../types";

/**
 * CocoaPods lock file. Top-level entries under PODS: are the installed pods:
 *   PODS:
 *     - Alamofire (5.6.4)
 *     - Firebase/Core (10.0.0):
 *       - FirebaseCore (= 10.0.0)
 * Subspecs (Firebase/Core) collapse into their pod (Firebase).
 *
 * No public vulnerability database covers the CocoaPods ecosystem, so these
 * feed the SBOM and inventory; they are not sent to OSV.
 */
export const podfileLockParser: DependencyParser = {
  filePatterns: ["Podfile.lock"],
  ecosystem: "CocoaPods",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];
    const seen = new Set<string>();
    let inPods = false;
    for (const line of content.split("\n")) {
      if (/^\S/.test(line)) {
        inPods = line.trim() === "PODS:";
        continue;
      }
      if (!inPods) continue;
      const m = line.match(/^ {2}- "?([^\s("]+)"? \(([^)]+)\)/);
      if (!m) continue;
      const name = m[1].split("/")[0];
      const version = m[2].trim();
      const key = `${name}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      deps.push({ name, version, ecosystem: "CocoaPods" });
    }
    return deps;
  },
};

/** github.com/owner/repo from a Carthage `github`/`git` source, else null. */
function githubPackage(kind: string, source: string): string | null {
  if (kind === "github") {
    const repo = source.replace(/\.git$/, "");
    return /^[\w.-]+\/[\w.-]+$/.test(repo) ? `github.com/${repo}` : null;
  }
  if (kind === "git") {
    const m = source.match(/github\.com[/:]([\w.-]+\/[\w.-]+?)(?:\.git)?\/?$/);
    return m ? `github.com/${m[1]}` : null;
  }
  return null;
}

/**
 * Carthage (`Cartfile.resolved`). GitHub-hosted frameworks are reported under
 * OSV's Swift ecosystem ("SwiftURL", package = github.com/owner/repo), the
 * same identity Swift Package Manager uses, so their advisories match.
 *   github "Alamofire/Alamofire" "5.6.4"
 *   git "https://github.com/ReactiveX/RxSwift.git" "6.5.0"
 */
export const cartfileResolvedParser: DependencyParser = {
  filePatterns: ["Cartfile.resolved"],
  ecosystem: "SwiftURL",
  parse(content: string): Dependency[] {
    const deps: Dependency[] = [];
    for (const line of content.split("\n")) {
      const m = line.trim().match(/^(github|git|binary)\s+"([^"]+)"\s+"([^"]+)"/);
      if (!m) continue;
      const name = githubPackage(m[1], m[2]);
      if (!name) continue; // binary frameworks and non-GitHub git sources
      const version = m[3].replace(/^v(?=\d)/, "");
      if (/^[0-9a-f]{40}$/i.test(version)) continue; // pinned to a commit, not a release
      deps.push({ name, version, ecosystem: "SwiftURL" });
    }
    return deps;
  },
};
