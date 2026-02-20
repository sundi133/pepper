import * as fs from "fs";
import * as path from "path";
import { Dependency, RawFinding, ScanContext, ScannerPlugin, DependencyParser } from "../types";
import { packageJsonParser, packageLockParser } from "./parsers/package-json";
import { requirementsTxtParser, pipfileLockParser } from "./parsers/requirements-txt";
import { goModParser } from "./parsers/go-mod";
import { cargoTomlParser } from "./parsers/cargo-toml";
import { pomXmlParser, buildGradleParser } from "./parsers/pom-xml";
import { gemfileLockParser } from "./parsers/gemfile-lock";
import { composerJsonParser, composerLockParser } from "./parsers/composer-json";
import { queryOsvBatch } from "./osv-client";

const ALL_PARSERS: DependencyParser[] = [
  packageLockParser,
  packageJsonParser,
  requirementsTxtParser,
  pipfileLockParser,
  goModParser,
  cargoTomlParser,
  pomXmlParser,
  buildGradleParser,
  gemfileLockParser,
  composerJsonParser,
  composerLockParser,
];

export function parseDependencies(
  workDir: string,
  fileList: string[]
): { dependencies: Dependency[]; parsedFiles: string[] } {
  const dependencies: Dependency[] = [];
  const parsedFiles: string[] = [];
  const seen = new Set<string>();

  for (const filePath of fileList) {
    const fileName = path.basename(filePath);

    for (const parser of ALL_PARSERS) {
      if (!parser.filePatterns.includes(fileName)) continue;

      const fullPath = path.join(workDir, filePath);
      try {
        const content = fs.readFileSync(fullPath, "utf-8");
        const deps = parser.parse(content, filePath);

        for (const dep of deps) {
          const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
          if (!seen.has(key)) {
            seen.add(key);
            dependencies.push(dep);
          }
        }

        if (deps.length > 0) {
          parsedFiles.push(filePath);
        }
      } catch {
        continue;
      }
    }
  }

  return { dependencies, parsedFiles };
}

export const scaScanner: ScannerPlugin = {
  name: "SCA",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    const { dependencies, parsedFiles } = parseDependencies(
      ctx.workDir,
      ctx.fileList
    );

    ctx.onProgress?.(
      `SCA: parsed ${dependencies.length} dependencies from ${parsedFiles.length} files`
    );

    if (dependencies.length === 0) return [];

    const findings = await queryOsvBatch(
      dependencies,
      ctx.orgSettings.osvApiUrl
    );

    ctx.onProgress?.(`SCA: found ${findings.length} vulnerabilities`);
    return findings;
  },
};

export { parseDependencies as getDependencies };
