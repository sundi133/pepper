import * as fs from "fs";
import * as path from "path";
import {
  Dependency,
  RawFinding,
  ScanContext,
  ScannerPlugin,
  DependencyParser,
} from "../types";
import { packageJsonParser, packageLockParser } from "./parsers/package-json";
import {
  requirementsTxtParser,
  pipfileLockParser,
} from "./parsers/requirements-txt";
import { pyprojectTomlParser } from "./parsers/pyproject-toml";
import { goModParser } from "./parsers/go-mod";
import { cargoTomlParser } from "./parsers/cargo-toml";
import { pomXmlParser, buildGradleParser } from "./parsers/pom-xml";
import { gemfileLockParser } from "./parsers/gemfile-lock";
import {
  composerJsonParser,
  composerLockParser,
} from "./parsers/composer-json";
import { csprojParser, packagesConfigParser } from "./parsers/csproj";
import { pubspecYamlParser } from "./parsers/pubspec-yaml";
import { mixLockParser } from "./parsers/mix-lock";
import { swiftPackageResolvedParser } from "./parsers/swift-package";
import { queryOsvBatch } from "./osv-client";

const ALL_PARSERS: DependencyParser[] = [
  // JavaScript/TypeScript
  packageLockParser,
  packageJsonParser,
  // Python
  requirementsTxtParser,
  pipfileLockParser,
  pyprojectTomlParser,
  // Go
  goModParser,
  // Rust
  cargoTomlParser,
  // Java/Kotlin/Scala
  pomXmlParser,
  buildGradleParser,
  // Ruby
  gemfileLockParser,
  // PHP
  composerJsonParser,
  composerLockParser,
  // .NET / C# / F#
  csprojParser,
  packagesConfigParser,
  // Dart/Flutter
  pubspecYamlParser,
  // Elixir
  mixLockParser,
  // Swift
  swiftPackageResolvedParser,
];

/** File extensions that are also dependency manifests (matched by extension, not filename) */
const EXTENSION_PARSERS: Record<string, DependencyParser> = {
  ".csproj": csprojParser,
  ".fsproj": csprojParser,
  ".vbproj": csprojParser,
};

export function parseDependencies(
  workDir: string,
  fileList: string[],
): { dependencies: Dependency[]; parsedFiles: string[] } {
  const dependencies: Dependency[] = [];
  const parsedFiles: string[] = [];
  const seen = new Set<string>();

  for (const filePath of fileList) {
    const fileName = path.basename(filePath);
    const ext = path.extname(filePath).toLowerCase();

    // Find matching parser by filename or extension
    const matchingParsers: DependencyParser[] = [];
    for (const parser of ALL_PARSERS) {
      if (parser.filePatterns.includes(fileName)) {
        matchingParsers.push(parser);
      }
    }
    // Check extension-based parsers (.csproj, .fsproj, .vbproj)
    if (
      EXTENSION_PARSERS[ext] &&
      !matchingParsers.includes(EXTENSION_PARSERS[ext])
    ) {
      matchingParsers.push(EXTENSION_PARSERS[ext]);
    }

    for (const parser of matchingParsers) {
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
    await ctx.waitIfPaused?.();
    const { dependencies, parsedFiles } = parseDependencies(
      ctx.workDir,
      ctx.fileList,
    );

    ctx.onProgress?.(
      `SCA: parsed ${dependencies.length} dependencies from ${parsedFiles.length} files`,
    );

    if (dependencies.length === 0) return [];

    if (ctx.orgSettings.vulnDbMode === "offline") {
      ctx.onProgress?.(
        "SCA: vulnerability database is offline; skipping OSV vulnerability lookup",
      );
      return [];
    }

    await ctx.waitIfPaused?.();
    ctx.onProgress?.(
      `SCA: querying OSV for ${dependencies.length} dependencies...`,
    );
    const findings = await queryOsvBatch(
      dependencies,
      ctx.orgSettings.osvApiUrl,
    );

    ctx.onProgress?.(`SCA: found ${findings.length} vulnerabilities`);
    return findings;
  },
};

