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
import { yarnLockParser } from "./parsers/yarn-lock";
import { pnpmLockParser } from "./parsers/pnpm-lock";
import {
  requirementsTxtParser,
  pipfileLockParser,
} from "./parsers/requirements-txt";
import { pyprojectTomlParser } from "./parsers/pyproject-toml";
import { poetryLockParser } from "./parsers/poetry-lock";
import { goModParser } from "./parsers/go-mod";
import { cargoTomlParser } from "./parsers/cargo-toml";
import { cargoLockParser } from "./parsers/cargo-lock";
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
import { triageScaFindings } from "./triage";
import { enrichFindingsWithEpssKev } from "@/lib/epss-kev-enrichment";
import { enhanceSCAFindingWithRiskScore } from "./supply-chain-scorer";
import { fetchVersionInfoBatch } from "./deps-dev-client";
import { buildLicenseFindings } from "./license-findings";
import { ENABLE_DEPS_DEV } from "@/lib/constants";
import { logger } from "@/lib/logger";

const ALL_PARSERS: DependencyParser[] = [
  // JavaScript/TypeScript — lock files first for full transitive tree
  packageLockParser,
  yarnLockParser,
  pnpmLockParser,
  packageJsonParser,
  // Python — lock files first
  pipfileLockParser,
  poetryLockParser,
  requirementsTxtParser,
  pyprojectTomlParser,
  // Go
  goModParser,
  // Rust — lock file first
  cargoLockParser,
  cargoTomlParser,
  // Java/Kotlin/Scala
  pomXmlParser,
  buildGradleParser,
  // Ruby
  gemfileLockParser,
  // PHP
  composerLockParser,
  composerJsonParser,
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
            dependencies.push({ ...dep, sourceFile: filePath });
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
      ctx.scaFileList ?? ctx.fileList,
    );

    ctx.onProgress?.(
      `SCA: parsed ${dependencies.length} dependencies from ${parsedFiles.length} files`,
    );

    if (dependencies.length === 0) return [];

    // Identify direct dependencies for risk scoring by checking which deps
    // came from manifest files (not lock files). Manifest parsers only extract
    // direct deps; lock file parsers may include transitive deps.
    const MANIFEST_NAMES = new Set([
      "package.json", "requirements.txt", "Pipfile", "go.mod", "Cargo.toml",
      "pom.xml", "Gemfile", "composer.json", "pyproject.toml", "pubspec.yaml",
      "mix.exs", "Package.swift", "build.gradle", "build.gradle.kts",
      ".csproj", ".fsproj", ".vbproj",
    ]);
    const directDependencies = new Set<string>();
    for (const dep of dependencies) {
      if (dep.sourceFile && MANIFEST_NAMES.has(path.basename(dep.sourceFile))) {
        directDependencies.add(dep.name);
      }
    }

    if (ctx.orgSettings.vulnDbMode === "offline") {
      ctx.onProgress?.(
        "SCA: vulnerability database is offline; skipping OSV vulnerability lookup",
      );
      return [];
    }

    // License policy via deps.dev. Independent of OSV, and kept out of the CVE
    // triage path below since it is not a vulnerability.
    let licenseFindings: RawFinding[] = [];
    if (ENABLE_DEPS_DEV) {
      await ctx.waitIfPaused?.();
      ctx.onProgress?.(
        `SCA: resolving licenses for ${dependencies.length} dependencies...`,
      );
      try {
        const infoByKey = await fetchVersionInfoBatch(dependencies, {
          signal: ctx.signal,
        });
        licenseFindings = buildLicenseFindings(
          dependencies,
          infoByKey,
          directDependencies,
        );
        ctx.onProgress?.(
          `SCA: resolved ${infoByKey.size} package licenses, ${licenseFindings.length} policy issues`,
        );
      } catch (err) {
        // Never fail a scan because license metadata was unavailable.
        logger.warn({ err }, "deps.dev license enrichment failed");
      }
    }

    await ctx.waitIfPaused?.();
    ctx.onProgress?.(
      `SCA: querying OSV for ${dependencies.length} dependencies...`,
    );
    let findings = await queryOsvBatch(
      dependencies,
      ctx.orgSettings.osvApiUrl,
      { workDir: ctx.workDir, fileList: ctx.fileList },
    );

    // EPSS + CISA KEV enrichment (additive metadata, graceful degradation)
    ctx.onProgress?.(`SCA: enriching ${findings.length} findings with EPSS/KEV data...`);
    findings = await enrichFindingsWithEpssKev(findings);

    // Enhance findings with supply-chain risk scoring
    ctx.onProgress?.(`SCA: scoring supply-chain risk for ${findings.length} vulnerabilities...`);
    findings = findings.map((f) =>
      enhanceSCAFindingWithRiskScore(f, directDependencies),
    );

    if (findings.length > 0 && ctx.orgSettings.enableLlmSast) {
      ctx.onProgress?.(`SCA: AI triaging ${findings.length} CVE findings...`);
      findings = await triageScaFindings(
        findings,
        {
          provider: ctx.orgSettings.llmProvider,
          baseUrl: ctx.orgSettings.llmBaseUrl,
          apiKey: ctx.orgSettings.llmApiKey,
          model: ctx.orgSettings.llmModel,
        },
        { workDir: ctx.workDir, fileList: ctx.fileList },
      );
    }

    ctx.onProgress?.(
      `SCA: ${findings.length} actionable vulnerabilities, ${licenseFindings.length} license issues`,
    );
    return [...findings, ...licenseFindings];
  },
};

