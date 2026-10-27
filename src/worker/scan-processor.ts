import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { Job } from "bullmq";
import { prisma } from "@/lib/prisma";
import { ScanJobData } from "@/lib/queue";
import { downloadObject } from "@/lib/minio";
import { clearPreviousAttempt } from "./scan-reset";
import { runScanners } from "@/scanners";
import { ScanContext, RawFinding } from "@/scanners/types";
import { createScanLogger } from "@/lib/logger";
import { sendScanCompleteEmail } from "@/lib/email";
import { extractArchive } from "@/lib/extract-archive";
import {
  enrichFindingWithReport,
  renderReportPlainText,
  CURRENT_REPORT_VERSION,
  type StoredFindingReport,
} from "@/lib/finding-report";
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import { uploadObject } from "@/lib/minio";
import {
  generateCycloneDx,
  generateSpdx,
  purlFor,
} from "@/scanners/sca/sbom-generator";
import {
  buildVexStatements,
  buildSuppressedVexStatements,
  mergeVexStatements,
  generateOpenVex,
  generateCycloneDxVex,
  summarizeVex,
} from "@/lib/vex-generator";
import {
  signWithCosignKeyless,
  signWithRsaKey,
  digestOf,
  type SignatureBundle,
} from "@/lib/code-signing";
import { decryptSecret } from "@/lib/token-encryption";
import { computeRiskScore } from "@/lib/risk-score";
import { validateExploitability } from "@/scanners/shared/exploit-validation";
import { evaluateBuildGate } from "@/lib/build-gate";
import {
  ENABLE_EXPLOIT_VALIDATION,
  BENCHMARK_MODE,
  EXPLOIT_VALIDATION_MIN_SEVERITY,
} from "@/lib/constants";
import {
  DecompiledPathMap,
  compiledScanConfig,
  describeOutcome,
  runCompiledScan,
} from "@/lib/compiled-scan";
import { decompiledOriginOf } from "@/lib/compiled-scan/finding-origin";
import { uploadedArtifactName } from "@/lib/compiled-scan/upload";
import { maxUploadBytes } from "@/lib/upload-limits";
import { mobilePlatformOf } from "@/lib/mobile-platform";
import { generateFindingDetails } from "@/lib/generate-finding-details";
import { SCAN_STATS_KEY } from "@/lib/scan-progress";
import { isAgentArtifact, agentOwnsUpload } from "@/scanners/mobile-agent/artifact";
import { scanIncludesModule } from "@/lib/scan-types";
import { isAgentScanConfigured, agentScanUnavailableReason } from "@/scanners/mobile-agent/config";

// prisma is imported from @/lib/prisma

class ScanCancelledError extends Error {
  constructor() {
    super("Scan cancelled");
    this.name = "ScanCancelledError";
  }
}

class ScanStoppedError extends Error {
  constructor() {
    super("Scan stopped");
    this.name = "ScanStoppedError";
  }
}

export async function processScanJob(job: Job<ScanJobData>) {
  const {
    scanId,
    projectId,
    sourceType,
    sourceRef,
    scanType,
    orgSettings,
    buildGate,
  } = job.data;
  const scanModules = job.data.scanModules ?? [];
  const log = createScanLogger(scanId);
  const abortController = new AbortController();

  log.info({ scanId, scanType, scanModules, sourceType }, "Starting scan");

  const markRunning = await prisma.scan.updateMany({
    where: { id: scanId, status: { notIn: ["CANCELLED", "STOPPED"] } },
    data: {
      status: "RUNNING",
      startedAt: new Date(),
      jobId: job.id,
      scannerProgress: {},
    },
  });
  if (markRunning.count === 0) {
    abortController.abort();
    log.info("Scan was cancelled before worker started");
    return;
  }

  // The queue re-runs a job whose worker was restarted mid-scan; start clean.
  const staleFindings = await clearPreviousAttempt(scanId);
  if (staleFindings > 0) {
    log.warn({ removed: staleFindings }, "Cleared findings saved by an interrupted earlier attempt of this scan");
  }

  async function assertScanActive() {
    let loggedPaused = false;
    while (true) {
      const scan = await prisma.scan.findUnique({
        where: { id: scanId },
        select: { status: true },
      });
      if (scan?.status === "STOPPED") {
        abortController.abort();
        throw new ScanStoppedError();
      }
      if (scan?.status === "CANCELLED" || abortController.signal.aborted) {
        abortController.abort();
        throw new ScanCancelledError();
      }
      if (scan?.status !== "PAUSED") {
        if (loggedPaused) log.info("Scan resumed");
        return;
      }
      if (!loggedPaused) {
        log.info("Scan paused; waiting for resume");
        loggedPaused = true;
      }
      await sleep(3000);
    }
  }

  const workDir = path.join(os.tmpdir(), `pepper-${scanId}`);
  let incrementalChangedPaths: string[] | null = null;

  // Stop and Cancel only update the database. Without this watcher the scan
  // noticed only when a scanner happened to check, and the job kept its
  // worker slot until every scanner wound down (minutes, or forever for a
  // scanner that hangs), leaving new scans waiting in the queue. Aborting
  // kills the external tools and lets runScanners return at once.
  const stopWatcher = setInterval(() => {
    prisma.scan
      .findUnique({ where: { id: scanId }, select: { status: true } })
      .then((s) => {
        if (s?.status === "STOPPED" || s?.status === "CANCELLED") abortController.abort();
      })
      .catch(() => undefined);
  }, STOP_WATCH_INTERVAL_MS);

  try {
    // 1. Download and extract source. A re-run of an interrupted attempt
    // (worker restarted mid-scan) finds the earlier checkout still here and
    // git refuses to clone into it, so start from an empty directory.
    fs.rmSync(workDir, { recursive: true, force: true });
    fs.mkdirSync(workDir, { recursive: true });
    await assertScanActive();

    const uploadedArtifact = sourceType === "UPLOAD" ? uploadedArtifactName(sourceRef) : null;
    if (uploadedArtifact) {
      // A single compiled artifact (app.apk, service.war, App.dll) is the
      // scan source: kept as is for the compiled-code scan to decompile.
      const data = await downloadObject(sourceRef);
      fs.writeFileSync(path.join(workDir, uploadedArtifact), data);
    } else if (sourceType === "UPLOAD") {
      const data = await downloadObject(sourceRef);
      const archiveExt =
        sourceRef.match(/\.(zip|tar\.gz|tgz|tar)$/i)?.[0] || ".zip";
      const archivePath = path.join(workDir, `source${archiveExt}`);
      fs.writeFileSync(archivePath, data);
      await extractArchive(archivePath, workDir);
      fs.unlinkSync(archivePath);
    } else if (sourceType === "GIT_CLONE") {
      const { execFileSync } = await import("child_process");
      const { withGitCredentials, sanitizeGitCloneError } = await import(
        "@/lib/git-repo-url"
      );
      let repoUrl = job.data.repoUrl || sourceRef;
      const repoLog = job.data.repoUrlDisplay || repoUrl;
      if (job.data.useOrgGithubToken && job.data.orgSettings.orgId) {
        const { getOrgGithubAccessToken } = await import(
          "@/lib/github-connection"
        );
        const ghToken = await getOrgGithubAccessToken(
          job.data.orgSettings.orgId,
        );
        if (ghToken) {
          repoUrl = withGitCredentials(repoLog, ghToken);
        }
      } else if (job.data.useOrgBitbucketToken && job.data.orgSettings.orgId) {
        const { withBitbucketCredentials } = await import("@/lib/git-repo-url");
        const { getOrgBitbucketAuth } = await import(
          "@/lib/bitbucket-connection"
        );
        const bbAuth = await getOrgBitbucketAuth(job.data.orgSettings.orgId);
        if (bbAuth) {
          repoUrl = withBitbucketCredentials(
            repoLog,
            bbAuth.username,
            bbAuth.appPassword,
          );
        }
      } else if (
        job.data.useOrgAzureDevOpsToken &&
        job.data.orgSettings.orgId
      ) {
        const { withAzureDevOpsCredentials } = await import(
          "@/lib/git-repo-url"
        );
        const { getOrgAzureDevOpsAuth } = await import(
          "@/lib/azure-devops-connection"
        );
        const adoAuth = await getOrgAzureDevOpsAuth(
          job.data.orgSettings.orgId,
        );
        if (adoAuth) {
          repoUrl = withAzureDevOpsCredentials(repoLog, adoAuth.pat);
        }
      }
      const branch = job.data.branch?.trim();
      const repoDir = path.join(workDir, "repo");
      const cloneArgs = ["clone", "--depth", "1"];
      if (branch) cloneArgs.push("--branch", branch);
      cloneArgs.push(repoUrl, repoDir);
      try {
        execFileSync("git", cloneArgs, {
          timeout: 120000,
          windowsHide: process.platform === "win32",
        });
      } catch (error) {
        const message =
          error instanceof Error
            ? error.message
            : String(error);
        if (!branch || !message.includes("Remote branch")) {
          throw sanitizeGitCloneError(error, repoUrl, repoLog);
        }

        log.warn(
          { branch, repoUrl: repoLog },
          "Git branch was not found; retrying clone with repository default branch",
        );
        try {
          execFileSync(
            "git",
            ["clone", "--depth", "1", repoUrl, repoDir],
            {
              timeout: 120000,
              windowsHide: process.platform === "win32",
            },
          );
        } catch (retryError) {
          throw sanitizeGitCloneError(retryError, repoUrl, repoLog);
        }
      }

      if (scanType === "INCREMENTAL") {
        const { resolveIncrementalPathsForScanJob } = await import(
          "@/lib/incremental-scan-files"
        );
        const diffResult = await resolveIncrementalPathsForScanJob({
          repoDir,
          baseSha: job.data.baseSha,
          commitSha: job.data.commitSha,
          prNumber: job.data.prNumber,
          projectId,
          useOrgGithubToken: job.data.useOrgGithubToken,
          orgId: job.data.orgSettings.orgId,
        });
        incrementalChangedPaths = diffResult.paths;
        if (diffResult.paths !== null) {
          log.info(
            {
              method: diffResult.method,
              changedFileCount: diffResult.paths.length,
            },
            "Incremental PR diff resolved",
          );
        } else {
          log.warn(
            "Incremental PR diff resolution failed; scanning full PR branch (fallback)",
          );
        }
      }

      // Move contents up
      if (fs.existsSync(repoDir)) {
        for (const item of fs.readdirSync(repoDir)) {
          if (item === ".git") continue;
          fs.renameSync(path.join(repoDir, item), path.join(workDir, item));
        }
      }
    } else if (sourceType === "SVN_CHECKOUT") {
      const { execFileSync } = await import("child_process");
      const svnUrl = job.data.svnUrl || sourceRef;
      const svnRevision = job.data.svnRevision;
      const repoDir = path.join(workDir, "repo");

      // Verify svn CLI is available
      try {
        execFileSync("svn", ["--version", "--quiet"], {
          timeout: 5000,
          windowsHide: process.platform === "win32",
        });
      } catch {
        throw new Error(
          "SVN CLI not found. Install Subversion on the worker (e.g. apt install subversion, brew install subversion, or Windows: https://subversion.apache.org/packages.html).",
        );
      }

      // Build args array (no shell interpolation)
      const exportArgs = [
        "export",
        "--non-interactive",
        "--trust-server-cert",
        "--trust-server-cert-failures=unknown-ca,cn-mismatch,expired,not-yet-valid,other",
      ];
      if (svnRevision) {
        exportArgs.push("-r", svnRevision);
      }
      if (job.data.svnUsername) {
        exportArgs.push("--username", job.data.svnUsername);
      }
      if (job.data.svnPassword) {
        exportArgs.push("--password", job.data.svnPassword);
      }
      exportArgs.push(svnUrl, repoDir);

      log.info({ svnUrl, svnRevision }, "SVN export starting");
      try {
        execFileSync("svn", exportArgs, {
          timeout: 300000,
          windowsHide: process.platform === "win32",
        });
      } catch (svnErr) {
        let msg = svnErr instanceof Error ? svnErr.message : String(svnErr);
        // execFileSync embeds the full argv (including --password) in a
        // failed command's message; strip it before it can reach
        // Scan.errorMessage.
        if (job.data.svnPassword) {
          msg = msg.split(job.data.svnPassword).join("[REDACTED]");
        }
        if (msg.includes("E170013") || msg.includes("Unable to connect")) {
          throw new Error(`SVN connection failed — check URL: ${svnUrl}`);
        }
        if (msg.includes("E170001") || msg.includes("Authorization failed")) {
          throw new Error(
            "SVN authentication failed — check username/password.",
          );
        }
        if (msg.includes("E200009") || msg.includes("not found")) {
          throw new Error(
            `SVN path not found at ${svnUrl}. Verify the repository URL includes the correct path (e.g. /trunk).`,
          );
        }
        throw new Error(`SVN export failed: ${msg}`);
      }

      // Capture the actual revision number via svn info
      try {
        const infoArgs = [
          "info",
          "--non-interactive",
          "--trust-server-cert",
          "--trust-server-cert-failures=unknown-ca,cn-mismatch,expired,not-yet-valid,other",
          "--show-item",
          "revision",
        ];
        if (svnRevision) {
          infoArgs.push("-r", svnRevision);
        }
        if (job.data.svnUsername) {
          infoArgs.push("--username", job.data.svnUsername);
        }
        if (job.data.svnPassword) {
          infoArgs.push("--password", job.data.svnPassword);
        }
        infoArgs.push(svnUrl);

        const revOutput = execFileSync("svn", infoArgs, {
          timeout: 30000,
          encoding: "utf-8",
          windowsHide: process.platform === "win32",
        }).trim();

        if (revOutput && /^\d+$/.test(revOutput)) {
          await prisma.scan.update({
            where: { id: scanId },
            data: { commitSha: `r${revOutput}` },
          });
          log.info({ revision: revOutput }, "SVN revision captured");
        }
      } catch (infoErr) {
        log.warn({ error: infoErr }, "Could not retrieve SVN revision info");
      }

      // Move exported contents up into workDir
      if (fs.existsSync(repoDir)) {
        for (const item of fs.readdirSync(repoDir)) {
          fs.renameSync(path.join(repoDir, item), path.join(workDir, item));
        }
        fs.rmSync(repoDir, { recursive: true, force: true });
      }
    }
    await assertScanActive();

    // 2. Enumerate files (INCREMENTAL PR scans limit scanners to changed paths)
    const allFiles = enumerateFiles(workDir);
    let fileList = allFiles;
    let scaFileList: string[] | undefined;

    if (scanType === "INCREMENTAL") {
      const { applyIncrementalFileFilter } = await import(
        "@/lib/incremental-scan-files"
      );
      const filtered = applyIncrementalFileFilter(
        allFiles,
        incrementalChangedPaths,
      );
      fileList = filtered.sastAndSecretsFiles;
      scaFileList = filtered.scaFiles;
      log.info(
        {
          repositoryFileCount: allFiles.length,
          changedPathCount: filtered.changedPathCount,
          sastAndSecretsFileCount: fileList.length,
          scaFileCount: scaFileList.length,
          usedDiff: filtered.usedDiff,
          diffMethod: filtered.method,
        },
        "Incremental file filter applied",
      );
    } else {
      log.info({ fileCount: allFiles.length }, "Files enumerated");
    }

    // Filled by the compiled-code scan (step 2b): decompiled source for the
    // source scanners, and the map that shows their findings as `app.apk!/…`.
    let decompiledFiles: string[] = [];
    let decompiledPaths = new DecompiledPathMap();

    // AI enrichment: generate contextual report content via LLM for unique finding types
    async function enrichFindingsWithAi(
      findings: RawFinding[],
    ): Promise<void> {
      const llmApiKey = orgSettings.llmApiKey?.trim();
      if (!llmApiKey && orgSettings.llmProvider !== "ollama") return;

      const groups = new Map<string, RawFinding[]>();
      for (const f of findings) {
        const key = `${f.scanner}:${f.ruleId || "unknown"}`;
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key)!.push(f);
      }

      const client = createLlmClient({
        provider: orgSettings.llmProvider,
        baseUrl: orgSettings.llmBaseUrl,
        apiKey: llmApiKey,
        model: orgSettings.llmModel,
      });

      const systemPrompt = `You are a security engineer. Generate a structured vulnerability report as JSON only — no markdown, no explanation, no code fences.

Schema:
{
  "vulnerabilityName": "concise descriptive name",
  "summary": "what the issue is (2-3 sentences, specific to the finding)",
  "stepsToReproduce": ["step 1", "step 2"],
  "impact": "security impact specific to this vulnerability (2-3 sentences)",
  "remediation": ["actionable fix step 1", "actionable fix step 2"]
}`;

      const tasks: Promise<void>[] = [];
      for (const group of groups.values()) {
        const rep = group[0];
        tasks.push(
          (async () => {
            try {
              const raw = await analyzeWithLlm(
                client,
                orgSettings.llmModel,
                systemPrompt,
                JSON.stringify({
                  title: rep.title,
                  description: rep.description,
                  severity: rep.severity,
                  scanner: rep.scanner,
                  filePath: rep.filePath,
                  snippet: rep.snippet,
                  ruleId: rep.ruleId,
                  cweId: rep.cweId,
                }),
                { temperature: 0.1, maxTokens: 1024 },
              );
              const report = parseLlmJsonResponse<StoredFindingReport | null>(
                raw,
                null,
              );
              if (!report) return;
              const markdown = renderReportPlainText(report);
              for (const f of group) {
                const md = (
                  f.metadata &&
                  typeof f.metadata === "object" &&
                  !Array.isArray(f.metadata)
                    ? f.metadata
                    : {}
                ) as Record<string, unknown>;
                md.reportVersion = CURRENT_REPORT_VERSION;
                md.reportSections = report;
                md.reportMarkdown = markdown;
                f.metadata = md;
              }
            } catch (err) {
              log.warn(
                { err, key: `${rep.scanner}:${rep.ruleId}` },
                "AI enrichment failed — falling back to template-based report",
              );
            }
          })(),
        );
      }

      await Promise.all(tasks);
    }

    // Helper: insert findings into DB and increment severity counts
    async function insertFindings(rawFindings: RawFinding[]) {
      if (rawFindings.length === 0) return;
      await assertScanActive();

      // Findings in decompiled code are stored against their artifact.
      const findings =
        decompiledPaths.size > 0
          ? rawFindings.map((f) => decompiledPaths.mapFinding(f))
          : rawFindings;

      // AI enrichment: generate contextual report content for unique finding types
      await enrichFindingsWithAi(findings);

      // Check findings against org suppression rules
      let keptFindings = findings;
      let suppressedFindings: RawFinding[] = [];
      try {
        const { filterSuppressedFindings } = await import(
          "@/lib/suppression-rules"
        );
        const orgId = orgSettings.orgId;
        if (orgId) {
          const result = await filterSuppressedFindings(findings, orgId, projectId);
          keptFindings = result.kept;
          suppressedFindings = result.suppressed.map((s) => s.finding);
          if (suppressedFindings.length > 0) {
            log.info(
              { suppressed: suppressedFindings.length, kept: keptFindings.length },
              "Suppression rules applied",
            );
          }
        }
      } catch {
        // Suppression check failed — insert all findings as normal
      }

      // Deduplicate within batch by (scanner, ruleId, filePath, startLine, title)
      const beforeDedup = keptFindings.length;
      const seen = new Set<string>();
      keptFindings = keptFindings.filter((f) => {
        const key = `${f.scanner}::${f.ruleId}::${f.filePath}::${f.startLine}::${f.title}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
      if (beforeDedup > keptFindings.length) {
        log.info(
          { before: beforeDedup, after: keptFindings.length, removed: beforeDedup - keptFindings.length },
          "Deduplicated findings within batch",
        );
      }

      // Insert kept findings as OPEN
      if (keptFindings.length > 0) {
        await prisma.finding.createMany({
          data: keptFindings.map((finding) => {
            const f = enrichFindingWithReport(finding);
            return {
              scanId,
              scanner: f.scanner,
              severity: f.severity,
              title: f.title,
              description: f.description,
              filePath: f.filePath,
              startLine: f.startLine,
              endLine: f.endLine,
              snippet: f.snippet,
              ruleId: f.ruleId,
              cweId: f.cweId,
              cveId: f.cveId,
              confidence: f.confidence,
              metadata: f.metadata as object,
              masked: f.masked ?? false,
              riskScore: computeRiskScore({
                severity: f.severity,
                scanner: f.scanner,
                confidence: f.confidence,
                filePath: f.filePath,
                metadata: f.metadata as Record<string, unknown>,
              }),
            };
          }),
        });
      }

      // Insert suppressed findings pre-marked as FALSE_POSITIVE
      if (suppressedFindings.length > 0) {
        await prisma.finding.createMany({
          data: suppressedFindings.map((finding) => {
            const f = enrichFindingWithReport(finding);
            return {
              scanId,
              scanner: f.scanner,
              severity: f.severity,
              title: f.title,
              description: f.description,
              filePath: f.filePath,
              startLine: f.startLine,
              endLine: f.endLine,
              snippet: f.snippet,
              ruleId: f.ruleId,
              cweId: f.cweId,
              cveId: f.cveId,
              confidence: f.confidence,
              metadata: f.metadata as object,
              masked: f.masked ?? false,
              riskScore: computeRiskScore({
                severity: f.severity,
                scanner: f.scanner,
                confidence: f.confidence,
                filePath: f.filePath,
                metadata: f.metadata as Record<string, unknown>,
              }),
              status: "FALSE_POSITIVE",
              statusNote: "Auto-suppressed by learned rule",
            };
          }),
        });
      }

      // Only count kept findings toward severity totals
      const counts = countSeverities(keptFindings);
      await prisma.scan.update({
        where: { id: scanId },
        data: {
          criticalCount: { increment: counts.CRITICAL },
          highCount: { increment: counts.HIGH },
          mediumCount: { increment: counts.MEDIUM },
          lowCount: { increment: counts.LOW },
          infoCount: { increment: counts.INFO },
        },
      });
    }

    // Track cumulative batch finding counts per scanner for progress
    const batchFindingCounts: Record<string, number> = {};
    // Full model reasoning trace per AI scanner, aggregated into one artifact
    // at finalize; reasoningTails holds a rolling tail per scanner for the live
    // scannerProgress view during the scan.
    const reasoningByScanner: Record<string, string> = {};
    const reasoningTails: Record<string, string> = {};

    // 3. Build scan context with incremental DB insert callbacks
    async function reportProgress(msg: string) {
      await assertScanActive();
      log.info(msg);
      void job.updateProgress({ message: msg }).catch(() => undefined);

      // Parse LLM file progress and update scannerProgress JSON
      // Format: "LLM SAST: 5/120 files scanned (3 findings)"
      const fileProgressMatch = msg.match(
        /LLM SAST: (\d+)\/(\d+) files scanned \((\d+) findings\)/,
      );
      if (fileProgressMatch) {
        const [, filesCompleted, filesTotal, findingsCount] =
          fileProgressMatch;
        await prisma.$executeRaw`
          UPDATE "Scan"
          SET "scannerProgress" = COALESCE("scannerProgress", '{}'::jsonb) || ${JSON.stringify(
            {
              SAST_LLM: {
                status: "RUNNING",
                findingsCount: parseInt(findingsCount),
                filesCompleted: parseInt(filesCompleted),
                filesTotal: parseInt(filesTotal),
              },
            },
          )}::jsonb
          WHERE id = ${scanId}
        `;
      }

      // Live reasoning stream: the shared reasoning sink emits "[<scanner>
      // reasoning] <chunk>" messages. Keep a rolling tail per scanner under a
      // dedicated __reasoning__ key so developers watch the model think during
      // the scan without clobbering each scanner's status entry.
      const reasoningMatch = msg.match(/^\[(\S+) reasoning\] ([\s\S]*)$/);
      if (reasoningMatch) {
        const [, scanner, chunk] = reasoningMatch;
        // Keep a short rolling window — a compact "what it's thinking now"
        // ticker, not a full transcript (the whole trace goes to the report).
        reasoningTails[scanner] = ((reasoningTails[scanner] || "") + chunk).slice(
          -1500,
        );
        // Display copy: when the tail is truncated, start it at a clean word
        // boundary (with a leading ellipsis) so it never begins mid-word.
        const display: Record<string, string> = {};
        for (const [s, t] of Object.entries(reasoningTails)) {
          const cut = t.length >= 1500 ? t.search(/\s/) : -1;
          display[s] = cut > 0 ? "… " + t.slice(cut).replace(/^\s+/, "") : t;
        }
        await prisma.$executeRaw`
          UPDATE "Scan"
          SET "scannerProgress" = COALESCE("scannerProgress", '{}'::jsonb) || ${JSON.stringify(
            { __reasoning__: display },
          )}::jsonb
          WHERE id = ${scanId}
        `;
      }
    }

    // 2b. Compiled-code scan: decompile JAR/WAR/EAR/class, APK/AAB/DEX and
    // .NET assemblies so the source scanners review them too. Never fails
    // the scan: a problem here only means compiled code goes unscanned.
    const compiledConfig = compiledScanConfig();
    if (uploadedArtifact) {
      // The upload limit already bounds an uploaded artifact: one the API
      // accepted is decompiled even when it is over the per-artifact limit
      // (which still applies to artifacts found in repositories and archives).
      compiledConfig.maxArtifactBytes = Math.max(compiledConfig.maxArtifactBytes, maxUploadBytes());
    }
    // Agent "deep scan" owns a configured binary upload end to end: it
    // decompiles and inspects inside the E2B sandbox, so the local decompile +
    // rule-based scanners are skipped for it. Only when the agent will actually
    // run — it is registered under LLM SAST (enableLlmSast + a SAST scan type),
    // so tie the skip to that; otherwise the binary falls back to the normal
    // compiled-scan pipeline, and so it does when the agent is not configured.
    const agentScanBinary =
      !!uploadedArtifact && isAgentArtifact(uploadedArtifact);
    const agentSastScan =
      scanIncludesModule(scanType, scanModules, "SAST") &&
      orgSettings.enableLlmSast === true;
    const agentScanOnly = agentOwnsUpload({
      uploadedArtifact,
      scanType,
      scanModules,
      enableLlmSast: orgSettings.enableLlmSast,
      // Org LLM Config OpenRouter key wins; env is the fallback.
      configured: isAgentScanConfigured(orgSettings),
    });
    if (agentScanOnly) {
      log.info({ artifact: uploadedArtifact }, "Agent deep scan owns this binary upload; skipping local decompile");
      await setDecompileProgress(scanId, {
        status: "DONE",
        findingsCount: 0,
        decompiled: 0,
        filesAdded: 0,
        skipped: [
          {
            path: uploadedArtifact!,
            reason: "disabled",
            detail: "handled by the agent deep scan (decompiled inside the sandbox)",
          },
        ],
      });
      await setAgentScanProgress(scanId, {
        status: "RUNNING",
        note: "starting the E2B sandbox",
      });
    } else if (
      compiledConfig.enabled &&
      COMPILED_SCAN_TYPES.has(scanType) &&
      // Decompiled source only feeds SAST and secrets.
      (scanIncludesModule(scanType, scanModules, "SAST") ||
        scanIncludesModule(scanType, scanModules, "SECRETS"))
    ) {
      let decompileStarted = false;
      try {
        const outcome = await runCompiledScan({
          workDir,
          fileList,
          scanType,
          config: compiledConfig,
          signal: abortController.signal,
          log,
          onProgress: (msg) => {
            void reportProgress(msg).catch(() => undefined);
          },
          onStart: () => {
            decompileStarted = true;
            return setDecompileProgress(scanId, { status: "RUNNING", findingsCount: 0 });
          },
        });
        decompiledFiles = outcome.files;
        decompiledPaths = outcome.pathMap;
        const s = outcome.summary;
        if (decompileStarted || s.skipped.length > 0) {
          log.info(
            { decompiled: s.decompiled, files: s.filesAdded, skipped: s.skippedByReason, failed: s.failed },
            describeOutcome(s),
          );
          // The scan's record of what was decompiled and what was skipped (and why).
          await setDecompileProgress(scanId, { status: "DONE", findingsCount: 0, ...s });
        }
      } catch (err) {
        if (abortController.signal.aborted) throw err;
        log.warn({ err }, "Compiled-code scan failed; continuing with source only");
      }
      await assertScanActive();
    } else if (uploadedArtifact && mobilePlatformOf(uploadedArtifact) !== "ios") {
      // The upload is nothing but a compiled artifact, and nothing will look inside it.
      // (An iOS app has no FOSS decompiler; the in-process .ipa dispatch handles it.)
      log.warn({ artifact: uploadedArtifact }, "Compiled-code scanning is off; the uploaded artifact is not decompiled");
      await setDecompileProgress(scanId, {
        status: "DONE",
        findingsCount: 0,
        decompiled: 0,
        filesAdded: 0,
        skipped: [
          {
            path: uploadedArtifact,
            reason: "disabled",
            detail: compiledConfig.enabled
              ? `${scanType} scans do not include compiled code`
              : "compiled-code scanning is turned off (ENABLE_COMPILED_SCAN=false)",
          },
        ],
      });
    }

    // A binary upload that the agent would have owned (LLM SAST on), but the
    // agent is ENABLED yet misconfigured for this org (missing E2B or OpenRouter
    // key): it fell back to the normal pipeline above. Surface exactly which key
    // is missing so a silent misconfiguration becomes visible. (When the feature
    // is simply off, the reason is null and we stay quiet.)
    if (agentScanBinary && agentSastScan && !agentScanOnly) {
      const reason = agentScanUnavailableReason(orgSettings);
      if (reason) {
        await setAgentScanProgress(scanId, {
          status: "DONE",
          outcome: "skipped",
          note: reason,
        });
      }
    }

    const ctx: ScanContext = {
      workDir,
      fileList,
      scaFileList,
      decompiledFileList: decompiledFiles,
      scanType,
      scanModules,
      scanId,
      uploadedArtifact: uploadedArtifact ?? undefined,
      orgSettings,
      signal: abortController.signal,
      waitIfPaused: assertScanActive,
      // Scanners call this without awaiting it, so it must never reject: an
      // unhandled rejection takes down the whole worker and every scan on it.
      // A cancelled or stopped scan aborts `signal` here; the next awaited
      // check in the scan ends it.
      onProgress: (msg) => {
        void reportProgress(msg).catch((err) => {
          if (err instanceof ScanCancelledError || err instanceof ScanStoppedError) return;
          log.warn({ err }, "Could not record scan progress");
        });
      },
      onScannerComplete: async (
        scannerName: string,
        findings: RawFinding[],
      ) => {
        await assertScanActive();
        log.info(
          { scanner: scannerName, findings: findings.length },
          "Scanner completed — inserting findings",
        );
        await insertFindings(findings);

        // Mark scanner as DONE in progress JSON
        const totalFindings =
          (batchFindingCounts[scannerName] || 0) + findings.length;
        await prisma.$executeRaw`
          UPDATE "Scan"
          SET "scannerProgress" = COALESCE("scannerProgress", '{}'::jsonb) || ${JSON.stringify({ [scannerName]: { status: "DONE", findingsCount: totalFindings } })}::jsonb
          WHERE id = ${scanId}
        `;
      },
      onReasoning: async (scannerName: string, reasoning: string) => {
        if (!reasoning?.trim()) return;
        // Aggregate every AI scanner's trace into one AI_REASONING artifact
        // (ScanArtifact is unique per [scanId, type]). Best-effort: a storage
        // failure must never fail the scan.
        try {
          reasoningByScanner[scannerName] = reasoning;
          const combined = Object.entries(reasoningByScanner)
            .map(([name, text]) => `# ${name}\n\n${text}`)
            .join("\n\n---\n\n");
          const key = `scans/${scanId}/ai-reasoning.md`;
          await uploadObject(key, combined, "text/markdown");
          await prisma.scanArtifact.upsert({
            where: { scanId_type: { scanId, type: "AI_REASONING" } },
            create: {
              scanId,
              type: "AI_REASONING",
              objectKey: key,
              size: Buffer.byteLength(combined),
            },
            update: { objectKey: key, size: Buffer.byteLength(combined) },
          });
          log.info(
            { scanner: scannerName, bytes: Buffer.byteLength(reasoning) },
            "Stored AI reasoning trace",
          );
        } catch (err) {
          log.warn({ err }, "Could not store AI reasoning trace");
        }
      },
      onAgentStatus: async (entry) => {
        // Persist the agent deep scan's visible status (running + sandbox id,
        // completed/incomplete/failed) so it survives the ephemeral sandbox and
        // shows on the scan page. Best-effort: never fail the scan over it.
        try {
          await setAgentScanProgress(scanId, entry);
          // A deep scan that FAILED mid-run (e.g. the model/OpenRouter refused)
          // must not read as a clean pass. Promote it to the scan's "Incomplete
          // scan" note — the same vehicle an AI-provider refusal uses — so it
          // shows the amber banner on the scan page and flows into PR/MCP
          // summaries. Scoped to the agent path (only on outcome "failed");
          // never flips the scan status or the quality gate.
          if (entry.status === "DONE" && entry.outcome === "failed") {
            const reason =
              typeof entry.note === "string" && entry.note.trim()
                ? entry.note.trim()
                : "the agentic reviewer could not complete";
            const note = `Agent deep scan failed: ${reason}`;
            const existing = await prisma.scan.findUnique({
              where: { id: scanId },
              select: { errorMessage: true },
            });
            const prev = existing?.errorMessage?.trim();
            const combined = (prev ? `${prev}\n\n${note}` : note).slice(0, 2000);
            await prisma.scan.update({
              where: { id: scanId },
              data: { errorMessage: combined },
            });
          }
        } catch (err) {
          log.warn({ err }, "Could not record agent deep scan status");
        }
      },
      onBatchFindings: async (scannerName: string, findings: RawFinding[]) => {
        await assertScanActive();
        log.info(
          { scanner: scannerName, findings: findings.length },
          "Batch findings — inserting intermediate results",
        );
        await insertFindings(findings);

        // Update scanner progress with running count
        batchFindingCounts[scannerName] =
          (batchFindingCounts[scannerName] || 0) + findings.length;
        await prisma.$executeRaw`
          UPDATE "Scan"
          SET "scannerProgress" = COALESCE("scannerProgress", '{}'::jsonb) || ${JSON.stringify({ [scannerName]: { status: "RUNNING", findingsCount: batchFindingCounts[scannerName] } })}::jsonb
          WHERE id = ${scanId}
        `;
      },
      onFindingsReplaced: async (replacements) => {
        await assertScanActive();
        log.info(
          { replacementsCount: replacements.length },
          "Replacing superseded findings with higher-quality findings",
        );
        for (const { superseded, replacement } of replacements) {
          try {
            await prisma.finding.deleteMany({
              where: {
                scanId,
                scanner: superseded.scanner,
                // Stored under its artifact path when it is in decompiled code.
                filePath: decompiledPaths.mapFinding(superseded).filePath,
                // Coerce to null, not undefined: Prisma DROPS an `undefined`
                // filter, so for artifact-level findings with no line (agent
                // iOS/binary review) `startLine: undefined` would match — and
                // delete — EVERY finding sharing the filePath. Match on title too
                // so siblings on the same artifact path aren't collaterally wiped.
                startLine: superseded.startLine ?? null,
                title: superseded.title,
              },
            });
          } catch (err) {
            log.warn({ err }, "Failed to delete superseded finding");
          }
          await insertFindings([replacement]);
        }
      },
    };

    // 4. Before the AI passes: is the configured model actually accepting
    // requests? A refused request (no credit, bad key, unknown model) would
    // otherwise look like "the AI found nothing".
    const aiEnabled = orgSettings.enableLlmSast || orgSettings.enableLlmSecrets;
    if (aiEnabled && (orgSettings.llmApiKey?.trim() || orgSettings.llmProvider === "ollama")) {
      const { checkLlmAvailable, aiUnavailableNote } = await import("@/lib/llm-preflight");
      const preflight = await checkLlmAvailable({
        provider: orgSettings.llmProvider,
        baseUrl: orgSettings.llmBaseUrl,
        apiKey: orgSettings.llmApiKey,
        model: orgSettings.llmModel,
      });
      if (!preflight.ok) {
        const note = aiUnavailableNote(orgSettings.llmProvider, orgSettings.llmModel, preflight.reason);
        log.error({ status: preflight.status, reason: preflight.reason }, "AI provider refused requests; AI analysis will not run");
        await prisma.scan.update({ where: { id: scanId }, data: { errorMessage: note } });
      }
    }

    // 5. Run scanners (findings are inserted incrementally via onScannerComplete)
    const result = await runScanners(ctx);
    await assertScanActive();
    log.info(
      { findings: result.findings.length, deps: result.depsScanned },
      "Scan complete",
    );

    // The agent deep scan (scanners/mobile-agent) is the sole reviewer for a
    // configured binary upload; it runs inside runScanners and reports its
    // findings and status through the normal pipeline, so there is no separate
    // post-scan mobile-review step here.

    // 5. Generate SBOMs (CycloneDX + SPDX) from parsed dependencies
    if (result.dependencies.length > 0) {
      try {
        const project = await prisma.project.findUnique({
          where: { id: projectId },
          select: { name: true },
        });
        const scanMeta = await prisma.scan.findUnique({
          where: { id: scanId },
          select: { commitSha: true, branch: true },
        });
        const sbomMeta = {
          projectName: project?.name || "unknown",
          projectVersion: scanMeta?.commitSha || undefined,
          scanId,
          commitSha: scanMeta?.commitSha || undefined,
          branch: scanMeta?.branch || undefined,
        };
        const cyclone = generateCycloneDx(result.dependencies, sbomMeta);
        const spdx = generateSpdx(result.dependencies, sbomMeta);
        const cycloneKey = `sboms/${scanId}/cyclonedx.json`;
        const spdxKey = `sboms/${scanId}/spdx.json`;
        await uploadObject(cycloneKey, cyclone, "application/vnd.cyclonedx+json");
        await uploadObject(spdxKey, spdx, "application/spdx+json");
        await prisma.scanArtifact.upsert({
          where: { scanId_type: { scanId, type: "SBOM_CYCLONEDX" } },
          create: {
            scanId,
            type: "SBOM_CYCLONEDX",
            objectKey: cycloneKey,
            size: Buffer.byteLength(cyclone),
          },
          update: {
            objectKey: cycloneKey,
            size: Buffer.byteLength(cyclone),
          },
        });
        await prisma.scanArtifact.upsert({
          where: { scanId_type: { scanId, type: "SBOM_SPDX" } },
          create: {
            scanId,
            type: "SBOM_SPDX",
            objectKey: spdxKey,
            size: Buffer.byteLength(spdx),
          },
          update: {
            objectKey: spdxKey,
            size: Buffer.byteLength(spdx),
          },
        });
        log.info(
          { deps: result.dependencies.length },
          "SBOMs generated (CycloneDX + SPDX)",
        );

        // VEX: state whether the vulnerabilities in the SBOM's components
        // actually affect this product. Built from the stored findings and their
        // adjudicated statuses, so suppressions and accepted risks are asserted
        // in a form a consumer can verify rather than being invisible.
        const vexFindings = await prisma.finding.findMany({
          where: {
            scanId,
            OR: [{ cveId: { not: null } }, { scanner: "SCA" }],
          },
          select: {
            cveId: true,
            ruleId: true,
            title: true,
            severity: true,
            status: true,
            statusNote: true,
            statusUpdatedAt: true,
            metadata: true,
          },
        });

        const vexMeta = {
          productName: sbomMeta.projectName,
          productId: `pkg:generic/${encodeURIComponent(sbomMeta.projectName)}@${sbomMeta.commitSha || "0.0.0"}`,
          scanId,
          commitSha: sbomMeta.commitSha,
          branch: sbomMeta.branch,
        };

        // Identify components exactly as the SBOM does, otherwise the statements
        // cannot be matched to the bill of materials.
        const vexPurl = (name: string, version: string, ecosystem: string) =>
          purlFor({ name, version, ecosystem });

        // CVEs triage ruled out never became findings, so they are asserted from
        // the scan result. A stored finding wins over an automated suppression
        // for the same vulnerability.
        const vexStatements = mergeVexStatements(
          buildVexStatements(vexFindings, { purlFor: vexPurl }),
          buildSuppressedVexStatements(result.suppressed, { purlFor: vexPurl }),
        );

        let openVex: string | undefined;
        let cycloneVex: string | undefined;

        if (vexStatements.length > 0) {
          openVex = generateOpenVex(vexStatements, vexMeta);
          cycloneVex = generateCycloneDxVex(vexStatements, vexMeta);
          const openVexKey = `vex/${scanId}/openvex.json`;
          const cycloneVexKey = `vex/${scanId}/cyclonedx-vex.json`;

          await uploadObject(openVexKey, openVex, "application/json");
          await uploadObject(
            cycloneVexKey,
            cycloneVex,
            "application/vnd.cyclonedx+json",
          );

          for (const [type, key, body] of [
            ["VEX_OPENVEX", openVexKey, openVex],
            ["VEX_CYCLONEDX", cycloneVexKey, cycloneVex],
          ] as const) {
            await prisma.scanArtifact.upsert({
              where: { scanId_type: { scanId, type } },
              create: {
                scanId,
                type,
                objectKey: key,
                size: Buffer.byteLength(body),
              },
              update: { objectKey: key, size: Buffer.byteLength(body) },
            });
          }

          log.info(
            { statements: vexStatements.length, ...summarizeVex(vexStatements) },
            "VEX generated (OpenVEX + CycloneDX)",
          );
        }

        // Sign SBOMs if code signing is enabled for this org
        try {
          const signingSettings = await prisma.orgSettings.findUnique({
            where: { organizationId: orgSettings.orgId || "" },
            select: {
              codeSigningEnabled: true,
              codeSigningMode: true,
              codeSigningKeyEnc: true,
              codeSigningIdentity: true,
            },
          });
          if (signingSettings?.codeSigningEnabled) {
            const bundles: Record<string, SignatureBundle> = {};
            // VEX is signed alongside the SBOMs: an unsigned exploitability
            // claim is not evidence, since anything asserting "not affected"
            // has to be attributable.
            const signable: Array<[string, string]> = [
              ["cyclonedx", cyclone],
              ["spdx", spdx],
              ...(openVex ? ([["openvex", openVex]] as Array<[string, string]>) : []),
              ...(cycloneVex
                ? ([["cyclonedx-vex", cycloneVex]] as Array<[string, string]>)
                : []),
            ];
            for (const [label, body] of signable) {
              let bundle: SignatureBundle | null = null;
              if (
                signingSettings.codeSigningMode === "keyless" ||
                !signingSettings.codeSigningKeyEnc
              ) {
                bundle = await signWithCosignKeyless(
                  digestOf(body),
                  signingSettings.codeSigningIdentity || undefined,
                );
              }
              if (!bundle && signingSettings.codeSigningKeyEnc) {
                try {
                  const pem = decryptSecret(signingSettings.codeSigningKeyEnc);
                  bundle = signWithRsaKey(
                    body,
                    pem,
                    undefined,
                    signingSettings.codeSigningIdentity || undefined,
                  );
                } catch {
                  /* fall through */
                }
              }
              if (bundle) bundles[label] = bundle;
            }
            if (Object.keys(bundles).length > 0) {
              const sigKey = `signatures/${scanId}/signatures.json`;
              const sigJson = JSON.stringify(bundles, null, 2);
              await uploadObject(sigKey, sigJson, "application/json");
              await prisma.scanArtifact.upsert({
                where: { scanId_type: { scanId, type: "SIGNATURE" } },
                create: {
                  scanId,
                  type: "SIGNATURE",
                  objectKey: sigKey,
                  size: Buffer.byteLength(sigJson),
                },
                update: {
                  objectKey: sigKey,
                  size: Buffer.byteLength(sigJson),
                },
              });
              log.info(
                { artifacts: Object.keys(bundles) },
                "Artifacts signed",
              );
            }
          }
        } catch (signErr) {
          log.warn({ signErr }, "Code signing failed (non-blocking)");
        }
      } catch (sbomErr) {
        log.warn({ sbomErr }, "SBOM generation failed (non-blocking)");
      }
    }

    // 5b. Adversarial exploit-validation pass (opt-in, default off).
    // Red-teams AI findings (SAST_LLM + ZERO_DAY) to confirm exploitability,
    // drop clear false positives, and attach concrete attack paths. Runs before
    // the gate so counts reflect the validated set. Never throws to the caller.
    await runExploitValidation(scanId, orgSettings, workDir, log);

    // 5c. Auto FP verification — re-check findings with the LLM and mark likely
    // false positives. Runs BEFORE the gate and before the scan is marked
    // COMPLETED so the gate result, PR status, notifications and history all
    // reflect the final counts (it recounts severities when it marks any).
    await assertScanActive();
    try {
      const { autoVerifyFalsePositives } = await import(
        "@/lib/auto-fp-verify"
      );
      const fpResult = await autoVerifyFalsePositives(scanId, orgSettings, log);
      if (fpResult.marked > 0) {
        log.info(
          { marked: fpResult.marked, total: fpResult.analyzed },
          "Auto FP verification marked findings as false positives",
        );
      }
    } catch (fpErr) {
      log.warn({ fpErr }, "Auto FP verification failed (non-blocking)");
    }

    // 6. Evaluate build gate (read current counts from DB since they were set incrementally)
    let gateResult: "PASSED" | "FAILED" = "PASSED";
    if (buildGate) {
      const currentScan = await prisma.scan.findUniqueOrThrow({
        where: { id: scanId },
        select: {
          criticalCount: true,
          highCount: true,
          mediumCount: true,
          lowCount: true,
        },
      });
      const hasNewFindings = buildGate.failOnNew
        ? await scanHasNewFindings(scanId)
        : false;
      gateResult = evaluateBuildGate(buildGate, currentScan, hasNewFindings);
    }

    // 9. Update scan record (severity counts already incremented per-scanner)
    let completed = await markScanCompleted(scanId, {
      filesScanned: result.filesScanned,
      depsScanned: result.depsScanned,
      gateResult,
    });
    if (completed.count === 0) {
      await assertScanActive();
      completed = await markScanCompleted(scanId, {
        filesScanned: result.filesScanned,
          depsScanned: result.depsScanned,
        gateResult,
      });
      if (completed.count === 0) {
        abortController.abort();
        throw new ScanCancelledError();
      }
    }

    log.info({ gateResult }, "Scan completed successfully");

    // 9d. Generate AI finding details for all findings so the UI shows full
    // content immediately when a finding is opened, instead of generating on
    // demand. Fire-and-forget with a concurrency cap so the scan is marked
    // COMPLETED right away while details populate in the background.
    void generateFindingDetailsForScan(scanId, orgSettings, log);

    // Lines scanned is shown next to the file count; it lives in the
    // reserved __stats__ entry of scannerProgress.
    try {
      await setScanStats(scanId, { linesScanned: result.linesScanned });
    } catch (err) {
      log.warn({ err }, "Failed to record lines scanned (non-blocking)");
    }

    // 9b. Auto-resolve findings that were fixed (no longer appear in this scan)
    try {
      const { autoResolveFixedFindings } = await import(
        "@/lib/fix-verification"
      );
      await autoResolveFixedFindings(scanId, projectId, log);
    } catch (fixErr) {
      log.warn({ fixErr }, "Fix verification failed (non-blocking)");
    }

    // 9c. Record this scan in the repository's history (trends survive rescans)
    try {
      const { recordScanSnapshot } = await import("@/lib/scan-history");
      await recordScanSnapshot(scanId);
    } catch (histErr) {
      log.warn({ histErr }, "Scan history snapshot failed (non-blocking)");
    }

    try {
      const { notifyScanLifecycleFromWorker } = await import(
        "@/lib/scan-notifications"
      );
      await notifyScanLifecycleFromWorker(scanId, "SCAN_COMPLETED");
    } catch (notifyErr) {
      log.warn({ notifyErr }, "In-app notification failed (non-blocking)");
    }

    try {
      const { dispatchScanCompleteIntegrations } = await import(
        "@/lib/integrations/scan-dispatcher"
      );
      await dispatchScanCompleteIntegrations(scanId);
    } catch (intErr) {
      log.warn(
        { intErr },
        "Integration dispatch failed (Slack/Jira/SIEM) — non-blocking",
      );
    }

    try {
      const { postScanPrReview } = await import("@/lib/pr-bot");
      await postScanPrReview(scanId);
    } catch (prErr) {
      log.warn({ prErr }, "PR summary comment failed (non-blocking)");
    }

    // 10. Send email notification (non-blocking)
    try {
      if (job.data.sourceType !== "WEBHOOK") {
        const triggeredBy = job.data.scanId
          ? await prisma.scan.findUnique({
              where: { id: scanId },
              select: {
                triggeredBy: true,
                project: { select: { name: true, organizationId: true } },
              },
            })
          : null;

        if (
          triggeredBy?.triggeredBy &&
          triggeredBy.triggeredBy !== "scheduler"
        ) {
          const user = await prisma.user.findUnique({
            where: { id: triggeredBy.triggeredBy },
            select: { email: true, name: true },
          });

          if (user?.email && triggeredBy.project) {
            // Check notification preferences
            const member = await prisma.orgMember.findFirst({
              where: {
                userId: triggeredBy.triggeredBy,
                organizationId: triggeredBy.project.organizationId,
              },
              select: {
                emailOnScanComplete: true,
                emailOnGateFail: true,
                emailOnCritical: true,
              },
            });

            const shouldEmail =
              member?.emailOnScanComplete ||
              (member?.emailOnGateFail && gateResult === "FAILED") ||
              (member?.emailOnCritical &&
                ((await prisma.scan.findUnique({
                  where: { id: scanId },
                  select: { criticalCount: true },
                }))?.criticalCount ?? 0) > 0);

            if (shouldEmail) {
              const scanCounts = await prisma.scan.findUnique({
                where: { id: scanId },
                select: {
                  criticalCount: true,
                  highCount: true,
                  mediumCount: true,
                  lowCount: true,
                  startedAt: true,
                  completedAt: true,
                },
              });

              const durationSecs =
                scanCounts?.startedAt && scanCounts?.completedAt
                  ? Math.floor(
                      (scanCounts.completedAt.getTime() -
                        scanCounts.startedAt.getTime()) /
                        1000,
                    )
                  : undefined;

              await sendScanCompleteEmail(triggeredBy.project.organizationId, {
                to: user.email,
                userName: user.name || undefined,
                projectName: triggeredBy.project.name,
                scanId,
                branch: job.data.branch,
                severityCounts: {
                  critical: scanCounts?.criticalCount || 0,
                  high: scanCounts?.highCount || 0,
                  medium: scanCounts?.mediumCount || 0,
                  low: scanCounts?.lowCount || 0,
                },
                gateResult,
                duration: durationSecs,
              });
            }
          }
        }
      }
    } catch (emailErr) {
      log.warn({ emailErr }, "Email notification failed (non-blocking)");
    }
  } catch (error) {
    if (error instanceof ScanCancelledError) {
      log.info("Scan cancelled");
      return;
    }
    if (error instanceof ScanStoppedError) {
      log.info("Scan stopped with partial findings preserved");
      return;
    }

    log.error({ error }, "Scan failed");
    await prisma.scan.updateMany({
      where: { id: scanId, status: { notIn: ["CANCELLED", "STOPPED"] } },
      data: {
        status: "FAILED",
        completedAt: new Date(),
        errorMessage: error instanceof Error ? error.message : "Unknown error",
      },
    });
    try {
      const { notifyScanLifecycleFromWorker } = await import(
        "@/lib/scan-notifications"
      );
      await notifyScanLifecycleFromWorker(scanId, "SCAN_FAILED");
    } catch {
      /* non-blocking */
    }
    try {
      const { postScanPrReview } = await import("@/lib/pr-bot");
      await postScanPrReview(scanId);
    } catch {
      /* non-blocking */
    }
    throw error;
  } finally {
    clearInterval(stopWatcher);
    // Cleanup
    try {
      fs.rmSync(workDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  }
}

const STOP_WATCH_INTERVAL_MS = 5000;

/** Scan types whose scanners (SAST, secrets) review decompiled compiled code. */
const COMPILED_SCAN_TYPES = new Set(["FULL", "SAST_ONLY", "SECRETS_ONLY", "INCREMENTAL"]);

/** The AGENT_SCAN entry of Scan.scannerProgress (running + sandbox id, then the deep scan's outcome on the scan page). */
async function setAgentScanProgress(scanId: string, entry: Record<string, unknown>): Promise<void> {
  await prisma.$executeRaw`
    UPDATE "Scan"
    SET "scannerProgress" = COALESCE("scannerProgress", '{}'::jsonb) || ${JSON.stringify({ AGENT_SCAN: entry })}::jsonb
    WHERE id = ${scanId}
  `;
}

/** The reserved __stats__ entry of Scan.scannerProgress (whole-scan statistics such as lines scanned). */
async function setScanStats(scanId: string, stats: { linesScanned: number }): Promise<void> {
  await prisma.$executeRaw`
    UPDATE "Scan"
    SET "scannerProgress" = COALESCE("scannerProgress", '{}'::jsonb) || ${JSON.stringify({ [SCAN_STATS_KEY]: stats })}::jsonb
    WHERE id = ${scanId}
  `;
}

/** The DECOMPILE entry of Scan.scannerProgress (progress badge, then the decompile summary). */
async function setDecompileProgress(scanId: string, entry: Record<string, unknown>): Promise<void> {
  await prisma.$executeRaw`
    UPDATE "Scan"
    SET "scannerProgress" = COALESCE("scannerProgress", '{}'::jsonb) || ${JSON.stringify({ DECOMPILE: entry })}::jsonb
    WHERE id = ${scanId}
  `;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function markScanCompleted(
  scanId: string,
  data: {
    filesScanned: number;
    depsScanned: number;
    gateResult: "PASSED" | "FAILED";
  },
) {
  return prisma.scan.updateMany({
    where: { id: scanId, status: "RUNNING" },
    data: {
      status: "COMPLETED",
      completedAt: new Date(),
      filesScanned: data.filesScanned,
      depsScanned: data.depsScanned,
      gateResult: data.gateResult,
    },
  });
}

function enumerateFiles(dir: string, prefix = ""): string[] {
  const SKIP = new Set([
    "node_modules",
    ".git",
    ".svn",
    "vendor",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".tox",
    "venv",
    ".venv",
    ".next",
    "coverage",
    ".nyc_output",
    ".cache",
  ]);

  const files: string[] = [];

  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (SKIP.has(entry.name)) continue;
        files.push(
          ...enumerateFiles(
            path.join(dir, entry.name),
            path.join(prefix, entry.name),
          ),
        );
      } else if (entry.isFile()) {
        files.push(path.join(prefix, entry.name));
      }
    }
  } catch {
    // skip unreadable directories
  }

  return files;
}

function countSeverities(findings: RawFinding[]) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) {
    counts[f.severity]++;
  }
  return counts;
}

const SEVERITY_RANK: Record<string, number> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

/**
 * Opt-in adversarial exploit-validation pass over AI findings.
 *
 * Gated by ENABLE_EXPLOIT_VALIDATION (default off) and the org's LLM SAST
 * config. Reads OPEN SAST_LLM/ZERO_DAY findings at or above
 * EXPLOIT_VALIDATION_MIN_SEVERITY, red-teams each for real exploitability, then:
 *   - marks clear false positives FALSE_POSITIVE (not deleted — audit trail),
 *   - annotates survivors with validated confidence + attack path,
 *   - recomputes severity counts so the build gate sees the validated set.
 *
 * Every failure path leaves findings untouched: this pass only ever *removes*
 * false positives the model is confident about, and never deletes a finding on
 * a model error. It must never throw to the caller.
 */
async function runExploitValidation(
  scanId: string,
  orgSettings: ScanJobData["orgSettings"],
  workDir: string,
  log: ReturnType<typeof createScanLogger>,
): Promise<void> {
  if (BENCHMARK_MODE) return; // benchmark: never suppress findings as false positives
  if (!ENABLE_EXPLOIT_VALIDATION) return;
  if (!orgSettings.enableLlmSast) return;
  const isOllama = orgSettings.llmProvider?.toLowerCase() === "ollama";
  if (!orgSettings.llmApiKey?.trim() && !isOllama) return;

  try {
    const minRank = SEVERITY_RANK[EXPLOIT_VALIDATION_MIN_SEVERITY.toUpperCase()] ?? 3;
    const severities = Object.keys(SEVERITY_RANK).filter(
      (s) => SEVERITY_RANK[s] >= minRank,
    );

    const candidates = await prisma.finding.findMany({
      where: {
        scanId,
        scanner: { in: ["SAST_LLM", "ZERO_DAY"] },
        severity: { in: severities as never },
        status: "OPEN",
      },
      select: {
        id: true,
        scanner: true,
        severity: true,
        title: true,
        description: true,
        filePath: true,
        startLine: true,
        endLine: true,
        snippet: true,
        cweId: true,
        confidence: true,
        metadata: true,
      },
    });
    if (candidates.length === 0) return;

    log.info(
      { candidates: candidates.length },
      "Exploit validation — red-teaming AI findings",
    );

    const outcome = await validateExploitability(
      candidates.map((c) => ({
        ...c,
        // Code context for a finding in decompiled code is read from the decompiled file.
        filePath: decompiledOriginOf(c.metadata)?.decompiledPath ?? c.filePath,
        scanner: String(c.scanner),
        severity: String(c.severity),
      })),
      {
        provider: orgSettings.llmProvider,
        baseUrl: orgSettings.llmBaseUrl,
        apiKey: orgSettings.llmApiKey,
        model: orgSettings.llmModel,
      },
      { workDir },
    );

    // Drop clear false positives — mark, do not delete, so the decision is auditable.
    if (outcome.drop.length > 0) {
      await prisma.finding.updateMany({
        where: { id: { in: outcome.drop.map((d) => d.id) } },
        data: {
          status: "FALSE_POSITIVE",
          statusNote: "Suppressed by exploit-validation — no reachable attack path",
          statusUpdatedAt: new Date(),
        },
      });
    }

    // Annotate survivors with validated confidence + attack path.
    for (const k of outcome.keep) {
      const orig = candidates.find((c) => c.id === k.id);
      if (!orig) continue;
      const meta =
        orig.metadata && typeof orig.metadata === "object"
          ? (orig.metadata as Record<string, unknown>)
          : {};
      await prisma.finding.update({
        where: { id: k.id },
        data: {
          confidence: k.confidence,
          metadata: {
            ...meta,
            exploitValidated: k.confirmed,
            ...(k.attackPath ? { attackPath: k.attackPath } : {}),
            ...(k.reason ? { exploitValidationReason: k.reason } : {}),
          },
        },
      });
    }

    // Recompute severity counts from OPEN findings so the gate reads the
    // post-validation totals (incremental counts were set before drops).
    const grouped = await prisma.finding.groupBy({
      by: ["severity"],
      where: { scanId, status: "OPEN" },
      _count: { _all: true },
    });
    const counts: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };
    for (const g of grouped) counts[String(g.severity)] = g._count._all;
    await prisma.scan.update({
      where: { id: scanId },
      data: {
        criticalCount: counts.CRITICAL,
        highCount: counts.HIGH,
        mediumCount: counts.MEDIUM,
        lowCount: counts.LOW,
        infoCount: counts.INFO,
      },
    });

    log.info(
      {
        dropped: outcome.drop.length,
        kept: outcome.keep.length,
        confirmed: outcome.keep.filter((k) => k.confirmed).length,
      },
      "Exploit validation complete",
    );
  } catch (err) {
    log.warn({ err }, "Exploit validation failed — findings left untouched");
  }
}

/**
 * Generate AI details (`metadata.generatedDetails`) for every OPEN finding in
 * the scan that lacks them, so the UI renders complete content immediately
 * when a finding is opened instead of calling the LLM on demand.
 *
 * Runs fire-and-forget from the scan-completion path with a concurrency cap to
 * avoid overwhelming the LLM provider. A finding that fails here is simply left
 * without generated details; the frontend falls back to on-demand generation.
 */
async function generateFindingDetailsForScan(
  scanId: string,
  orgSettings: ScanJobData["orgSettings"],
  log: ReturnType<typeof createScanLogger>,
): Promise<void> {
  const llmApiKey = orgSettings.llmApiKey?.trim();
  if (!llmApiKey && orgSettings.llmProvider !== "ollama") return;

  const config = {
    provider: orgSettings.llmProvider ?? "openai",
    baseUrl: orgSettings.llmBaseUrl ?? "",
    apiKey: llmApiKey ?? "",
    model: orgSettings.llmModel ?? "gpt-4o-mini",
  };

  const findings = await prisma.finding.findMany({
    where: { scanId, status: "OPEN" },
    select: {
      id: true,
      title: true,
      cweId: true,
      severity: true,
      filePath: true,
      startLine: true,
      endLine: true,
      description: true,
      metadata: true,
    },
    take: 2000,
  });

  const pending = findings.filter((f) => {
    const meta =
      f.metadata && typeof f.metadata === "object" && !Array.isArray(f.metadata)
        ? (f.metadata as Record<string, unknown>)
        : {};
    return !meta?.generatedDetails;
  });

  if (pending.length === 0) return;

  log.info(
    { pending: pending.length, total: findings.length },
    "Generating AI details for findings at scan completion",
  );

  const CONCURRENCY = 5;
  const queue = [...pending];
  let completed = 0;

  async function worker(): Promise<void> {
    while (queue.length > 0) {
      const f = queue.shift();
      if (!f) return;
      try {
        const details = await generateFindingDetails(
          {
            id: f.id,
            title: f.title,
            cweId: f.cweId,
            severity: f.severity,
            filePath: f.filePath,
            startLine: f.startLine,
            endLine: f.endLine,
            description: f.description,
          },
          config,
        );
        if (details) {
          const meta =
            f.metadata && typeof f.metadata === "object" && !Array.isArray(f.metadata)
              ? (f.metadata as Record<string, unknown>)
              : {};
          await prisma.finding.update({
            where: { id: f.id },
            data: {
              metadata: {
                ...meta,
                generatedDetails: details,
              } as object,
            },
          });
        }
      } catch (err) {
        log.warn({ err, findingId: f.id }, "Failed to generate finding details");
      } finally {
        completed += 1;
        if (completed % 25 === 0) {
          log.info({ completed, total: pending.length }, "Finding details generation progress");
        }
      }
    }
  }

  const workers: Promise<void>[] = [];
  for (let i = 0; i < Math.min(CONCURRENCY, pending.length); i++) {
    workers.push(worker());
  }
  await Promise.all(workers);

  log.info({ generated: completed, total: pending.length }, "Finding details generation complete");
}

/**
 * Build-gate "fail on new findings": does this scan contain findings that
 * were not in the repository's history baseline (see lib/scan-delta)?
 * False when there is no baseline yet, so a first scan never fails on "new".
 */
async function scanHasNewFindings(scanId: string): Promise<boolean> {
  const { computeScanDelta } = await import("@/lib/scan-delta");
  const delta = await computeScanDelta(scanId);
  return (delta?.newFindingIds.length ?? 0) > 0;
}
