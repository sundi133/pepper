import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { Job } from "bullmq";
import { prisma } from "@/lib/prisma";
import { ScanJobData } from "@/lib/queue";
import { downloadObject, uploadObject } from "@/lib/minio";
import { runScanners } from "@/scanners";
import { buildSarif } from "@/scanners/sarif-builder";
import { buildHtmlFindingsReport } from "@/scanners/html-report-builder";
import { buildScanMarkdownReport } from "@/scanners/reports/scan-markdown-report-builder";
import { generateSbom } from "@/scanners/sca/sbom-generator";
import { ScanContext, RawFinding } from "@/scanners/types";
import { parseDependencies } from "@/scanners/sca";
import { createScanLogger } from "@/lib/logger";
import { sendScanCompleteEmail } from "@/lib/email";
import { enrichRawFindingsWithSource } from "@/lib/security-report";
import { analyzeArchitecture, architectureOverviewMarkdown } from "@/scanners/sast/architecture";
import { enrichFindingsWithSastEngine } from "@/scanners/sast/finding-enrichment";
import { appendScanLiveEvent } from "@/lib/scan-live-events";
import {
  safeExtractZip,
  SafeExtractError,
} from "@/lib/safe-extract-zip";
import type { ScanEvent } from "@/scanners/types";

// prisma is imported from @/lib/prisma

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
  const log = createScanLogger(scanId);
  const abortController = new AbortController();

  log.info({ scanId, scanType, sourceType }, "Starting scan");

  // The user may delete/cancel scans while a queued job is still pending.
  // In that case, exit cleanly instead of retrying a stale job.
  const started = await prisma.scan.updateMany({
    where: { id: scanId, status: { not: "CANCELLED" } },
    data: {
      status: "RUNNING",
      startedAt: new Date(),
      jobId: job.id,
      scannerProgress: {},
    },
  });
  if (started.count === 0) {
    log.warn({ scanId }, "Scan no longer exists or was cancelled; skipping job");
    return;
  }

  const workDir = path.join(os.tmpdir(), `pepper-${scanId}`);

  const ts = () => new Date().toISOString();
  const emitEvent = async (e: ScanEvent) => {
    await appendScanLiveEvent(scanId, e);
    try {
      await job.updateProgress({ message: e.type, event: e });
    } catch {
      // Job handle may be unavailable during teardown.
    }
  };

  try {
    // 1. Download and extract source
    fs.mkdirSync(workDir, { recursive: true });

    await emitEvent({
      type: "scan_started",
      scanId,
      timestamp: ts(),
      totalFiles: 0,
    });

    let extractedUncompressedBytes = 0;

    if (sourceType === "UPLOAD") {
      const data = await downloadObject(sourceRef);
      const maxUpload = parseInt(
        process.env.UPLOAD_MAX_BYTES || String(100 * 1024 * 1024),
        10,
      );
      if (data.length > maxUpload) {
        throw new Error(`Upload exceeds maximum size (${maxUpload} bytes)`);
      }

      const archiveExt =
        sourceRef.match(/\.(zip|tar\.gz|tgz|tar)$/i)?.[0] || ".zip";
      const archivePath = path.join(workDir, `source${archiveExt}`);

      if (archiveExt.toLowerCase() === ".zip") {
        const magic = data.subarray(0, Math.min(4, data.length));
        if (magic.length < 2 || magic[0] !== 0x50 || magic[1] !== 0x4b) {
          throw new Error("File is not a valid ZIP archive");
        }
      }

      fs.writeFileSync(archivePath, data);

      if (archivePath.toLowerCase().endsWith(".zip")) {
        await emitEvent({
          type: "extract_started",
          scanId,
          timestamp: ts(),
        });
        try {
          const out = safeExtractZip(archivePath, workDir, {
            maxFiles: parseInt(process.env.SAFE_ZIP_MAX_FILES || "50000", 10),
            maxTotalUncompressedBytes: parseInt(
              process.env.SAFE_ZIP_MAX_UNCOMPRESSED_BYTES ||
                String(500 * 1024 * 1024),
              10,
            ),
            maxSingleFileBytes: parseInt(
              process.env.SAFE_ZIP_MAX_FILE_BYTES || String(20 * 1024 * 1024),
              10,
            ),
          });
          extractedUncompressedBytes = out.totalBytes;
        } catch (err) {
          if (err instanceof SafeExtractError) {
            throw new Error(err.message);
          }
          throw err;
        }
      } else {
        await emitEvent({
          type: "extract_started",
          scanId,
          timestamp: ts(),
        });
        await extractArchive(archivePath, workDir);
        extractedUncompressedBytes = 0;
      }
      fs.unlinkSync(archivePath);
    } else if (sourceType === "GIT_CLONE") {
      const { execSync } = await import("child_process");
      const repoUrl = job.data.repoUrl || sourceRef;
      const branch = job.data.branch || "main";
      execSync(
        `git clone --depth 1 --branch ${branch} ${repoUrl} ${workDir}/repo`,
        { timeout: 120000 },
      );
      // Move contents up
      const repoDir = path.join(workDir, "repo");
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
        execFileSync("svn", ["--version", "--quiet"], { timeout: 5000 });
      } catch {
        throw new Error(
          "SVN CLI not found. Install Subversion (e.g. `brew install subversion`) on the worker.",
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
        execFileSync("svn", exportArgs, { timeout: 300000 });
      } catch (svnErr) {
        const msg = svnErr instanceof Error ? svnErr.message : String(svnErr);
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

    // 2. Enumerate files
    const fileList = enumerateFiles(workDir);
    log.info({ fileCount: fileList.length }, "Files enumerated");

    await emitEvent({
      type: "extract_completed",
      scanId,
      timestamp: ts(),
      totalFiles: fileList.length,
      totalBytes: extractedUncompressedBytes,
    });

    const architecture = analyzeArchitecture(workDir, fileList);

    // Helper: insert findings into DB and increment severity counts
    async function insertFindings(findings: RawFinding[]) {
      if (findings.length === 0) return;
      const engineEnriched = enrichFindingsWithSastEngine(
        findings,
        workDir,
        architecture,
      );
      const enrichedFindings = await enrichRawFindingsWithSource(
        engineEnriched,
        workDir,
      );
      await prisma.finding.createMany({
        data: enrichedFindings.map((f) => ({
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
        })),
      });
      const counts = countSeverities(enrichedFindings);
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

    // 3. Build scan context with incremental DB insert callbacks
    const ctx: ScanContext = {
      workDir,
      fileList,
      scanType,
      scanId,
      orgSettings,
      signal: abortController.signal,
      onEvent: emitEvent,
      onProgress: async (msg) => {
        log.info(msg);
        job.updateProgress({ message: msg });

        // Parse LLM file progress and update scannerProgress JSON
        // Format: "LLM SAST: 5/120 files scanned (3 findings)"
        const fileProgressMatch = msg.match(
          /LLM SAST: (\d+)\/(\d+) files scanned \((\d+) findings\)/,
        );
        const priorityMatch = msg.match(
          /LLM SAST: prioritizing (\d+)\/(\d+) security-relevant files/,
        );
        await emitEvent({
          type: "scan_progress",
          scanId,
          message: msg,
          timestamp: ts(),
          scanner: msg.startsWith("LLM SAST")
            ? "SAST_LLM"
            : msg.startsWith("SAST Pattern")
              ? "SAST_PATTERN"
              : msg.startsWith("SCA")
                ? "SCA"
                : msg.startsWith("Supply Chain")
                  ? "MALICIOUS_PKG"
                  : msg.startsWith("Secrets")
                    ? "SECRETS_LLM"
                    : msg.startsWith("IaC")
                      ? "IAC"
                      : msg.startsWith("Zero-Day")
                        ? "ZERO_DAY"
                        : undefined,
          filesCompleted: fileProgressMatch
            ? parseInt(fileProgressMatch[1])
            : priorityMatch
              ? parseInt(priorityMatch[1])
              : undefined,
          filesTotal: fileProgressMatch
            ? parseInt(fileProgressMatch[2])
            : priorityMatch
              ? parseInt(priorityMatch[2])
              : undefined,
          findingsCount: fileProgressMatch
            ? parseInt(fileProgressMatch[3])
            : undefined,
        });
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
      },
      onScannerComplete: async (
        scannerName: string,
        findings: RawFinding[],
      ) => {
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
      onBatchFindings: async (scannerName: string, findings: RawFinding[]) => {
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
    };

    // 4. Run scanners (findings are inserted incrementally via onScannerComplete)
    const result = await runScanners(ctx);
    log.info(
      { findings: result.findings.length, deps: result.depsScanned },
      "Scan complete",
    );

    const stillExists = await prisma.scan.findUnique({
      where: { id: scanId },
      select: { id: true, status: true },
    });
    if (!stillExists || stillExists.status === "CANCELLED") {
      log.warn(
        { scanId, status: stillExists?.status },
        "Scan was deleted or cancelled before artifact generation; stopping job",
      );
      return;
    }

    // 6. Generate and upload SARIF (same enrichment as DB inserts)
    const findingsForArtifacts = enrichFindingsWithSastEngine(
      result.findings,
      workDir,
      architecture,
    );
    const sarif = buildSarif(findingsForArtifacts);
    const sarifJson = JSON.stringify(sarif, null, 2);
    const sarifKey = `scans/${scanId}/results.sarif.json`;
    await uploadObject(sarifKey, sarifJson, "application/json");

    await prisma.scanArtifact.upsert({
      where: {
        scanId_type: {
          scanId,
          type: "SARIF",
        },
      },
      create: {
        scanId,
        type: "SARIF",
        objectKey: sarifKey,
        size: Buffer.byteLength(sarifJson),
      },
      update: {
        objectKey: sarifKey,
        size: Buffer.byteLength(sarifJson),
      },
    });

    // 7. Generate and upload SBOM
    const project = await prisma.project.findUnique({
      where: { id: projectId },
    });
    const dependencies = parseDependencies(workDir, fileList).dependencies;
    const sbom = generateSbom(dependencies, project?.name || "unknown");
    const sbomJson = JSON.stringify(sbom, null, 2);
    const sbomKey = `scans/${scanId}/sbom.cyclonedx.json`;
    await uploadObject(sbomKey, sbomJson, "application/json");

    await prisma.scanArtifact.upsert({
      where: {
        scanId_type: {
          scanId,
          type: "SBOM_CYCLONEDX",
        },
      },
      create: {
        scanId,
        type: "SBOM_CYCLONEDX",
        objectKey: sbomKey,
        size: Buffer.byteLength(sbomJson),
      },
      update: {
        objectKey: sbomKey,
        size: Buffer.byteLength(sbomJson),
      },
    });

    // 8. Evaluate build gate (read current counts from DB since they were set incrementally)
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
      if (
        (buildGate.maxCritical >= 0 &&
          currentScan.criticalCount > buildGate.maxCritical) ||
        (buildGate.maxHigh >= 0 && currentScan.highCount > buildGate.maxHigh) ||
        (buildGate.maxMedium >= 0 &&
          currentScan.mediumCount > buildGate.maxMedium) ||
        (buildGate.maxLow >= 0 && currentScan.lowCount > buildGate.maxLow)
      ) {
        gateResult = "FAILED";
      }
    }

    const completedAt = new Date();
    const scanForReport = await prisma.scan.findUniqueOrThrow({
      where: { id: scanId },
      select: {
        id: true,
        scanType: true,
        branch: true,
        commitSha: true,
        sourceType: true,
        sourceRef: true,
        startedAt: true,
      },
    });
    const htmlReport = buildHtmlFindingsReport({
      scan: {
        ...scanForReport,
        completedAt,
        filesScanned: result.filesScanned,
        depsScanned: result.depsScanned,
        gateResult,
      },
      project: {
        name: project?.name || "unknown",
        repoUrl: project?.repoUrl,
      },
      findings: findingsForArtifacts,
    });
    const htmlReportKey = `scans/${scanId}/findings-report.html`;
    await uploadObject(
      htmlReportKey,
      htmlReport,
      "text/html; charset=utf-8",
    );
    await prisma.scanArtifact.upsert({
      where: {
        scanId_type: {
          scanId,
          type: "HTML_FINDINGS_REPORT",
        },
      },
      create: {
        scanId,
        type: "HTML_FINDINGS_REPORT",
        objectKey: htmlReportKey,
        size: Buffer.byteLength(htmlReport),
      },
      update: {
        objectKey: htmlReportKey,
        size: Buffer.byteLength(htmlReport),
      },
    });

    const markdownReport = buildScanMarkdownReport({
      scan: {
        ...scanForReport,
      },
      project: {
        name: project?.name || "unknown",
        repoUrl: project?.repoUrl,
      },
      findings: findingsForArtifacts,
    });
    const markdownReportKey = `scans/${scanId}/findings-report.md`;
    await uploadObject(
      markdownReportKey,
      markdownReport,
      "text/markdown; charset=utf-8",
    );
    await prisma.scanArtifact.upsert({
      where: {
        scanId_type: {
          scanId,
          type: "MARKDOWN_FINDINGS_REPORT",
        },
      },
      create: {
        scanId,
        type: "MARKDOWN_FINDINGS_REPORT",
        objectKey: markdownReportKey,
        size: Buffer.byteLength(markdownReport),
      },
      update: {
        objectKey: markdownReportKey,
        size: Buffer.byteLength(markdownReport),
      },
    });

    // 9. Update scan record (severity counts already incremented per-scanner)
    const findingTotal = await prisma.finding.count({ where: { scanId } });

    await emitEvent({
      type: "scan_completed",
      scanId,
      findingCount: findingTotal,
      timestamp: ts(),
    });

    const existingProgress = await prisma.scan.findUnique({
      where: { id: scanId },
      select: { scannerProgress: true },
    });
    const progressObj =
      existingProgress?.scannerProgress &&
      typeof existingProgress.scannerProgress === "object" &&
      !Array.isArray(existingProgress.scannerProgress)
        ? (existingProgress.scannerProgress as Record<string, unknown>)
        : {};

    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: "COMPLETED",
        completedAt,
        filesScanned: result.filesScanned,
        depsScanned: result.depsScanned,
        gateResult,
        scannerProgress: {
          ...markScannerProgressDone(progressObj),
          architectureOverview: architectureOverviewMarkdown(architecture),
          rulesVersion: "pepper-sast-engine@1.1",
        },
      },
    });

    log.info({ gateResult }, "Scan completed successfully");

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

            const criticalForEmail = member?.emailOnCritical
              ? await prisma.scan.findUnique({
                  where: { id: scanId },
                  select: { criticalCount: true },
                })
              : null;

            const shouldEmail =
              member?.emailOnScanComplete ||
              (member?.emailOnGateFail && gateResult === "FAILED") ||
              (member?.emailOnCritical &&
                (criticalForEmail?.criticalCount ?? 0) > 0);

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
    log.error({ error }, "Scan failed");
    const errMsg = error instanceof Error ? error.message : "Unknown error";
    try {
      await appendScanLiveEvent(scanId, {
        type: "scan_failed",
        scanId,
        error: errMsg,
        timestamp: new Date().toISOString(),
      });
    } catch {
      // non-fatal
    }
    const updated = await prisma.scan.updateMany({
      where: { id: scanId },
      data: {
        status: "FAILED",
        completedAt: new Date(),
        errorMessage: errMsg,
      },
    });
    if (updated.count === 0) {
      log.warn({ scanId }, "Scan failure ignored because scan was deleted");
      return;
    }
    throw error;
  } finally {
    // Cleanup
    try {
      fs.rmSync(workDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  }
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

function markScannerProgressDone(
  progress: Record<string, unknown>,
): Record<string, unknown> {
  const next: Record<string, unknown> = { ...progress };
  for (const [key, value] of Object.entries(progress)) {
    if (
      value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      "status" in value
    ) {
      next[key] = {
        ...(value as Record<string, unknown>),
        status: "DONE",
      };
    }
  }
  return next;
}

async function extractArchive(archivePath: string, destDir: string) {
  const { execSync } = await import("child_process");

  if (archivePath.endsWith(".zip")) {
    execSync(`unzip -o -q "${archivePath}" -d "${destDir}"`, {
      timeout: 60000,
    });
  } else if (archivePath.endsWith(".tar.gz") || archivePath.endsWith(".tgz")) {
    execSync(`tar -xzf "${archivePath}" -C "${destDir}"`, { timeout: 60000 });
  } else if (archivePath.endsWith(".tar")) {
    execSync(`tar -xf "${archivePath}" -C "${destDir}"`, { timeout: 60000 });
  }
}
