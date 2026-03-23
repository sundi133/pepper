import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { Job } from "bullmq";
import { prisma } from "@/lib/prisma";
import { ScanJobData } from "@/lib/queue";
import { downloadObject, uploadObject } from "@/lib/minio";
import { runScanners } from "@/scanners";
import { buildSarif } from "@/scanners/sarif-builder";
import { generateSbom } from "@/scanners/sca/sbom-generator";
import { ScanContext, RawFinding } from "@/scanners/types";
import { parseDependencies } from "@/scanners/sca";
import { createScanLogger } from "@/lib/logger";
import { sendScanCompleteEmail } from "@/lib/email";

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

  // Update scan status to RUNNING with initial scanner progress
  await prisma.scan.update({
    where: { id: scanId },
    data: {
      status: "RUNNING",
      startedAt: new Date(),
      jobId: job.id,
      scannerProgress: {},
    },
  });

  const workDir = path.join(os.tmpdir(), `pepper-${scanId}`);

  try {
    // 1. Download and extract source
    fs.mkdirSync(workDir, { recursive: true });

    if (sourceType === "UPLOAD") {
      const data = await downloadObject(sourceRef);
      const archiveExt =
        sourceRef.match(/\.(zip|tar\.gz|tgz|tar)$/i)?.[0] || ".zip";
      const archivePath = path.join(workDir, `source${archiveExt}`);
      fs.writeFileSync(archivePath, data);
      await extractArchive(archivePath, workDir);
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

    // Helper: insert findings into DB and increment severity counts
    async function insertFindings(findings: RawFinding[]) {
      if (findings.length === 0) return;
      await prisma.finding.createMany({
        data: findings.map((f) => ({
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
      const counts = countSeverities(findings);
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
      orgSettings,
      signal: abortController.signal,
      onProgress: async (msg) => {
        log.info(msg);
        job.updateProgress({ message: msg });

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

    // 6. Generate and upload SARIF
    const sarif = buildSarif(result.findings);
    const sarifJson = JSON.stringify(sarif, null, 2);
    const sarifKey = `scans/${scanId}/results.sarif.json`;
    await uploadObject(sarifKey, sarifJson, "application/json");

    await prisma.scanArtifact.create({
      data: {
        scanId,
        type: "SARIF",
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

    await prisma.scanArtifact.create({
      data: {
        scanId,
        type: "SBOM_CYCLONEDX",
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

    // 9. Update scan record (severity counts already incremented per-scanner)
    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: "COMPLETED",
        completedAt: new Date(),
        filesScanned: result.filesScanned,
        depsScanned: result.depsScanned,
        gateResult,
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

            const shouldEmail =
              member?.emailOnScanComplete ||
              (member?.emailOnGateFail && gateResult === "FAILED") ||
              (member?.emailOnCritical &&
                (
                  await prisma.scan.findUnique({
                    where: { id: scanId },
                    select: { criticalCount: true },
                  })
                )?.criticalCount! > 0);

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
    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: "FAILED",
        completedAt: new Date(),
        errorMessage: error instanceof Error ? error.message : "Unknown error",
      },
    });
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
