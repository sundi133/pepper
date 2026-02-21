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
      const archivePath = path.join(workDir, "source.zip");
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
        const fileProgressMatch = msg.match(/LLM SAST: (\d+)\/(\d+) files scanned \((\d+) findings\)/);
        if (fileProgressMatch) {
          const [, filesCompleted, filesTotal, findingsCount] = fileProgressMatch;
          await prisma.$executeRaw`
            UPDATE "Scan"
            SET "scannerProgress" = COALESCE("scannerProgress", '{}'::jsonb) || ${JSON.stringify({
              SAST_LLM: {
                status: "RUNNING",
                findingsCount: parseInt(findingsCount),
                filesCompleted: parseInt(filesCompleted),
                filesTotal: parseInt(filesTotal),
              }
            })}::jsonb
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
