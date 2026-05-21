import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { Job } from "bullmq";
import { prisma } from "@/lib/prisma";
import { ScanJobData } from "@/lib/queue";
import { downloadObject } from "@/lib/minio";
import { runScanners } from "@/scanners";
import { ScanContext, RawFinding } from "@/scanners/types";
import { createScanLogger } from "@/lib/logger";
import { sendScanCompleteEmail } from "@/lib/email";
import { extractArchive } from "@/lib/extract-archive";
import { enrichFindingWithReport } from "@/lib/finding-report";
import { uploadObject } from "@/lib/minio";
import {
  generateCycloneDx,
  generateSpdx,
} from "@/scanners/sca/sbom-generator";
import {
  signWithCosignKeyless,
  signWithRsaKey,
  digestOf,
  type SignatureBundle,
} from "@/lib/code-signing";
import { decryptSecret } from "@/lib/token-encryption";

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
  const log = createScanLogger(scanId);
  const abortController = new AbortController();

  log.info({ scanId, scanType, sourceType }, "Starting scan");

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

  try {
    // 1. Download and extract source
    fs.mkdirSync(workDir, { recursive: true });
    await assertScanActive();

    if (sourceType === "UPLOAD") {
      const data = await downloadObject(sourceRef);
      const archiveExt =
        sourceRef.match(/\.(zip|tar\.gz|tgz|tar)$/i)?.[0] || ".zip";
      const archivePath = path.join(workDir, `source${archiveExt}`);
      fs.writeFileSync(archivePath, data);
      await extractArchive(archivePath, workDir);
      fs.unlinkSync(archivePath);
    } else if (sourceType === "GIT_CLONE") {
      const { execFileSync } = await import("child_process");
      const { withGitCredentials } = await import("@/lib/git-repo-url");
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
      const cloneArgs = ["clone", "--depth", "1"];
      if (branch) cloneArgs.push("--branch", branch);
      cloneArgs.push(repoUrl, path.join(workDir, "repo"));
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
          throw error;
        }

        log.warn(
          { branch, repoUrl: repoLog },
          "Git branch was not found; retrying clone with repository default branch",
        );
        execFileSync(
          "git",
          ["clone", "--depth", "1", repoUrl, path.join(workDir, "repo")],
          {
            timeout: 120000,
            windowsHide: process.platform === "win32",
          },
        );
      }
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

    // 2. Enumerate files
    const fileList = enumerateFiles(workDir);
    log.info({ fileCount: fileList.length }, "Files enumerated");

    // Helper: insert findings into DB and increment severity counts
    async function insertFindings(findings: RawFinding[]) {
      if (findings.length === 0) return;
      await assertScanActive();
      await prisma.finding.createMany({
        data: findings.map((finding) => {
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
          };
        }),
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
      scanId,
      orgSettings: {
        ...orgSettings,
        dastTargetUrl: job.data.dastTargetUrl || orgSettings.dastTargetUrl,
      },
      signal: abortController.signal,
      waitIfPaused: assertScanActive,
      onProgress: async (msg) => {
        await assertScanActive();
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
    };

    // 4. Run scanners (findings are inserted incrementally via onScannerComplete)
    const result = await runScanners(ctx);
    await assertScanActive();
    log.info(
      { findings: result.findings.length, deps: result.depsScanned },
      "Scan complete",
    );

    // Persist DAST report bundle if the scanner wrote one into the workDir.
    try {
      const dastReportPath = path.join(workDir, "deliverables", "dast-report.json");
      if (fs.existsSync(dastReportPath)) {
        const dastReport = fs.readFileSync(dastReportPath, "utf8");
        const dastKey = `dast-reports/${scanId}/dast-report.json`;
        await uploadObject(dastKey, dastReport, "application/json");
        await prisma.scanArtifact.upsert({
          where: { scanId_type: { scanId, type: "DAST_REPORT" } },
          create: {
            scanId,
            type: "DAST_REPORT",
            objectKey: dastKey,
            size: Buffer.byteLength(dastReport),
          },
          update: {
            objectKey: dastKey,
            size: Buffer.byteLength(dastReport),
          },
        });
        log.info({ dastKey }, "DAST report bundle uploaded");
      }
    } catch (dastReportErr) {
      log.warn({ dastReportErr }, "DAST report upload failed (non-blocking)");
    }

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
            for (const [label, body] of [
              ["cyclonedx", cyclone],
              ["spdx", spdx],
            ] as const) {
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
          createdAt: true,
        },
      });
      const hasNewFindings = buildGate.failOnNew
        ? await scanHasNewFindings(scanId, projectId, currentScan.createdAt)
        : false;
      if (
        hasNewFindings ||
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
    // Cleanup
    try {
      fs.rmSync(workDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  }
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

async function scanHasNewFindings(
  scanId: string,
  projectId: string,
  createdAt: Date,
): Promise<boolean> {
  const previousScan = await prisma.scan.findFirst({
    where: {
      projectId,
      status: "COMPLETED",
      id: { not: scanId },
      createdAt: { lt: createdAt },
    },
    orderBy: { createdAt: "desc" },
    select: {
      findings: {
        select: {
          scanner: true,
          ruleId: true,
          cweId: true,
          cveId: true,
          filePath: true,
          startLine: true,
          title: true,
        },
      },
    },
  });

  if (!previousScan) {
    return false;
  }

  const previousKeys = new Set(previousScan.findings.map(findingFingerprint));
  const currentFindings = await prisma.finding.findMany({
    where: { scanId, status: { not: "FALSE_POSITIVE" } },
    select: {
      scanner: true,
      ruleId: true,
      cweId: true,
      cveId: true,
      filePath: true,
      startLine: true,
      title: true,
    },
  });

  return currentFindings.some(
    (finding) => !previousKeys.has(findingFingerprint(finding)),
  );
}

function findingFingerprint(finding: {
  scanner: string;
  ruleId: string | null;
  cweId: string | null;
  cveId: string | null;
  filePath: string | null;
  startLine: number | null;
  title: string;
}): string {
  return [
    finding.scanner,
    finding.ruleId || finding.cveId || finding.cweId || normalizeFindingTitle(finding.title),
    finding.filePath || "",
    finding.startLine ? Math.floor(finding.startLine / 5) : 0,
  ].join(":");
}

function normalizeFindingTitle(title: string): string {
  return title.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}
