import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

const isWin = process.platform === "win32";

/** Exit status of a failed execFileSync, if it ran at all. */
function exitStatus(err: unknown): number | null {
  const status = (err as { status?: unknown } | null)?.status;
  return typeof status === "number" ? status : null;
}

/** Whether `destDir` holds anything besides the archive itself (it is often extracted next to it). */
function hasExtractedFiles(archivePath: string, destDir: string): boolean {
  const archive = path.resolve(archivePath);
  return fs.readdirSync(destDir).some((name) => path.resolve(destDir, name) !== archive);
}

/**
 * Info-ZIP unzip exits 1 for warnings after extracting everything it could:
 * a zip made by Windows PowerShell's Compress-Archive ("appears to use
 * backslashes as path separators"), entries whose unsafe "../" parts it
 * dropped, odd timestamps. That is a successful extraction when files came out.
 */
function unzipArchive(archivePath: string, destDir: string) {
  try {
    execFileSync("unzip", ["-o", "-q", archivePath, "-d", destDir], {
      timeout: 120_000,
      windowsHide: isWin,
      // No stdin: a password-protected zip fails instead of waiting for a password.
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    if (exitStatus(err) === 1 && hasExtractedFiles(archivePath, destDir)) return;
    throw err;
  }
}

/** One line of a tool's failure for the scan's error message. */
function describeFailure(err: unknown): string {
  const stderr = (err as { stderr?: Buffer | string } | null)?.stderr?.toString().trim();
  const text = stderr || (err instanceof Error ? err.message : String(err));
  const oneLine = text.replace(/\s+/g, " ").trim();
  return oneLine.length > 300 ? `${oneLine.slice(0, 300)}…` : oneLine;
}

function psEscapeLiteral(s: string): string {
  return `'${s.replace(/'/g, "''")}'`;
}

function extractZipWindowsPowerShell(archivePath: string, destDir: string) {
  const script = `Expand-Archive -LiteralPath ${psEscapeLiteral(archivePath)} -DestinationPath ${psEscapeLiteral(destDir)} -Force`;
  execFileSync(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", script],
    {
      timeout: 120_000,
      windowsHide: true,
    },
  );
}

/**
 * Extract .zip using tools commonly available on Linux, macOS, and Windows
 * (without requiring `unzip` on Windows).
 */
function extractZip(archivePath: string, destDir: string) {
  const attempts: Array<{ label: string; fn: () => void }> = [];

  if (isWin) {
    attempts.push({
      label: "tar",
      fn: () =>
        execFileSync("tar", ["-xf", archivePath, "-C", destDir], {
          timeout: 120_000,
          windowsHide: true,
        }),
    });
    attempts.push({
      label: "powershell Expand-Archive",
      fn: () => extractZipWindowsPowerShell(archivePath, destDir),
    });
  }

  attempts.push({
    label: "unzip",
    fn: () => unzipArchive(archivePath, destDir),
  });

  if (!isWin) {
    attempts.push({
      label: "tar",
      fn: () =>
        execFileSync("tar", ["-xf", archivePath, "-C", destDir], {
          timeout: 120_000,
        }),
    });
  }

  // Every tool's reason, not just the last one: on Linux the last is tar,
  // which cannot read ZIP files at all ("invalid tar magic").
  const failures: string[] = [];
  for (const { label, fn } of attempts) {
    try {
      fn();
      return;
    } catch (err) {
      failures.push(`${label}: ${describeFailure(err)}`);
    }
  }

  const tried = attempts.map((a) => a.label).join(", ");
  throw new Error(`Failed to extract ZIP (tried ${tried}): ${failures.join(" | ")}`);
}

function extractTar(
  archivePath: string,
  destDir: string,
  compression: "gzip" | "none",
) {
  const args =
    compression === "gzip"
      ? ["-xzf", archivePath, "-C", destDir]
      : ["-xf", archivePath, "-C", destDir];
  execFileSync("tar", args, {
    timeout: 120_000,
    windowsHide: isWin,
  });
}

/**
 * Extract uploaded scan archives into `destDir` (must exist).
 * Uses native `tar` where possible; ZIP on Windows falls back to PowerShell.
 */
export function extractArchive(archivePath: string, destDir: string): void {
  if (!fs.existsSync(destDir)) {
    throw new Error(`extractArchive: destination does not exist: ${destDir}`);
  }

  if (archivePath.endsWith(".zip")) {
    extractZip(archivePath, destDir);
  } else if (archivePath.endsWith(".tar.gz") || archivePath.endsWith(".tgz")) {
    extractTar(archivePath, destDir, "gzip");
  } else if (archivePath.endsWith(".tar")) {
    extractTar(archivePath, destDir, "none");
  } else {
    throw new Error(`Unsupported archive format: ${archivePath}`);
  }
}
