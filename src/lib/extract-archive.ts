import { execFileSync } from "child_process";
import * as fs from "fs";

const isWin = process.platform === "win32";

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
    fn: () =>
      execFileSync("unzip", ["-o", "-q", archivePath, "-d", destDir], {
        timeout: 120_000,
        windowsHide: isWin,
      }),
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

  let lastError: unknown;
  for (const { fn } of attempts) {
    try {
      fn();
      return;
    } catch (err) {
      lastError = err;
    }
  }

  const tried = attempts.map((a) => a.label).join(", ");
  const msg =
    lastError instanceof Error ? lastError.message : String(lastError);
  throw new Error(`Failed to extract ZIP (tried ${tried}): ${msg}`);
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
