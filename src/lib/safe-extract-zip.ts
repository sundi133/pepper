import * as fs from "fs";
import * as path from "path";
import AdmZip from "adm-zip";

export interface SafeExtractZipOptions {
  maxFiles: number;
  maxTotalUncompressedBytes: number;
  maxSingleFileBytes: number;
  /** Merged with defaults; any path segment matching is skipped (not extracted). */
  blockedPathSegments?: Set<string>;
  /** Names of directory segments to skip (e.g. \`node_modules\`). Merged with defaults. */
  blockedDirectories?: string[];
  /** If set, only files whose basename extension is in this set are extracted (lowercase, include dot). */
  allowedExtensions?: Set<string>;
}

const DEFAULT_BLOCKED = new Set([
  "node_modules",
  ".git",
  "vendor",
  "dist",
  "build",
  "target",
  "coverage",
  ".next",
  ".svn",
  "__pycache__",
  ".cache",
  "venv",
  ".venv",
  ".nyc_output",
]);

export class SafeExtractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SafeExtractError";
  }
}

/**
 * Safely extract a ZIP to a directory: Zip Slip protection, file/count/total size caps.
 * Does not execute any file from the archive.
 */
export function safeExtractZip(
  zipPath: string,
  destinationDir: string,
  options: Partial<SafeExtractZipOptions> = {},
): { fileCount: number; totalBytes: number; filesWritten: string[] } {
  const maxFiles = options.maxFiles ?? 50_000;
  const maxTotalUncompressedBytes = options.maxTotalUncompressedBytes ?? 500 * 1024 * 1024;
  const maxSingleFileBytes = options.maxSingleFileBytes ?? 20 * 1024 * 1024;
  const blockedPathSegments = new Set(DEFAULT_BLOCKED);
  if (options.blockedPathSegments) {
    for (const s of options.blockedPathSegments) blockedPathSegments.add(s);
  }
  if (options.blockedDirectories) {
    for (const s of options.blockedDirectories) blockedPathSegments.add(s);
  }
  const allowedExtensions = options.allowedExtensions;

  if (!fs.existsSync(zipPath)) {
    throw new SafeExtractError("ZIP file not found");
  }

  fs.mkdirSync(destinationDir, { recursive: true });
  const destReal = fs.realpathSync(path.resolve(destinationDir));

  const buf = fs.readFileSync(zipPath);
  const zip = new AdmZip(buf);
  const entries = zip.getEntries();

  let fileCount = 0;
  let totalBytes = 0;
  const filesWritten: string[] = [];

  for (const entry of entries) {
    if (entry.isDirectory) continue;

    const rawName = entry.entryName.replace(/\\/g, "/").replace(/^\/+/, "");
    if (!rawName || rawName.includes("\0")) {
      throw new SafeExtractError("Invalid entry name in ZIP");
    }

    const segments = rawName.split("/").filter(Boolean);
    if (segments.some((s) => s === "..")) {
      throw new SafeExtractError("Path traversal sequence in ZIP entry");
    }
    if (segments.some((s) => blockedPathSegments.has(s))) {
      continue;
    }

    const baseName = segments[segments.length - 1] ?? "";
    if (allowedExtensions?.size) {
      const ext = path.extname(baseName).toLowerCase();
      if (!allowedExtensions.has(ext)) continue;
    }

    const absTarget = path.resolve(path.join(destReal, ...segments));
    const rel = path.relative(destReal, absTarget);
    if (rel.startsWith("..") || path.isAbsolute(rel)) {
      throw new SafeExtractError("Zip Slip: entry escapes destination directory");
    }

    // adm-zip EntryHeader exposes uncompressed size as `size` (bytes).
    const headerSize =
      typeof (entry.header as { size?: number }).size === "number"
        ? (entry.header as { size: number }).size
        : 0;
    if (headerSize > maxSingleFileBytes) {
      throw new SafeExtractError(
        `ZIP entry exceeds max single file size: ${rawName}`,
      );
    }

    if (totalBytes + headerSize > maxTotalUncompressedBytes) {
      throw new SafeExtractError("ZIP uncompressed total size limit exceeded");
    }

    fileCount += 1;
    if (fileCount > maxFiles) {
      throw new SafeExtractError("ZIP contains too many files");
    }

    const content = entry.getData();
    if (content.length > maxSingleFileBytes) {
      throw new SafeExtractError(
        `ZIP entry uncompressed size exceeds limit: ${rawName}`,
      );
    }

    totalBytes += content.length;

    fs.mkdirSync(path.dirname(absTarget), { recursive: true });
    fs.writeFileSync(absTarget, content);
    filesWritten.push(path.relative(destReal, absTarget).split(path.sep).join("/"));
  }

  return { fileCount, totalBytes, filesWritten };
}
