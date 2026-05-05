/**
 * Safely process an uploaded source archive for scanning.
 * The worker does not execute project build/test commands; this module documents
 * limits and re-exports helpers for API routes and tests.
 */
import { safeExtractZip, SafeExtractError } from "@/lib/safe-extract-zip";

export { safeExtractZip, SafeExtractError };

export const DEFAULT_UPLOAD_MAX_BYTES = 100 * 1024 * 1024;

export function getUploadMaxBytes(): number {
  return parseInt(
    process.env.UPLOAD_MAX_BYTES || String(DEFAULT_UPLOAD_MAX_BYTES),
    10,
  );
}

/** Verify buffer begins with ZIP local file header magic (PK). */
export function isZipMagic(buffer: Buffer): boolean {
  return buffer.length >= 2 && buffer[0] === 0x50 && buffer[1] === 0x4b;
}
