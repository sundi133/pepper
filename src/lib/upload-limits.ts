/**
 * Largest scan upload (source archive or single compiled artifact).
 *
 *   MAX_UPLOAD_MB=500   default 500
 *
 * Read when the app is built: next.config.ts inlines it into the API and the
 * browser and sizes the middleware body buffer from it, so the form, the API
 * and the proxy always agree. Docker builds take it as a build argument. The
 * worker reads it at run time, to decompile an uploaded artifact up to this size.
 */

export const DEFAULT_MAX_UPLOAD_MB = 500;

const MB = 1024 * 1024;

/** MAX_UPLOAD_MB as a positive whole number of megabytes, else the default. */
export function maxUploadMb(raw: string | undefined = process.env.MAX_UPLOAD_MB): number {
  const n = Math.floor(Number(raw?.trim()));
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_MAX_UPLOAD_MB;
}

export function maxUploadBytes(raw?: string): number {
  return maxUploadMb(raw) * MB;
}

/** Middleware body buffer: the upload plus room for the multipart envelope and form fields. */
export function proxyBodySizeLimit(raw?: string): `${number}mb` {
  const mb = maxUploadMb(raw);
  return `${mb + Math.max(50, Math.ceil(mb / 10))}mb`;
}
