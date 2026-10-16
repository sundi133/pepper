/**
 * A single compiled artifact (app.apk, service.war, App.dll …) uploaded as a
 * scan's source. It is stored as `scans/<scanId>/compiled/<file name>` so the
 * worker can keep its name, which is what findings show (`app.apk!/…`).
 * Archives (.zip / .tar.gz) keep their `scans/<scanId>/source.<ext>` key.
 */

export const UPLOADABLE_ARTIFACT_EXTENSIONS = [".jar", ".war", ".ear", ".apk", ".aab", ".dll", ".exe"] as const;

/** MIME types browsers and CI clients send for these files. */
export const ARTIFACT_MIME_TYPES = new Set([
  "application/java-archive",
  "application/x-java-archive",
  "application/x-jar",
  "application/vnd.android.package-archive",
  "application/x-authorware-bin", // some browsers' guess for .aab
  "application/x-webarchive",
  "application/x-msdownload",
  "application/x-msdos-program",
  "application/x-ms-dos-executable",
  "application/x-dosexec",
  "application/vnd.microsoft.portable-executable",
  "application/octet-stream",
  "application/zip",
  "application/x-zip-compressed",
]);

export function isCompiledArtifactUpload(fileName: string): boolean {
  const lower = fileName.toLowerCase();
  return UPLOADABLE_ARTIFACT_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

/** File name safe to use as an object key segment and a file in the work dir. */
export function safeArtifactFileName(fileName: string): string {
  const base = fileName.replace(/.*[/\\]/, "");
  const dot = base.lastIndexOf(".");
  const ext = dot >= 0 ? base.slice(dot).toLowerCase() : "";
  const stem = (dot >= 0 ? base.slice(0, dot) : base).replace(/[^A-Za-z0-9._-]/g, "_").replace(/^[.]+/, "").slice(0, 100);
  return `${stem || "artifact"}${ext}`;
}

export function compiledUploadObjectKey(scanId: string, fileName: string): string {
  return `scans/${scanId}/compiled/${safeArtifactFileName(fileName)}`;
}

/** Object keys of uploaded compiled artifacts (for data retention). */
export const COMPILED_UPLOAD_KEY = /^scans\/[^/]+\/compiled\/[^/]+\.(?:jar|war|ear|apk|aab|dll|exe)$/i;

/** The artifact's file name when a scan's sourceRef is an uploaded compiled artifact. */
export function uploadedArtifactName(sourceRef: string | null | undefined): string | null {
  if (!sourceRef || !COMPILED_UPLOAD_KEY.test(sourceRef)) return null;
  const name = sourceRef.slice(sourceRef.lastIndexOf("/") + 1);
  return name && name === safeArtifactFileName(name) ? name : null;
}
