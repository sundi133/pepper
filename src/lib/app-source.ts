/**
 * Optional public URL for a “Source code” link (e.g. your GitHub repository).
 * Set `NEXT_PUBLIC_SOURCE_CODE_URL` in `.env` (e.g. `https://github.com/org/pepper`).
 */
export function getSourceCodeUrl(): string {
  return process.env.NEXT_PUBLIC_SOURCE_CODE_URL?.trim() || "";
}
