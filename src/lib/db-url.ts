/**
 * Prefer IPv4 loopback — on Linux, `localhost` often resolves to ::1 while
 * Docker publishes DB/Redis/MinIO on 127.0.0.1 only.
 */
export function normalizeLocalhostToIPv4(url: string): string {
  try {
    const u = new URL(url);
    if (u.hostname === "localhost") {
      u.hostname = "127.0.0.1";
      return u.toString();
    }
  } catch {
    // keep original
  }
  return url;
}
