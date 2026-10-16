/**
 * Whether a finding's path is test, fixture, example or demo code. Quality
 * gates drop low-confidence findings there and severity calibration lowers
 * them one level.
 *
 * Two kinds of path look like that but are production code:
 * - inside a compiled artifact (`app.jar!/com/example/Login.java`) the path is
 *   a Java/.NET package name, not a folder someone named "example";
 * - Maven/Gradle production sources (`src/main/java/com/example/…`), where
 *   `com.example` is a very common real package name.
 */
const TEST_LIKE =
  /(?:^|\/)(?:test|tests|spec|specs|__tests__|fixtures?|mocks?|examples?|demo|sample)(?:\/|$)|\.(?:test|spec)\.[jt]sx?$/i;

export function isTestLikePath(filePath: string | null | undefined): boolean {
  if (!filePath) return false;
  const p = filePath.replace(/\\/g, "/");
  if (p.includes("!/")) return false;
  if (/(?:^|\/)src\/main\//.test(p)) return false;
  return TEST_LIKE.test(p);
}
