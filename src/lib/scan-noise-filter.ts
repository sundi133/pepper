/**
 * Built-in noise filter for code scans.
 *
 * Tests, fixtures, API collections, generated docs, examples and benchmarks
 * rarely hold exploitable production code, but in large repos they can be
 * most of the lines (e.g. hyperswitch: cypress-tests + postman ≈ 35%).
 * Sending them to the AI burns tokens and time and buries real findings.
 *
 * The worker drops these paths from the SAST / secrets / zero-day / IaC file
 * list. Dependency (SCA) scanning still sees every file.
 */

/** Any path segment equal to one of these marks the file as noise. */
const NOISE_DIRS = new Set([
  "test",
  "tests",
  "__tests__",
  "__test__",
  "__mocks__",
  "__snapshots__",
  "__fixtures__",
  "spec",
  "specs",
  "e2e",
  "integration-tests",
  "integration_tests",
  "fixtures",
  "fixture",
  "testdata",
  "test-data",
  "test_data",
  "mocks",
  "cypress",
  "playwright",
  "postman",
  "api-reference",
  "docs",
  "doc",
  "examples",
  "example",
  "samples",
  "benches",
  "benchmarks",
  "loadtest",
  "load-test",
  "storybook",
  ".storybook",
]);

/** Directory name prefixes treated as noise (cypress-tests, cypress-tests-v2, …). */
const NOISE_DIR_PREFIXES = ["cypress-", "test-", "tests-", "e2e-"];

/** File-name patterns treated as noise. */
const NOISE_FILE_RES = [
  /\.(test|spec|e2e|cy|stories|story|bench)\.[a-z0-9]+$/i,
  /_(test|tests|spec|bench)\.[a-z0-9]+$/i, // foo_test.go, foo_test.rs, foo_spec.rb
  /^test_.*\.py$/i,
  /\.min\.(js|css)$/i,
  /\.(map|snap)$/i,
  /\.postman_(collection|environment)\.json$/i,
  /(^|[._-])generated\.[a-z0-9]+$/i,
  /\.pb\.(go|ts|js)$/i,
  /_pb2(_grpc)?\.py$/i,
  /^CHANGELOG/i,
];

/** True when `filePath` (repo-relative) is test/fixture/doc/generated noise. */
export function isScanNoisePath(filePath: string): boolean {
  if (!filePath) return false;
  const parts = filePath.split(/[\\/]+/).filter(Boolean);
  const base = parts.pop() ?? "";
  for (const dir of parts) {
    const d = dir.toLowerCase();
    if (NOISE_DIRS.has(d)) return true;
    if (NOISE_DIR_PREFIXES.some((p) => d.startsWith(p))) return true;
  }
  return NOISE_FILE_RES.some((re) => re.test(base));
}

/** Split a file list into scannable code and dropped noise. */
export function filterScanNoise(files: string[]): { kept: string[]; dropped: number } {
  const kept = files.filter((f) => !isScanNoisePath(f));
  return { kept, dropped: files.length - kept.length };
}
