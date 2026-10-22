/**
 * iOS .ipa extraction. There is no FOSS decompiler for iOS the way jadx exists
 * for Android, so instead of source we extract the reviewable metadata the
 * mobile reviewer needs: Info.plist (ATS/URL schemes/permissions), entitlements
 * and provisioning, linked frameworks, and printable strings from the Mach-O
 * executable (URLs, endpoints, embedded secrets). Dependency-free: operates on
 * an already-unzipped .ipa tree (the worker unzips the archive upstream).
 */
import * as fs from "fs";
import * as path from "path";

const MAX_STRINGS = 8000;
const MAX_OUTPUT_BYTES = 512 * 1024;

/** Printable-ASCII runs of >= minLen bytes, deduped and capped. Works on a
 *  Mach-O binary or a binary plist (both carry readable key/value strings). */
export function extractAsciiStrings(buf: Buffer, minLen = 4): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  let cur = "";
  for (let i = 0; i < buf.length; i++) {
    const c = buf[i];
    if (c >= 0x20 && c < 0x7f) {
      cur += String.fromCharCode(c);
      continue;
    }
    if (cur.length >= minLen && !seen.has(cur)) {
      seen.add(cur);
      out.push(cur);
      if (out.length >= MAX_STRINGS) return out;
    }
    cur = "";
  }
  if (cur.length >= minLen && !seen.has(cur)) out.push(cur);
  return out;
}

/** Locate Payload/<App>.app inside an extracted .ipa root (recursively, shallow). */
export function findDotApp(root: string): string | null {
  const payload = path.join(root, "Payload");
  for (const dir of [payload, root]) {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    const app = entries.find((e) => e.isDirectory() && e.name.endsWith(".app"));
    if (app) return path.join(dir, app.name);
  }
  return null;
}

export interface IpaExtractResult {
  /** The .app bundle name, or null if none was found. */
  appName: string | null;
  /** Files written into outDir (relative paths). */
  written: string[];
}

function writeCapped(outDir: string, rel: string, body: string, written: string[]) {
  const text = body.length > MAX_OUTPUT_BYTES ? body.slice(0, MAX_OUTPUT_BYTES) + "\n… (truncated)\n" : body;
  fs.writeFileSync(path.join(outDir, rel), text);
  written.push(rel);
}

/**
 * Read an already-unzipped .ipa tree and write readable iOS metadata into
 * outDir for the mobile reviewer. Info.plist is written verbatim so the mobile
 * scanner's anchor detection picks up the scan as iOS.
 */
export function extractIpaMetadata(extractedRoot: string, outDir: string): IpaExtractResult {
  const app = findDotApp(extractedRoot);
  if (!app) return { appName: null, written: [] };
  fs.mkdirSync(outDir, { recursive: true });
  const written: string[] = [];
  const appName = path.basename(app);

  // Info.plist — copied verbatim (the scanner anchor) plus a strings view, since
  // it is usually a binary plist that the reviewer can't read directly.
  const infoPlist = path.join(app, "Info.plist");
  if (fs.existsSync(infoPlist)) {
    const buf = fs.readFileSync(infoPlist);
    fs.writeFileSync(path.join(outDir, "Info.plist"), buf);
    written.push("Info.plist");
    writeCapped(outDir, "Info.plist.strings.txt", extractAsciiStrings(buf, 3).join("\n"), written);
  }

  // Entitlements / provisioning — readable entitlement XML lives inside the CMS.
  const mobileprovision = path.join(app, "embedded.mobileprovision");
  if (fs.existsSync(mobileprovision)) {
    writeCapped(
      outDir,
      "embedded.mobileprovision.txt",
      extractAsciiStrings(fs.readFileSync(mobileprovision), 4).join("\n"),
      written,
    );
  }
  for (const f of safeReaddir(app)) {
    if (f.endsWith(".entitlements")) {
      try {
        writeCapped(outDir, f, fs.readFileSync(path.join(app, f), "utf8"), written);
      } catch {
        /* ignore */
      }
    }
  }

  // Linked frameworks / dylibs — an SBOM-ish inventory of third-party code.
  const fwDir = path.join(app, "Frameworks");
  const frameworks = safeReaddir(fwDir).filter((f) => f.endsWith(".framework") || f.endsWith(".dylib"));
  if (frameworks.length) {
    writeCapped(outDir, "frameworks.txt", frameworks.sort().join("\n"), written);
  }

  // Main Mach-O executable strings — URLs, endpoints, embedded secrets.
  const execName = guessExecutableName(app, appName);
  const execPath = execName ? path.join(app, execName) : null;
  if (execPath && fs.existsSync(execPath)) {
    writeCapped(
      outDir,
      "executable.strings.txt",
      extractAsciiStrings(fs.readFileSync(execPath), 5).join("\n"),
      written,
    );
  }

  return { appName, written };
}

function safeReaddir(dir: string): string[] {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
}

/** The executable is usually the .app name without the extension; fall back to
 *  the largest Mach-O-looking file at the bundle root. */
function guessExecutableName(app: string, appName: string): string | null {
  const base = appName.replace(/\.app$/, "");
  if (fs.existsSync(path.join(app, base))) return base;
  let best: { name: string; size: number } | null = null;
  for (const f of safeReaddir(app)) {
    const full = path.join(app, f);
    try {
      const st = fs.statSync(full);
      if (st.isFile() && path.extname(f) === "" && (!best || st.size > best.size)) {
        best = { name: f, size: st.size };
      }
    } catch {
      /* ignore */
    }
  }
  return best?.name ?? null;
}
