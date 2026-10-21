import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { execFileSync } = vi.hoisted(() => ({ execFileSync: vi.fn() }));
vi.mock("child_process", () => ({ execFileSync }));

import { extractArchive } from "./extract-archive";

function failure(status: number, stderr: string): Error {
  return Object.assign(new Error(`Command failed (exit ${status})`), { status, stderr: Buffer.from(stderr) });
}

describe.skipIf(process.platform === "win32")("extractArchive unzip exit codes", () => {
  let workDir: string;
  let archivePath: string;
  beforeEach(() => {
    vi.clearAllMocks();
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-zip-codes-"));
    archivePath = path.join(workDir, "source.zip");
    fs.writeFileSync(archivePath, "PK");
  });
  afterEach(() => {
    fs.rmSync(workDir, { recursive: true, force: true });
  });

  it("treats a warning (exit 1) as success when files were extracted", () => {
    execFileSync.mockImplementationOnce(() => {
      fs.writeFileSync(path.join(workDir, "app.py"), "x");
      throw failure(1, "warning: source.zip appears to use backslashes as path separators");
    });
    expect(() => extractArchive(archivePath, workDir)).not.toThrow();
    expect(execFileSync).toHaveBeenCalledTimes(1);
  });

  it("does not count the archive itself as extracted output", () => {
    execFileSync
      .mockImplementationOnce(() => {
        throw failure(1, "warning: skipped everything");
      })
      .mockImplementationOnce(() => {
        throw failure(1, "tar: invalid tar magic");
      });
    expect(() => extractArchive(archivePath, workDir)).toThrow(
      "Failed to extract ZIP (tried unzip, tar): unzip: warning: skipped everything | tar: tar: invalid tar magic",
    );
  });

  it("reports every tool's reason when all fail", () => {
    execFileSync
      .mockImplementationOnce(() => {
        throw failure(9, "End-of-central-directory signature not found.");
      })
      .mockImplementationOnce(() => {
        throw failure(1, "tar: invalid tar magic");
      });
    expect(() => extractArchive(archivePath, workDir)).toThrow(
      /unzip: End-of-central-directory signature not found\. \| tar: tar: invalid tar magic/,
    );
  });

  it("runs unzip without stdin so a password prompt cannot hang the scan", () => {
    execFileSync.mockImplementationOnce(() => undefined);
    extractArchive(archivePath, workDir);
    expect(execFileSync).toHaveBeenCalledWith(
      "unzip",
      ["-o", "-q", archivePath, "-d", workDir],
      expect.objectContaining({ stdio: ["ignore", "pipe", "pipe"] }),
    );
  });
});
