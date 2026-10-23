import { describe, it, expect } from "vitest";
import { isAgentArtifact, agentOwnsUpload } from "./artifact";

describe("isAgentArtifact", () => {
  it.each(["app.apk", "App.AAB", "MyApp.ipa", "classes.dex", "service.jar", "a.war", "b.ear", "lib.dll", "tool.exe"])(
    "accepts binary artifact %s",
    (name) => expect(isAgentArtifact(name)).toBe(true),
  );

  it.each(["project.zip", "src.tar.gz", "code.tar", "README.md", "Main.java", "a.ts", "", undefined, null])(
    "rejects non-binary / source %s",
    (name) => expect(isAgentArtifact(name as string | null | undefined)).toBe(false),
  );
});

describe("agentOwnsUpload", () => {
  const base = { scanType: "FULL", enableLlmSast: true, configured: true };

  it("owns a configured binary upload on a SAST scan", () => {
    expect(agentOwnsUpload({ ...base, uploadedArtifact: "app.apk" })).toBe(true);
    expect(agentOwnsUpload({ ...base, uploadedArtifact: "service.jar" })).toBe(true);
  });

  it("does NOT own a source-archive or repo scan (no uploaded binary)", () => {
    // source archives yield no uploadedArtifact (uploadedArtifactName → null)
    expect(agentOwnsUpload({ ...base, uploadedArtifact: null })).toBe(false);
    expect(agentOwnsUpload({ ...base, uploadedArtifact: undefined })).toBe(false);
    // and even a .zip name is not an agent artifact
    expect(agentOwnsUpload({ ...base, uploadedArtifact: "project.zip" })).toBe(false);
  });

  it("does NOT own when unconfigured — binary falls back to the normal pipeline", () => {
    expect(agentOwnsUpload({ ...base, uploadedArtifact: "app.apk", configured: false })).toBe(false);
  });

  it("does NOT own when LLM SAST is off or the scan type has no SAST", () => {
    expect(agentOwnsUpload({ ...base, uploadedArtifact: "app.apk", enableLlmSast: false })).toBe(false);
    expect(agentOwnsUpload({ ...base, uploadedArtifact: "app.apk", scanType: "SECRETS_ONLY" })).toBe(false);
    expect(agentOwnsUpload({ ...base, uploadedArtifact: "app.apk", scanType: "SCA_ONLY" })).toBe(false);
  });
});
