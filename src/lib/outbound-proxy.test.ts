import { describe, expect, it } from "vitest";
import { describeOutboundProxy, redactProxyUrl } from "./outbound-proxy";

describe("describeOutboundProxy", () => {
  it("reports nothing when no proxy is configured", () => {
    const r = describeOutboundProxy({ NODE_USE_ENV_PROXY: "1" }, "v22.23.3");
    expect(r).toMatchObject({ configured: false, active: false, warnings: [] });
  });

  it("is active with the flag on a supporting Node, reading upper- or lower-case vars", () => {
    const r = describeOutboundProxy(
      { https_proxy: "http://proxy.corp:3128", NO_PROXY: ",localhost,127.0.0.1,ado.corp", NODE_USE_ENV_PROXY: "1" },
      "v22.23.3",
    );
    expect(r.active).toBe(true);
    expect(r.httpsProxy).toBe("http://proxy.corp:3128");
    expect(r.noProxy).toEqual(["localhost", "127.0.0.1", "ado.corp"]);
    expect(r.warnings).toEqual([]);
  });

  it("warns when the proxy is set but Node will not use it", () => {
    const missingFlag = describeOutboundProxy({ HTTPS_PROXY: "http://p:1", NO_PROXY: "localhost" }, "v22.23.3");
    expect(missingFlag.active).toBe(false);
    expect(missingFlag.warnings[0]).toMatch(/NODE_USE_ENV_PROXY=1 is not/);

    const oldNode = describeOutboundProxy(
      { HTTPS_PROXY: "http://p:1", NO_PROXY: "localhost", NODE_USE_ENV_PROXY: "1" },
      "v22.12.0",
    );
    expect(oldNode.active).toBe(false);
    expect(oldNode.warnings[0]).toMatch(/ignores NODE_USE_ENV_PROXY/);

    expect(describeOutboundProxy({ HTTPS_PROXY: "http://p:1", NODE_USE_ENV_PROXY: "1" }, "v24.5.0").warnings[0]).toMatch(
      /does not include localhost/,
    );
  });
});

describe("redactProxyUrl", () => {
  it("never logs proxy credentials", () => {
    expect(redactProxyUrl("http://svc-user:S3cret!@proxy.corp:3128")).toBe("http://***@proxy.corp:3128");
    expect(redactProxyUrl("not a url")).toBe("(unparseable proxy URL)");
  });
});
