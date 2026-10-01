import { describe, expect, it } from "vitest";
import { explainFetchError, isNetworkError } from "./network-error";

const fetchFailed = (cause: unknown) => Object.assign(new TypeError("fetch failed"), { cause });

describe("explainFetchError", () => {
  it("explains a refused connection, with the localhost trap spelled out", () => {
    // Node reports dual-stack localhost failures as an AggregateError.
    const err = fetchFailed(Object.assign(new AggregateError([{ code: "ECONNREFUSED" }, { code: "ECONNREFUSED" }]), { code: "ECONNREFUSED" }));
    expect(isNetworkError(err)).toBe(true);
    const msg = explainFetchError(err, "http://localhost:18080/DefaultCollection");
    expect(msg).toMatch(/Could not connect to localhost:18080: connection refused/);
    expect(msg).toMatch(/"localhost" is Pepper itself/);
    expect(explainFetchError(err, "https://tfs.corp.local")).toMatch(/tfs\.corp\.local: connection refused.*firewall, NO_PROXY/);
  });

  it("explains DNS, timeout and certificate failures", () => {
    expect(explainFetchError(fetchFailed({ code: "ENOTFOUND" }), "http://ado-server")).toMatch(/Could not find ado-server.*DNS/);
    expect(explainFetchError(fetchFailed({ code: "UND_ERR_CONNECT_TIMEOUT" }), "https://tfs.corp")).toMatch(/Timed out connecting to tfs\.corp/);
    expect(explainFetchError(fetchFailed({ code: "SELF_SIGNED_CERT_IN_CHAIN" }), "https://tfs.corp")).toMatch(/certificate Pepper doesn't trust.*NODE_EXTRA_CA_CERTS/);
    expect(explainFetchError(fetchFailed(undefined), "https://tfs.corp")).toMatch(/Could not reach tfs\.corp/);
  });

  it("leaves other errors alone", () => {
    expect(explainFetchError(new Error("Project \"x\" was not found"), "https://tfs.corp")).toBe('Project "x" was not found');
    expect(isNetworkError(new Error("boom"))).toBe(false);
  });
});
