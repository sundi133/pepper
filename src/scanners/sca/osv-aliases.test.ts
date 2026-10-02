import { describe, expect, it } from "vitest";
import { cargoLockParser } from "./parsers/cargo-lock";
import { mergeAliasedVulns } from "./osv-client";

const CVSS = [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" }];

describe("mergeAliasedVulns", () => {
  it("reports one vulnerability once, whichever databases list it", () => {
    const merged = mergeAliasedVulns([
      { id: "RUSTSEC-2025-0071", aliases: ["CVE-2025-1", "GHSA-mm7x-qfjj-5g2c"] },
      { id: "GHSA-mm7x-qfjj-5g2c", aliases: ["CVE-2025-1"], severity: CVSS },
      { id: "GHSA-aaaa-bbbb-cccc" },
    ]);
    expect(merged.map((v) => v.id)).toEqual(["GHSA-mm7x-qfjj-5g2c", "GHSA-aaaa-bbbb-cccc"]);
    expect(merged[0].aliases?.sort()).toEqual(["CVE-2025-1", "RUSTSEC-2025-0071"]);
  });

  it("links records that only share a CVE, and keeps unrelated ones apart", () => {
    const merged = mergeAliasedVulns([
      { id: "PYSEC-2024-1", aliases: ["CVE-2024-9"] },
      { id: "GHSA-xxxx-yyyy-zzzz", aliases: ["CVE-2024-9"] },
      { id: "PYSEC-2024-2", aliases: ["CVE-2024-10"] },
    ]);
    expect(merged.map((v) => v.id)).toEqual(["GHSA-xxxx-yyyy-zzzz", "PYSEC-2024-2"]);
  });

  it("keeps the most severe record of a group", () => {
    const merged = mergeAliasedVulns([
      { id: "GHSA-low0-0000-0000", aliases: ["RUSTSEC-2020-0070"], severity: [{ type: "CVSS_V3", score: "4.0" }] },
      { id: "GHSA-high-0000-0000", aliases: ["RUSTSEC-2020-0070"], severity: [{ type: "CVSS_V3", score: "8.1" }] },
      { id: "RUSTSEC-2020-0070", aliases: ["GHSA-low0-0000-0000", "GHSA-high-0000-0000"] },
    ]);
    expect(merged.map((v) => v.id)).toEqual(["GHSA-high-0000-0000"]);
  });

  it("leaves records without aliases untouched", () => {
    const vulns = [{ id: "GHSA-1111-2222-3333" }, { id: "RUSTSEC-2024-0001" }];
    expect(mergeAliasedVulns(vulns)).toEqual(vulns);
  });
});

describe("Cargo.lock", () => {
  const registry = 'source = "registry+https://github.com/rust-lang/crates.io-index"';

  it("leaves out the workspace's own crates", () => {
    const deps = cargoLockParser.parse(
      `[[package]]\nname = "common_types"\nversion = "0.1.0"\ndependencies = [\n "serde",\n]\n\n[[package]]\nname = "serde"\nversion = "1.0.188"\n${registry}\n\n[[package]]\nname = "forked"\nversion = "0.2.0"\nsource = "git+https://github.com/acme/forked?rev=abc#abc"\n`,
      "Cargo.lock",
    );
    expect(deps.map((d) => `${d.name}@${d.version}`)).toEqual(["serde@1.0.188", "forked@0.2.0"]);
  });

  it("keeps every package of a lock file that records no sources", () => {
    const deps = cargoLockParser.parse(`[[package]]\nname = "serde"\nversion = "1.0.188"\n\n[[package]]\nname = "rand"\nversion = "0.8.5"\n`, "Cargo.lock");
    expect(deps.map((d) => d.name)).toEqual(["serde", "rand"]);
  });
});

describe("Cargo.toml", () => {
  it("leaves out path dependencies, which are crates of this repository", async () => {
    const { cargoTomlParser } = await import("./parsers/cargo-toml");
    const deps = cargoTomlParser.parse(
      `[dependencies]\ncommon_types = { version = "0.1.0", path = "../common_types" }\nserde = { version = "1.0.188", features = ["derive"] }\nrand = "0.8"\n`,
      "crates/api_models/Cargo.toml",
    );
    expect(deps.map((d) => `${d.name}@${d.version}`)).toEqual(["serde@1.0.188", "rand@0.8"]);
  });
});
