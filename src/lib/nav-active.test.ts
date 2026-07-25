import { describe, it, expect } from "vitest";
import { resolveActiveNavHref } from "./nav-active";

/** The sidebar's hrefs, in the order the nav declares them. */
const HREFS = [
  "/dashboard",
  "/scans/new",
  "/projects",
  "/scans",
  "/trends",
  "/settings/policies",
  "/settings/build-gates",
  "/settings/suppressions",
  "/settings/signing",
  "/settings/llm",
  "/settings/integrations",
  "/settings/apikeys",
  "/settings/team",
  "/settings/audit-log",
  "/settings/documentation",
];

const active = (pathname: string) => resolveActiveNavHref(pathname, HREFS);

describe("nav active state", () => {
  it("matches a top-level page exactly", () => {
    expect(active("/dashboard")).toBe("/dashboard");
    expect(active("/projects")).toBe("/projects");
    expect(active("/trends")).toBe("/trends");
  });

  // The bug: "Scan" pointed at /scans/new, so viewing a scan matched nothing
  // and the sidebar highlighted no entry at all.
  it("highlights Scans when viewing a scan or a finding", () => {
    expect(active("/scans/cmqi76cgq0002afokozdzqo37")).toBe("/scans");
    expect(active("/scans/cmqi76cgq0002afokozdzqo37/compliance")).toBe("/scans");
  });

  // /scans is also a prefix of /scans/new, so the more specific entry must win.
  it("highlights New scan on the create page, not Scans", () => {
    expect(active("/scans/new")).toBe("/scans/new");
  });

  it("highlights Scans on the scans list", () => {
    expect(active("/scans")).toBe("/scans");
  });

  it("highlights Projects for a project sub-page", () => {
    expect(active("/projects/abc123")).toBe("/projects");
    expect(active("/projects/abc123/settings")).toBe("/projects");
    expect(active("/projects/new")).toBe("/projects");
  });

  // Settings entries used to match exactly, so sub-pages highlighted nothing.
  it("highlights the settings entry for its sub-pages", () => {
    expect(active("/settings/integrations/ide")).toBe("/settings/integrations");
    expect(active("/settings/integrations/precommit")).toBe(
      "/settings/integrations",
    );
    expect(active("/settings/integrations/outbound")).toBe(
      "/settings/integrations",
    );
  });

  it("does not confuse settings entries that share a prefix", () => {
    expect(active("/settings/build-gates")).toBe("/settings/build-gates");
    expect(active("/settings/signing")).toBe("/settings/signing");
    expect(active("/settings/audit-log")).toBe("/settings/audit-log");
  });

  it("returns undefined for a path the nav does not cover", () => {
    // /repositories is not in the nav; it must not spuriously light something up.
    expect(active("/repositories")).toBeUndefined();
    expect(active("/notifications")).toBeUndefined();
    expect(active("/")).toBeUndefined();
  });

  it("matches on whole path segments only", () => {
    // /projects must not match /projects-archive.
    expect(active("/projects-archive")).toBeUndefined();
    expect(active("/scansomething")).toBeUndefined();
  });

  it("is independent of declaration order", () => {
    const reversed = [...HREFS].reverse();
    expect(resolveActiveNavHref("/scans/new", reversed)).toBe("/scans/new");
    expect(resolveActiveNavHref("/scans/abc", reversed)).toBe("/scans");
  });

  it("handles an empty href list", () => {
    expect(resolveActiveNavHref("/dashboard", [])).toBeUndefined();
  });
});
