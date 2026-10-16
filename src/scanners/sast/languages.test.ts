import { describe, expect, it } from "vitest";
import { FILE_EXTENSIONS, BINARY_EXTENSIONS } from "@/lib/constants";
import { SAST_EXCLUDED_EXTENSIONS } from "../shared/extension-filters";
import { isSecretScanCandidate } from "../secrets/patterns";
import { SYSTEM_PROMPT } from "./llm-analyzer";

/** What the AI SAST and zero-day passes read: a known language, not excluded config, not binary. */
const aiReads = (ext: string) => Boolean(FILE_EXTENSIONS[ext]) && !SAST_EXCLUDED_EXTENSIONS.has(ext) && !BINARY_EXTENSIONS.has(ext);

describe("JSP, ASP.NET, Dart, ABAP and PL/SQL coverage", () => {
  const files = [
    "src/main/webapp/login.jsp",
    "WEB-INF/tags/user.tag",
    "Web/Default.aspx",
    "Web/Controls/Header.ascx",
    "Web/Global.asax",
    "Web/Upload.ashx",
    "legacy/default.asp",
    "lib/screens/login.dart",
    "src/zcl_orders.clas.abap",
    "db/pkg_orders.pks",
    "db/pkg_orders.pkb",
    "db/proc_transfer.prc",
    "db/trg_audit.trg",
  ];

  it("are read by the AI SAST and zero-day passes", () => {
    for (const f of files) expect(aiReads(f.slice(f.lastIndexOf("."))), f).toBe(true);
  });

  it("are checked for secrets", () => {
    for (const f of files.filter((x) => !x.endsWith(".tag") && !x.endsWith(".ashx"))) {
      expect(isSecretScanCandidate(f, "pattern"), f).toBe(true);
    }
  });

  it("skip wrapped (obfuscated) PL/SQL", () => {
    expect(aiReads(".plb")).toBe(false);
  });

  it("give the model each language's sources, sinks and guards", () => {
    expect(SYSTEM_PROMPT).toContain("${param.x}"); // JSP EL kept literally, not interpolated
    expect(SYSTEM_PROMPT).toMatch(/ValidateRequest="false"/);
    expect(SYSTEM_PROMPT).toMatch(/badCertificateCallback/);
    expect(SYSTEM_PROMPT).toMatch(/AUTHORITY-CHECK/);
    expect(SYSTEM_PROMPT).toMatch(/EXECUTE IMMEDIATE/);
    expect(SYSTEM_PROMPT).toMatch(/DBMS_ASSERT/);
  });
});
