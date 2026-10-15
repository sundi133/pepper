import { describe, expect, it } from "vitest";
import { findingsFromExport, parseCsv } from "./score-export";

const header = "Severity,Scanner,Title,Description,File Path,Start Line,End Line,Rule ID,CWE ID,CVE ID,Confidence,Snippet";

describe("Pepper CSV export", () => {
  it("parses quoted fields with commas, quotes and newlines", () => {
    expect(parseCsv('a,"b, ""c""\nd",e\r\n1,2,3\n')).toEqual([["a", 'b, "c"\nd', "e"], ["1", "2", "3"]]);
  });

  it("reads AI findings and skips other scanners unless asked", () => {
    const csv = [
      header,
      'HIGH,SAST_LLM,"IDOR, any user",desc,api_views/books.py,50,52,CWE-639,CWE-639,,0.85,',
      "MEDIUM,SCA,lodash,desc,package-lock.json,,,GHSA-x,,CVE-1,1.00,",
      'HIGH,ZERO_DAY,Chain,"multi\nline",app.py,9,,R,CWE-284,,0.80,',
    ].join("\n");
    const ai = findingsFromExport(csv);
    expect(ai.map((f) => [f.scanner, f.title, f.filePath, f.startLine, f.endLine, f.cweId, f.confidence])).toEqual([
      ["SAST_LLM", "IDOR, any user", "api_views/books.py", 50, 52, "CWE-639", 0.85],
      ["ZERO_DAY", "Chain", "app.py", 9, null, "CWE-284", 0.8],
    ]);
    expect(findingsFromExport(csv, true)).toHaveLength(3);
  });

  it("rejects a file that is not a Pepper export", () => {
    expect(() => findingsFromExport("a,b\n1,2")).toThrow(/Not a Pepper findings export/);
  });
});
