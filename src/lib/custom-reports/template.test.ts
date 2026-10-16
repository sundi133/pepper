import { deflateRawSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import {
  fillPlaceholders,
  findPlaceholders,
  formatFromFileName,
  htmlToMarkdown,
  normalizeTemplateBody,
  templateSections,
  MAX_TEMPLATE_SECTIONS,
} from "./template";
import { docxToMarkdown, DocxError } from "./docx";

describe("placeholders", () => {
  it("fills known placeholders deterministically, tolerating spaces inside the braces", () => {
    const out = fillPlaceholders("Repo {{scan.repository}} has {{ findings.critical_count }} critical", {
      "scan.repository": "payments",
      "findings.critical_count": 3,
    });
    expect(out).toBe("Repo payments has 3 critical");
  });

  it("replaces unknown or empty placeholders with n/a so the AI never fills braces itself", () => {
    expect(fillPlaceholders("{{scan.commit}} / {{org.secret_sauce}}", { "scan.commit": null })).toBe("n/a / n/a");
    expect(fillPlaceholders("{{findings.new_count}}", { "findings.new_count": 0 })).toBe("0");
  });

  it("separates known from unknown placeholder names", () => {
    expect(findPlaceholders("{{scan.branch}} {{scan.branch}} {{nope.x}}")).toEqual({
      known: ["scan.branch"],
      unknown: ["nope.x"],
    });
  });
});

describe("template normalisation", () => {
  it("converts an HTML template to Markdown keeping headings, lists and tables, dropping scripts", () => {
    const md = htmlToMarkdown(`
      <html><head><title>x</title><script>alert(1)</script></head><body>
      <h1>Security report</h1>
      <p>Intro with <strong>bold</strong> &amp; more.</p>
      <h2>Top risks</h2>
      <ul><li>First</li><li>Second</li></ul>
      <table><tr><th>Severity</th><th>Count</th></tr><tr><td>High</td><td>{{findings.high_count}}</td></tr></table>
      </body></html>`);
    expect(md).toContain("# Security report");
    expect(md).toContain("Intro with **bold** & more.");
    expect(md).toContain("## Top risks");
    expect(md).toContain("- First");
    expect(md).toContain("| Severity | Count |");
    expect(md).toContain("| High | {{findings.high_count}} |");
    expect(md).not.toMatch(/alert|<script/);
  });

  it("strips raw HTML tags from Markdown and text templates", () => {
    expect(normalizeTemplateBody("markdown", "## A\n<script>x()</script><b>keep</b>")).toBe("## A\nkeep");
  });

  it("recognises upload file types", () => {
    expect(formatFromFileName("t.MD")).toBe("markdown");
    expect(formatFromFileName("t.htm")).toBe("html");
    expect(formatFromFileName("t.docx")).toBe("docx");
    expect(formatFromFileName("t.pdf")).toBeNull();
  });
});

describe("templateSections", () => {
  it("treats a bare leading H1 as the title and splits on H1–H3", () => {
    const { title, sections } = templateSections(
      "# Monthly report\n\n## Summary\nTwo sentences.\n\n## Risks\n### Detail\nText\n#### Deep\nkept inside",
    );
    expect(title).toBe("Monthly report");
    expect(sections.map((s) => s.heading)).toEqual(["Summary", "Risks", "Detail"]);
    expect(sections[2].body).toContain("#### Deep");
  });

  it("uses a leading H1 with text under it as the title plus an introduction", () => {
    const { title, sections } = templateSections("# Status for acme\nScan of main.\n\n## Summary\nx");
    expect(title).toBe("Status for acme");
    expect(sections.map((s) => [s.heading, s.body])).toEqual([["", "Scan of main."], ["Summary", "x"]]);
  });

  it("does not take a title when the template has several H1 sections", () => {
    expect(templateSections("# One\na\n\n# Two\nb").title).toBeNull();
  });

  it("keeps text before the first heading as an introduction section", () => {
    const { title, sections } = templateSections("Prepared for the board.\n\n## Findings\nList them.");
    expect(title).toBeNull();
    expect(sections[0]).toMatchObject({ heading: "", body: "Prepared for the board." });
  });

  it("makes a template without headings a single section", () => {
    expect(templateSections("Just write a summary.").sections).toHaveLength(1);
  });

  it("caps the number of sections (bounds AI calls)", () => {
    const md = Array.from({ length: 30 }, (_, i) => `## S${i}\nbody ${i}`).join("\n\n");
    const { sections } = templateSections(md);
    expect(sections).toHaveLength(MAX_TEMPLATE_SECTIONS);
    expect(sections.at(-1)!.body).toContain("S29");
  });
});

/** Build a minimal single-entry ZIP (deflated) like a .docx. */
function zipOf(name: string, content: string): Buffer {
  const data = Buffer.from(content, "utf8");
  const comp = deflateRawSync(data);
  const nameBuf = Buffer.from(name);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(8, 8);
  local.writeUInt32LE(comp.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(nameBuf.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(8, 10);
  central.writeUInt32LE(comp.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(nameBuf.length, 28);
  central.writeUInt32LE(0, 42);
  const cdOffset = local.length + nameBuf.length + comp.length;
  const cdSize = central.length + nameBuf.length;
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(cdSize, 12);
  eocd.writeUInt32LE(cdOffset, 16);
  return Buffer.concat([local, nameBuf, comp, central, nameBuf, eocd]);
}

describe("DOCX import", () => {
  it("extracts headings, lists, paragraphs and tables as Markdown", () => {
    const xml = `<?xml version="1.0"?><w:document><w:body>
      <w:p><w:pPr><w:pStyle w:val="Title"/></w:pPr><w:r><w:t>Audit report</w:t></w:r></w:p>
      <w:p><w:pPr><w:pStyle w:val="Heading2"/></w:pPr><w:r><w:t>Scope</w:t></w:r></w:p>
      <w:p><w:r><w:t xml:space="preserve">Branch </w:t></w:r><w:r><w:t>{{scan.branch}} &amp; commit</w:t></w:r></w:p>
      <w:p><w:pPr><w:numPr><w:ilvl w:val="0"/></w:numPr></w:pPr><w:r><w:t>One</w:t></w:r></w:p>
      <w:p><w:pPr><w:numPr><w:ilvl w:val="0"/></w:numPr></w:pPr><w:r><w:t>Two</w:t></w:r></w:p>
      <w:tbl><w:tr><w:tc><w:p><w:r><w:t>Ref</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>Title</w:t></w:r></w:p></w:tc></w:tr></w:tbl>
    </w:body></w:document>`;
    const md = docxToMarkdown(zipOf("word/document.xml", xml));
    expect(md).toContain("# Audit report");
    expect(md).toContain("## Scope");
    expect(md).toContain("Branch {{scan.branch}} & commit");
    expect(md).toContain("- One\n- Two");
    expect(md).toContain("| Ref | Title |");
  });

  it("rejects files that are not Word documents", () => {
    expect(() => docxToMarkdown(Buffer.from("plain text"))).toThrow(DocxError);
    expect(() => docxToMarkdown(zipOf("other.xml", "<x/>"))).toThrow(/word\/document.xml/);
  });
});
