/**
 * DOCX template import without a dependency: a .docx is a ZIP archive whose
 * word/document.xml holds the text. We read the ZIP central directory, inflate
 * that one entry with node:zlib, and turn its paragraphs and tables into
 * Markdown (Heading styles → #, numbered/bulleted paragraphs → lists, tables →
 * pipe tables). Formatting, images and fields are not needed by the AI.
 */
import { inflateRawSync } from "node:zlib";

const MAX_DOCX_BYTES = 10 * 1024 * 1024;
const MAX_XML_BYTES = 20 * 1024 * 1024;

export class DocxError extends Error {}

/** Extract one entry from a ZIP buffer, or null when it is absent. */
export function readZipEntry(zip: Buffer, name: string): Buffer | null {
  // End of central directory: the last 0x06054b50 within the trailing 64 KiB.
  const min = Math.max(0, zip.length - 22 - 0xffff);
  let eocd = -1;
  for (let i = zip.length - 22; i >= min; i--) {
    if (zip.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new DocxError("Not a ZIP archive");
  const entries = zip.readUInt16LE(eocd + 10);
  let p = zip.readUInt32LE(eocd + 16);
  for (let n = 0; n < entries; n++) {
    if (p + 46 > zip.length || zip.readUInt32LE(p) !== 0x02014b50) throw new DocxError("Corrupt ZIP directory");
    const method = zip.readUInt16LE(p + 10);
    const compressedSize = zip.readUInt32LE(p + 20);
    const uncompressedSize = zip.readUInt32LE(p + 24);
    const nameLen = zip.readUInt16LE(p + 28);
    const extraLen = zip.readUInt16LE(p + 30);
    const commentLen = zip.readUInt16LE(p + 32);
    const localOffset = zip.readUInt32LE(p + 42);
    const entryName = zip.toString("utf8", p + 46, p + 46 + nameLen);
    p += 46 + nameLen + extraLen + commentLen;
    if (entryName !== name) continue;

    if (localOffset + 30 > zip.length || zip.readUInt32LE(localOffset) !== 0x04034b50) {
      throw new DocxError("Corrupt ZIP entry");
    }
    const start = localOffset + 30 + zip.readUInt16LE(localOffset + 26) + zip.readUInt16LE(localOffset + 28);
    const data = zip.subarray(start, start + compressedSize);
    if (uncompressedSize > MAX_XML_BYTES) throw new DocxError("Document is too large");
    if (method === 0) return Buffer.from(data);
    if (method === 8) return inflateRawSync(data, { maxOutputLength: MAX_XML_BYTES });
    throw new DocxError(`Unsupported ZIP compression method ${method}`);
  }
  return null;
}

function decodeXml(s: string): string {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_, h: string) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d: string) => String.fromCodePoint(Number(d)))
    .replace(/&amp;/g, "&");
}

function paragraphText(p: string): string {
  let out = "";
  for (const m of p.matchAll(/<w:t(?:\s[^>]*)?>([\s\S]*?)<\/w:t>|<w:tab\/>|<w:br\/>/g)) {
    if (m[0] === "<w:tab/>") out += "\t";
    else if (m[0] === "<w:br/>") out += "\n";
    else out += decodeXml(m[1]);
  }
  return out;
}

function paragraphToMarkdown(p: string): string {
  const text = paragraphText(p).trim();
  if (!text) return "";
  const style = p.match(/<w:pStyle w:val="([^"]+)"/)?.[1] ?? "";
  const heading = style.match(/^(?:Heading|heading)\s?(\d)$/)?.[1];
  if (style === "Title") return `# ${text}`;
  if (heading) return `${"#".repeat(Math.min(6, Number(heading)))} ${text}`;
  if (/<w:numPr>/.test(p) || /^List/.test(style)) return `- ${text}`;
  return text;
}

function tableToMarkdown(tbl: string): string {
  const rows = [...tbl.matchAll(/<w:tr[\s>][\s\S]*?<\/w:tr>/g)].map((r) =>
    [...r[0].matchAll(/<w:tc[\s>][\s\S]*?<\/w:tc>/g)].map((c) =>
      [...c[0].matchAll(/<w:p[\s>][\s\S]*?<\/w:p>/g)]
        .map((pp) => paragraphText(pp[0]).trim())
        .filter(Boolean)
        .join(" ")
        .replace(/\|/g, "\\|"),
    ),
  );
  if (rows.length === 0) return "";
  const width = Math.max(...rows.map((r) => r.length));
  const line = (r: string[]) => `| ${Array.from({ length: width }, (_, i) => r[i] ?? "").join(" | ")} |`;
  return [line(rows[0]), `| ${Array(width).fill("---").join(" | ")} |`, ...rows.slice(1).map(line)].join("\n");
}

/** word/document.xml → Markdown. */
export function docxXmlToMarkdown(xml: string): string {
  const body = xml.match(/<w:body>([\s\S]*)<\/w:body>/)?.[1] ?? xml;
  const parts: string[] = [];
  for (const m of body.matchAll(/<w:tbl>[\s\S]*?<\/w:tbl>|<w:p[\s>][\s\S]*?<\/w:p>|<w:p\/>/g)) {
    const md = m[0].startsWith("<w:tbl>") ? tableToMarkdown(m[0]) : paragraphToMarkdown(m[0]);
    if (md) parts.push(md);
  }
  // Consecutive list items stay together; everything else is its own block.
  return parts
    .map((p, i) => (i > 0 && p.startsWith("- ") && parts[i - 1].startsWith("- ") ? `\n${p}` : `\n\n${p}`))
    .join("")
    .trim();
}

export function docxToMarkdown(buffer: Buffer): string {
  if (buffer.length > MAX_DOCX_BYTES) throw new DocxError("DOCX file is larger than 10 MB");
  const xml = readZipEntry(buffer, "word/document.xml");
  if (!xml) throw new DocxError("Not a Word document (word/document.xml is missing)");
  return docxXmlToMarkdown(xml.toString("utf8"));
}
