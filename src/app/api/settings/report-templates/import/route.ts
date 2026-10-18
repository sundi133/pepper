import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import { MAX_TEMPLATE_CHARS, formatFromFileName } from "@/lib/custom-reports/template";
import { DocxError, docxToMarkdown } from "@/lib/custom-reports/docx";

const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;

/**
 * POST /api/settings/report-templates/import — read an uploaded template file
 * (.md, .html, .txt or .docx) into a template body. Nothing is stored; the
 * editor fills its form with the result.
 */
export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  const form = await req.formData().catch(() => null);
  const file = form?.get("file");
  if (!file || typeof file === "string") {
    return NextResponse.json({ error: "Attach a template file." }, { status: 400 });
  }
  const kind = formatFromFileName(file.name);
  if (!kind) {
    return NextResponse.json({ error: "Unsupported file type. Use .md, .html, .txt or .docx." }, { status: 400 });
  }
  if (file.size > MAX_UPLOAD_BYTES) {
    return NextResponse.json({ error: "The file is larger than 10 MB." }, { status: 400 });
  }

  const buffer = Buffer.from(await file.arrayBuffer());
  let format: "markdown" | "html" | "text";
  let body: string;
  if (kind === "docx") {
    try {
      body = docxToMarkdown(buffer);
      format = "markdown";
    } catch (e) {
      const message = e instanceof DocxError ? e.message : "Could not read the Word document.";
      return NextResponse.json({ error: message }, { status: 400 });
    }
  } else {
    body = buffer.toString("utf8").replace(/^﻿/, "");
    format = kind;
  }
  if (!body.trim()) return NextResponse.json({ error: "The file has no text content." }, { status: 400 });
  if (body.length > MAX_TEMPLATE_CHARS) {
    return NextResponse.json({ error: `The template is longer than ${MAX_TEMPLATE_CHARS.toLocaleString()} characters.` }, { status: 400 });
  }

  return NextResponse.json({
    name: file.name.replace(/\.[^.]+$/, "").slice(0, 120),
    format,
    body,
    sourceFileName: file.name.slice(0, 255),
  });
}
