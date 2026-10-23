import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { requireAuth, getActiveOrgId, requireRole } from "@/lib/auth-guard";
import {
  MAX_TEMPLATE_CHARS,
  PLACEHOLDERS,
  PLACEHOLDER_RE,
  TEMPLATE_FORMATS,
  findPlaceholders,
  normalizeTemplateBody,
  templateSections,
} from "@/lib/custom-reports/template";
import { renderMarkdownHtml } from "@/lib/custom-reports/markdown";
import { sanitizeReportHtml } from "@/lib/custom-reports/sanitize-html";

const bodySchema = z.object({
  format: z.enum(TEMPLATE_FORMATS).default("markdown"),
  body: z.string().max(MAX_TEMPLATE_CHARS),
});

/**
 * POST /api/settings/report-templates/preview — how Pepper reads a template:
 * the sections the AI will write, the placeholders it will fill, and a
 * sanitized rendering. Read-only; available to every member.
 */
export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = await getActiveOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });
  const roleAuth = await requireRole(orgId, "VIEWER");
  if ("error" in roleAuth) return roleAuth.error;

  const parsed = bodySchema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid input", details: parsed.error.issues }, { status: 400 });
  }
  const markdown = normalizeTemplateBody(parsed.data.format, parsed.data.body);
  const { title, sections } = templateSections(markdown);
  const placeholders = findPlaceholders(markdown);
  // Show placeholders as code so the preview makes clear what gets filled.
  const html = sanitizeReportHtml(renderMarkdownHtml(markdown.replace(PLACEHOLDER_RE, (m) => `\`${m}\``)));

  return NextResponse.json({
    title,
    sections: sections.map((s) => ({ heading: s.heading || "(introduction)", level: s.level, hasGuidance: !!s.body })),
    placeholders,
    knownPlaceholders: PLACEHOLDERS,
    markdown,
    html,
  });
}
