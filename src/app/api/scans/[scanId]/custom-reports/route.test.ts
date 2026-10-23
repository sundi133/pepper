import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest, NextResponse } from "next/server";

const requireRole = vi.fn();
vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => ({ session: { user: { id: "u1" } } })),
  getDefaultOrgId: vi.fn(() => "o1"),
  getActiveOrgId: vi.fn(async () => "o1"),
  requireRole: (...a: unknown[]) => requireRole(...a),
}));
const scanFind = vi.fn();
const templateFind = vi.fn();
const report = { findFirst: vi.fn(), create: vi.fn(), update: vi.fn(), findMany: vi.fn(), delete: vi.fn() };
vi.mock("@/lib/prisma", () => ({
  prisma: {
    scan: { findFirst: (...a: unknown[]) => scanFind(...a) },
    reportTemplate: { findFirst: (...a: unknown[]) => templateFind(...a) },
    orgSettings: { findUnique: vi.fn(async () => null) },
    customReport: {
      findFirst: (...a: unknown[]) => report.findFirst(...a),
      create: (...a: unknown[]) => report.create(...a),
      update: (...a: unknown[]) => report.update(...a),
      findMany: (...a: unknown[]) => report.findMany(...a),
      delete: (...a: unknown[]) => report.delete(...a),
    },
  },
}));
const llmConfig = vi.fn();
vi.mock("@/lib/llm-gateway", () => ({ getLlmConfig: () => llmConfig() }));
const queueAdd = vi.fn();
vi.mock("@/lib/queue", () => ({ getReportQueue: () => ({ add: (...a: unknown[]) => queueAdd(...a) }) }));
const audit = vi.fn();
vi.mock("@/lib/audit-log", () => ({ writeAuditLog: (...a: unknown[]) => audit(...a), ipFromHeaders: vi.fn(() => null) }));

import * as list from "./route";
import * as one from "./[reportId]/route";
import * as download from "./[reportId]/download/route";

/** Handlers always respond; drop the `undefined` their inferred types allow. */
type Responds<F> = F extends (...a: infer A) => Promise<infer R> ? (...a: A) => Promise<NonNullable<R>> : never;
const GET = list.GET as Responds<typeof list.GET>;
const POST = list.POST as Responds<typeof list.POST>;
const DELETE = one.DELETE as Responds<typeof one.DELETE>;
const DOWNLOAD = download.GET as Responds<typeof download.GET>;

const params = { params: Promise.resolve({ scanId: "s1" }) };
const reportParams = { params: Promise.resolve({ scanId: "s1", reportId: "r1" }) };
const post = (body: unknown) =>
  POST(new NextRequest("http://localhost/api/scans/s1/custom-reports", { method: "POST", body: JSON.stringify(body) }), params);

beforeEach(() => {
  vi.clearAllMocks();
  requireRole.mockResolvedValue({ session: {}, membership: { role: "DEVELOPER" } });
  scanFind.mockResolvedValue({ id: "s1", status: "COMPLETED" });
  templateFind.mockResolvedValue({ id: "t1", name: "Monthly", format: "markdown", body: "## A\nx", instructions: "CTO" });
  llmConfig.mockReturnValue({ provider: "openai", apiKey: "sk-x", model: "gpt-test" });
  report.findFirst.mockResolvedValue(null);
  report.create.mockResolvedValue({ id: "r1" });
  report.findMany.mockResolvedValue([]);
  queueAdd.mockResolvedValue({});
});

describe("custom report generation API", () => {
  it("queues a report with a snapshot of the template and audit-logs the request", async () => {
    const res = await post({ templateId: "t1", instructions: " Focus on payments " });
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ reportId: "r1" });
    expect(requireRole).toHaveBeenCalledWith("o1", "DEVELOPER");
    const data = report.create.mock.calls[0][0].data;
    expect(data).toMatchObject({
      organizationId: "o1",
      scanId: "s1",
      templateId: "t1",
      templateName: "Monthly",
      extraInstructions: "Focus on payments",
      createdBy: "u1",
      templateSnapshot: { name: "Monthly", format: "markdown", body: "## A\nx", instructions: "CTO" },
    });
    expect(queueAdd).toHaveBeenCalledWith("custom-report", { reportId: "r1" }, { jobId: "r1" });
    expect(audit).toHaveBeenCalledWith(expect.objectContaining({ action: "report.custom_requested", resource: "report", resourceId: "r1" }));
  });

  it("refuses viewers", async () => {
    requireRole.mockResolvedValue({ error: NextResponse.json({ error: "Forbidden" }, { status: 403 }) });
    expect((await post({ templateId: "t1" })).status).toBe(403);
    expect(report.create).not.toHaveBeenCalled();
  });

  it("only uses scans and templates from the caller's organization", async () => {
    scanFind.mockResolvedValueOnce(null);
    expect((await post({ templateId: "t1" })).status).toBe(404);
    expect(scanFind.mock.calls[0][0].where).toEqual({ id: "s1", project: { organizationId: "o1" } });

    templateFind.mockResolvedValueOnce(null);
    expect((await post({ templateId: "other-org-template" })).status).toBe(404);
    expect(templateFind.mock.calls[0][0].where).toEqual({ id: "other-org-template", organizationId: "o1" });
    expect(report.create).not.toHaveBeenCalled();
  });

  it("rejects unfinished scans, missing LLM config, bad input and concurrent runs", async () => {
    scanFind.mockResolvedValueOnce({ id: "s1", status: "RUNNING" });
    expect((await post({ templateId: "t1" })).status).toBe(409);

    llmConfig.mockReturnValueOnce({ provider: "openai", apiKey: "", model: "m" });
    expect((await post({ templateId: "t1" })).status).toBe(400);

    expect((await post({})).status).toBe(400);
    expect((await post({ templateId: "t1", instructions: "x".repeat(2001) })).status).toBe(400);

    report.findFirst.mockResolvedValueOnce({ id: "r0" });
    const busy = await post({ templateId: "t1" });
    expect(busy.status).toBe(409);
    expect((await busy.json()).reportId).toBe("r0");
    expect(report.create).not.toHaveBeenCalled();
  });

  it("marks the report failed when it cannot be queued", async () => {
    queueAdd.mockRejectedValue(new Error("ECONNREFUSED"));
    expect((await post({ templateId: "t1" })).status).toBe(503);
    expect(report.update.mock.calls[0][0].data).toMatchObject({ status: "FAILED" });
  });

  it("lists the scan's reports scoped to the organization", async () => {
    report.findMany.mockResolvedValue([{ id: "r1", status: "COMPLETED" }]);
    const res = await GET(new NextRequest("http://localhost/api/scans/s1/custom-reports"), params);
    expect(res.status).toBe(200);
    expect(report.findMany.mock.calls[0][0].where).toEqual({ scanId: "s1", organizationId: "o1" });
  });

  it("lets only the author or Admin / Security delete a finished report", async () => {
    const del = () => DELETE(new NextRequest("http://localhost/x", { method: "DELETE" }), reportParams);
    report.findFirst.mockResolvedValue({ id: "r1", status: "COMPLETED", createdBy: "someone-else", templateName: "M" });
    expect((await del()).status).toBe(403);
    requireRole.mockResolvedValue({ session: {}, membership: { role: "SECURITY" } });
    expect((await del()).status).toBe(200);
    expect(audit).toHaveBeenCalledWith(expect.objectContaining({ action: "report.custom_deleted" }));
    report.findFirst.mockResolvedValue({ id: "r1", status: "RUNNING", createdBy: "u1", templateName: "M" });
    expect((await del()).status).toBe(409);
  });
});

describe("custom report download", () => {
  const done = {
    status: "COMPLETED",
    title: "Status",
    templateName: "Monthly",
    markdown: "## Summary\nText [F1]",
    html: "<!DOCTYPE html><p>stored</p>",
    model: "gpt-test",
    completedAt: new Date("2026-10-16T10:00:00Z"),
    scan: { project: { name: "payments" } },
  };
  const get = (fmt: string) => DOWNLOAD(new NextRequest(`http://localhost/x?format=${fmt}`), reportParams);

  it("serves the stored HTML under the no-script report CSP", async () => {
    report.findFirst.mockResolvedValue(done);
    const res = await get("html");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Security-Policy")).toBe("default-src 'none'; style-src 'unsafe-inline'");
    expect(await res.text()).toBe(done.html);
    expect(report.findFirst.mock.calls[0][0].where).toEqual({ id: "r1", scanId: "s1", organizationId: "o1" });
  });

  it("renders Markdown and PDF with the AI footer", async () => {
    report.findFirst.mockResolvedValue(done);
    const md = await get("md");
    expect(md.headers.get("Content-Type")).toContain("text/markdown");
    expect(await md.text()).toContain("generated by AI from Pepper scan s1 at 2026-10-16 10:00:00 UTC with model gpt-test");
    const pdf = await get("pdf");
    expect(pdf.headers.get("Content-Type")).toBe("application/pdf");
    expect(Buffer.from(await pdf.arrayBuffer()).subarray(0, 4).toString()).toBe("%PDF");
  });

  it("refuses unfinished reports and unknown formats", async () => {
    report.findFirst.mockResolvedValue({ ...done, status: "RUNNING", html: null });
    expect((await get("html")).status).toBe(409);
    expect((await get("docx")).status).toBe(400);
  });
});
