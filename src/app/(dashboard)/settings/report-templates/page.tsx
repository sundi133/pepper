"use client";

import { useEffect, useRef, useState } from "react";
import { useSession } from "next-auth/react";
import { FileText, Loader2, Pencil, Plus, Sparkles, Trash2, Upload, Eye } from "lucide-react";
import { toast } from "sonner";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";
import { ReportPreviewFrame } from "@/components/settings/report-preview-frame";
import { PLACEHOLDERS } from "@/lib/custom-reports/template";
import { EXAMPLE_TEMPLATES } from "@/lib/custom-reports/examples";

interface Template {
  id: string;
  name: string;
  description: string | null;
  format: "markdown" | "html" | "text";
  body: string;
  instructions: string | null;
  sourceFileName: string | null;
  updatedAt: string;
}

interface Preview {
  title: string | null;
  sections: Array<{ heading: string; level: number; hasGuidance: boolean }>;
  placeholders: { known: string[]; unknown: string[] };
  html: string;
}

const FORMAT_LABELS: Record<Template["format"], string> = { markdown: "Markdown", html: "HTML", text: "Plain text" };

const EMPTY_FORM = {
  name: "",
  description: "",
  format: "markdown" as Template["format"],
  body: "",
  instructions: "",
  sourceFileName: "" as string | null,
};

async function fetchPreview(format: string, body: string): Promise<Preview> {
  const res = await fetch("/api/settings/report-templates/preview", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ format, body }),
  });
  if (!res.ok) throw new Error(((await res.json().catch(() => ({}))) as { error?: string }).error || "Preview failed");
  return res.json();
}

function PreviewPanel({ preview, loading }: { preview: Preview | null; loading: boolean }) {
  if (loading || !preview) {
    return (
      <div className="flex h-40 items-center justify-center text-sm text-muted-foreground">
        <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Rendering preview…
      </div>
    );
  }
  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="rounded-lg border p-3">
          <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Sections the AI will write ({preview.sections.length})
          </p>
          <ol className="list-decimal space-y-0.5 pl-5 text-sm">
            {preview.sections.map((s, i) => (
              <li key={i}>
                {s.heading}
                {!s.hasGuidance && <span className="text-xs text-muted-foreground"> — heading only</span>}
              </li>
            ))}
          </ol>
        </div>
        <div className="rounded-lg border p-3 text-sm">
          <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Placeholders</p>
          {preview.placeholders.known.length === 0 && preview.placeholders.unknown.length === 0 ? (
            <p className="text-muted-foreground">None — the AI follows the template&apos;s structure and wording.</p>
          ) : (
            <div className="flex flex-wrap gap-1">
              {preview.placeholders.known.map((p) => (
                <Badge key={p} variant="secondary" className="font-mono text-[10px]">{`{{${p}}}`}</Badge>
              ))}
              {preview.placeholders.unknown.map((p) => (
                <Badge key={p} variant="outline" className="border-amber-300 font-mono text-[10px] text-amber-700 dark:text-amber-400" title="Unknown placeholder — it will be shown as n/a">
                  {`{{${p}}}`} unknown
                </Badge>
              ))}
            </div>
          )}
        </div>
      </div>
      <ReportPreviewFrame html={preview.html} title={preview.title} />
    </div>
  );
}

export default function ReportTemplatesPage() {
  const { data: session } = useSession();
  const role = session?.user?.memberships?.[0]?.role;
  const canManage = role === "ADMIN" || role === "SECURITY";

  const [templates, setTemplates] = useState<Template[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<Template | null>(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [tab, setTab] = useState("edit");
  const [saving, setSaving] = useState(false);
  const [importing, setImporting] = useState(false);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [viewing, setViewing] = useState<Template | null>(null);
  const [viewPreview, setViewPreview] = useState<Preview | null>(null);
  const bodyRef = useRef<HTMLTextAreaElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  async function load() {
    try {
      const res = await fetch("/api/settings/report-templates");
      const data = await res.json();
      setTemplates(data.templates || []);
    } catch {
      toast.error("Failed to load report templates");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  function openCreate() {
    setEditing(null);
    setForm(EMPTY_FORM);
    setTab("edit");
    setDialogOpen(true);
  }

  function openEdit(t: Template) {
    setEditing(t);
    setForm({
      name: t.name,
      description: t.description || "",
      format: t.format,
      body: t.body,
      instructions: t.instructions || "",
      sourceFileName: t.sourceFileName,
    });
    setTab("edit");
    setDialogOpen(true);
  }

  async function openView(t: Template) {
    setViewing(t);
    setViewPreview(null);
    try {
      setViewPreview(await fetchPreview(t.format, t.body));
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Preview failed");
      setViewing(null);
    }
  }

  async function showPreview() {
    setTab("preview");
    setPreviewLoading(true);
    try {
      setPreview(await fetchPreview(form.format, form.body));
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Preview failed");
      setTab("edit");
    } finally {
      setPreviewLoading(false);
    }
  }

  function insertPlaceholder(name: string) {
    const token = `{{${name}}}`;
    const el = bodyRef.current;
    if (!el) {
      setForm((f) => ({ ...f, body: f.body + token }));
      return;
    }
    const start = el.selectionStart ?? form.body.length;
    const end = el.selectionEnd ?? start;
    const body = form.body.slice(0, start) + token + form.body.slice(end);
    setForm((f) => ({ ...f, body }));
    requestAnimationFrame(() => {
      el.focus();
      el.setSelectionRange(start + token.length, start + token.length);
    });
  }

  async function importFile(file: File) {
    setImporting(true);
    try {
      const data = new FormData();
      data.append("file", file);
      const res = await fetch("/api/settings/report-templates/import", { method: "POST", body: data });
      const j = await res.json();
      if (!res.ok) throw new Error(j.error || "Import failed");
      setForm((f) => ({ ...f, name: f.name || j.name, format: j.format, body: j.body, sourceFileName: j.sourceFileName }));
      toast.success(`Imported ${file.name}`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Import failed");
    } finally {
      setImporting(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  async function save() {
    if (!form.name.trim() || !form.body.trim()) {
      toast.error("Name and template body are required");
      return;
    }
    setSaving(true);
    try {
      const res = await fetch(
        editing ? `/api/settings/report-templates/${editing.id}` : "/api/settings/report-templates",
        {
          method: editing ? "PATCH" : "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: form.name,
            description: form.description || null,
            format: form.format,
            body: form.body,
            instructions: form.instructions || null,
            sourceFileName: form.sourceFileName || null,
          }),
        },
      );
      const j = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(j.error || "Save failed");
      toast.success(editing ? "Template updated" : "Template created");
      setDialogOpen(false);
      load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to save template");
    } finally {
      setSaving(false);
    }
  }

  async function remove(t: Template) {
    if (!confirm(`Delete the template "${t.name}"? Reports already generated from it are kept.`)) return;
    const res = await fetch(`/api/settings/report-templates/${t.id}`, { method: "DELETE" });
    if (res.ok) {
      toast.success("Template deleted");
      load();
    } else toast.error("Failed to delete template");
  }

  return (
    <div className="max-w-4xl space-y-6">
      <PageBreadcrumb items={[{ label: "Dashboard", href: "/dashboard" }, { label: "Report Templates" }]} />
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Report Templates</h1>
          <p className="text-muted-foreground">
            Your organization&apos;s report layouts. AI fills a template with a scan&apos;s real data from the scan&apos;s
            Reports menu.
          </p>
        </div>
        {canManage && (
          <Button onClick={openCreate}>
            <Plus className="mr-2 h-4 w-4" />
            New Template
          </Button>
        )}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Sparkles className="h-5 w-5" />
            How custom reports work
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          <p>
            Write or upload a template (Markdown, HTML, plain text or Word). Its <strong>headings, sections, tables
            and wording</strong> show the AI what to produce — no special syntax needed.
          </p>
          <p>
            The AI plans the report from your sections, fetches only the scan data each one needs (findings, history,
            compliance, dependencies), and writes it. Every finding it cites is checked against the scan; anything
            that does not exist is removed.
          </p>
          <p>
            Optional placeholders such as <code className="rounded bg-muted px-1">{"{{findings.critical_count}}"}</code>{" "}
            are filled with exact values before the AI step.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Templates ({templates.length})</CardTitle>
          <CardDescription>
            {canManage ? "Available to everyone who can generate reports." : "Only Admin and Security members can change templates."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <p className="py-8 text-center text-muted-foreground">Loading...</p>
          ) : templates.length === 0 ? (
            <p className="py-8 text-center text-muted-foreground">
              No templates yet.{canManage ? " Create one, or start from an example." : ""}
            </p>
          ) : (
            <div className="space-y-3">
              {templates.map((t) => (
                <div key={t.id} className="rounded-lg border p-4">
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0 flex-1">
                      <div className="mb-1 flex flex-wrap items-center gap-2">
                        <FileText className="h-4 w-4 text-muted-foreground" />
                        <span className="font-medium">{t.name}</span>
                        <Badge variant="secondary" className="text-[10px]">{FORMAT_LABELS[t.format] ?? t.format}</Badge>
                        {t.sourceFileName && (
                          <span className="text-xs text-muted-foreground">from {t.sourceFileName}</span>
                        )}
                      </div>
                      {t.description && <p className="line-clamp-2 text-sm text-muted-foreground">{t.description}</p>}
                      <p className="mt-1 text-xs text-muted-foreground">
                        Updated {new Date(t.updatedAt).toLocaleDateString()}
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-1">
                      <Button variant="ghost" size="icon" className="h-8 w-8" title="Preview" onClick={() => openView(t)}>
                        <Eye className="h-3.5 w-3.5" />
                      </Button>
                      {canManage && (
                        <>
                          <Button variant="ghost" size="icon" className="h-8 w-8" title="Edit" onClick={() => openEdit(t)}>
                            <Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 text-destructive"
                            title="Delete"
                            onClick={() => remove(t)}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create / edit */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>{editing ? "Edit Report Template" : "New Report Template"}</DialogTitle>
            <DialogDescription>
              Paste or upload the report you want. Keep the headings and tables you need; describe what each section
              should say in plain words.
            </DialogDescription>
          </DialogHeader>

          <Tabs value={tab} onValueChange={(v) => (v === "preview" ? showPreview() : setTab(v))}>
            <TabsList>
              <TabsTrigger value="edit">Edit</TabsTrigger>
              <TabsTrigger value="preview" disabled={!form.body.trim()}>
                Preview
              </TabsTrigger>
            </TabsList>

            <TabsContent value="edit" className="space-y-4 pt-2">
              <div className="grid gap-4 sm:grid-cols-[1fr_160px]">
                <div className="space-y-2">
                  <Label>Name</Label>
                  <Input
                    value={form.name}
                    onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                    placeholder="e.g., Monthly security status"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Format</Label>
                  <Select value={form.format} onValueChange={(v) => setForm((f) => ({ ...f, format: v as Template["format"] }))}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="markdown">Markdown</SelectItem>
                      <SelectItem value="html">HTML</SelectItem>
                      <SelectItem value="text">Plain text</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-2">
                <Label>Description (optional)</Label>
                <Input
                  value={form.description}
                  onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                  placeholder="Who this report is for"
                />
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <Label>Template</Label>
                  <div className="flex items-center gap-2">
                    <input
                      ref={fileRef}
                      type="file"
                      accept=".md,.markdown,.html,.htm,.txt,.docx"
                      className="hidden"
                      onChange={(e) => e.target.files?.[0] && importFile(e.target.files[0])}
                    />
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="h-7 gap-1.5 text-xs"
                      disabled={importing}
                      onClick={() => fileRef.current?.click()}
                    >
                      {importing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-3.5 w-3.5" />}
                      Upload .md / .html / .txt / .docx
                    </Button>
                  </div>
                </div>
                <Textarea
                  ref={bodyRef}
                  value={form.body}
                  onChange={(e) => setForm((f) => ({ ...f, body: e.target.value }))}
                  placeholder={"# Security status\n\n## Summary\nTwo sentences on overall risk.\n\n## Top risks\n..."}
                  rows={14}
                  className="font-mono text-xs"
                />
                <div className="flex flex-wrap items-center gap-1">
                  <span className="mr-1 text-xs text-muted-foreground">Insert placeholder:</span>
                  {Object.entries(PLACEHOLDERS).map(([name, label]) => (
                    <button
                      key={name}
                      type="button"
                      title={label}
                      onClick={() => insertPlaceholder(name)}
                      className="rounded-md border px-1.5 py-0.5 font-mono text-[10px] transition-colors hover:bg-muted"
                    >
                      {name}
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-2">
                <Label>Instructions for the AI (optional)</Label>
                <Textarea
                  value={form.instructions}
                  onChange={(e) => setForm((f) => ({ ...f, instructions: e.target.value }))}
                  placeholder="Audience, tone and emphasis — e.g., For the board: plain language, focus on business risk, no code."
                  rows={3}
                />
              </div>

              {!editing && (
                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground">Quick start — load an example:</Label>
                  <div className="flex flex-wrap gap-1.5">
                    {EXAMPLE_TEMPLATES.map((ex) => (
                      <button
                        key={ex.name}
                        type="button"
                        onClick={() =>
                          setForm({
                            name: ex.name,
                            description: ex.description,
                            format: "markdown",
                            body: ex.body,
                            instructions: ex.instructions,
                            sourceFileName: null,
                          })
                        }
                        className="rounded-md border px-2 py-1 text-xs transition-colors hover:bg-muted"
                      >
                        {ex.name}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </TabsContent>

            <TabsContent value="preview" className="pt-2">
              <PreviewPanel preview={preview} loading={previewLoading} />
            </TabsContent>
          </Tabs>

          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={save} disabled={saving}>
              {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {editing ? "Update" : "Create"} Template
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Read-only preview */}
      <Dialog open={!!viewing} onOpenChange={(o) => !o && setViewing(null)}>
        <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>{viewing?.name}</DialogTitle>
            <DialogDescription>
              {viewing?.instructions ? `AI instructions: ${viewing.instructions}` : "How Pepper reads this template."}
            </DialogDescription>
          </DialogHeader>
          <PreviewPanel preview={viewPreview} loading={!viewPreview} />
        </DialogContent>
      </Dialog>
    </div>
  );
}
