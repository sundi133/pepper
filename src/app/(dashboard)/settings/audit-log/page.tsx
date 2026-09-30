"use client";

import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import { Download, ChevronRight, Archive } from "lucide-react";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";
import { AUDIT_ACTIONS, AUDIT_RESOURCES } from "@/lib/audit-actions";

interface Entry {
  id: string;
  action: string;
  resource: string;
  resourceId: string | null;
  details: Record<string, unknown> | null;
  ipAddress: string | null;
  createdAt: string;
  user: { id: string; name: string | null; email: string | null } | null;
}

interface Retention {
  retentionDays: number | null;
  archive: boolean;
  instanceDefaultDays: number | null;
  effectiveDays: number | null;
  minDays: number;
  lastPurge: { action: string; createdAt: string; details: Record<string, unknown> | null } | null;
}

interface ArchiveObject {
  key: string;
  name: string;
  size: number;
  lastModified: string | null;
}

const ALL = "__all__";
const INSTANCE_DEFAULT = "default";
const RETENTION_CHOICES = [90, 180, 365, 730];

function describeDays(days: number | null): string {
  if (days == null) return "kept forever";
  if (days % 365 === 0) return `kept for ${days / 365} year${days === 365 ? "" : "s"}`;
  return `kept for ${days} days`;
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export default function AuditLogPage() {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [forbidden, setForbidden] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [action, setAction] = useState(ALL);
  const [resource, setResource] = useState(ALL);

  const [retention, setRetention] = useState<Retention | null>(null);
  const [retentionChoice, setRetentionChoice] = useState(INSTANCE_DEFAULT);
  const [archive, setArchive] = useState(true);
  const [saving, setSaving] = useState(false);
  const [archives, setArchives] = useState<ArchiveObject[] | null>(null);

  const query = useMemo(() => {
    const q = new URLSearchParams();
    if (from) q.set("from", from);
    if (to) q.set("to", to);
    if (action !== ALL) q.set("action", action);
    if (resource !== ALL) q.set("resource", resource);
    return q;
  }, [from, to, action, resource]);

  const load = useCallback(
    async (cursor?: string) => {
      setLoading(true);
      try {
        const q = new URLSearchParams(query);
        if (cursor) q.set("cursor", cursor);
        const res = await fetch(`/api/audit-log?${q}`);
        if (res.status === 403) {
          setForbidden(true);
          return;
        }
        const j = (await res.json()) as { entries?: Entry[]; nextCursor?: string | null; error?: string };
        if (!res.ok) {
          toast.error(j.error || "Failed to load the audit log");
          return;
        }
        setEntries((prev) => (cursor ? [...prev, ...(j.entries ?? [])] : (j.entries ?? [])));
        setNext(j.nextCursor ?? null);
      } finally {
        setLoading(false);
      }
    },
    [query],
  );

  const applyRetention = (r: Retention) => {
    setRetention(r);
    setArchive(r.archive);
    setRetentionChoice(r.retentionDays == null ? INSTANCE_DEFAULT : String(r.retentionDays));
  };

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    void fetch("/api/audit-log/retention")
      .then((r) => (r.ok ? (r.json() as Promise<Retention>) : null))
      .then((r) => r && applyRetention(r))
      .catch(() => {});
  }, []);

  async function saveRetention() {
    setSaving(true);
    try {
      const retentionDays = retentionChoice === INSTANCE_DEFAULT ? null : Number(retentionChoice);
      const res = await fetch("/api/audit-log/retention", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ retentionDays, archive }),
      });
      const j = await res.json();
      if (res.status === 403) throw new Error("Only admins can change retention");
      if (!res.ok) throw new Error(j.error || "Save failed");
      applyRetention(j as Retention);
      toast.success("Retention saved");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  async function loadArchives() {
    const res = await fetch("/api/audit-log/archives");
    const j = (await res.json()) as { archives?: ArchiveObject[]; error?: string };
    if (!res.ok) toast.error(j.error || "Failed to list archives");
    setArchives(j.archives ?? []);
  }

  const exportHref = (format: "csv" | "json") => {
    const q = new URLSearchParams(query);
    q.set("format", format);
    return `/api/audit-log/export?${q}`;
  };

  const retentionOptions = useMemo(() => {
    const opts = [...RETENTION_CHOICES];
    if (retention?.retentionDays && !opts.includes(retention.retentionDays)) opts.push(retention.retentionDays);
    return opts.sort((a, b) => a - b);
  }, [retention]);

  const pendingDays =
    retentionChoice === INSTANCE_DEFAULT
      ? (retention?.instanceDefaultDays ?? null)
      : retentionChoice === "0"
        ? null
        : Number(retentionChoice);
  const dirty =
    retention != null &&
    (archive !== retention.archive ||
      retentionChoice !== (retention.retentionDays == null ? INSTANCE_DEFAULT : String(retention.retentionDays)));

  if (forbidden) {
    return (
      <div className="max-w-5xl space-y-6">
        <h1 className="text-2xl font-bold">Audit log</h1>
        <p className="text-muted-foreground">
          Only security and admin roles can view the audit log.
        </p>
      </div>
    );
  }

  return (
    <div className="max-w-5xl space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Settings", href: "/settings/integrations" },
          { label: "Audit log" },
        ]}
      />
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">Audit log</h1>
          <p className="text-muted-foreground">
            Append-only record of security-relevant actions in this organization.
          </p>
        </div>
        <div className="flex gap-2">
          <Button asChild variant="outline" size="sm" className="gap-1.5">
            <a href={exportHref("csv")}>
              <Download className="h-3.5 w-3.5" aria-hidden /> Export CSV
            </a>
          </Button>
          <Button asChild variant="outline" size="sm" className="gap-1.5">
            <a href={exportHref("json")}>
              <Download className="h-3.5 w-3.5" aria-hidden /> Export JSON
            </a>
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div className="space-y-1">
              <Label className="text-xs">From</Label>
              <Input type="date" value={from} max={to || undefined} onChange={(e) => setFrom(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">To</Label>
              <Input type="date" value={to} min={from || undefined} onChange={(e) => setTo(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Action</Label>
              <Select value={action} onValueChange={setAction}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={ALL}>All actions</SelectItem>
                  {[...AUDIT_ACTIONS].sort().map((a) => (
                    <SelectItem key={a} value={a}>
                      {a}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Resource</Label>
              <Select value={resource} onValueChange={setResource}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={ALL}>All resources</SelectItem>
                  {[...AUDIT_RESOURCES].sort().map((r) => (
                    <SelectItem key={r} value={r}>
                      {r}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent className="text-sm">
          {entries.length === 0 && !loading && (
            <p className="py-6 text-center text-muted-foreground">No events match these filters.</p>
          )}
          <div className="divide-y">
            {entries.map((e) => {
              const open = expanded === e.id;
              return (
                <Fragment key={e.id}>
                  <button
                    type="button"
                    onClick={() => setExpanded(open ? null : e.id)}
                    className="grid w-full grid-cols-12 items-center gap-2 py-2 text-left hover:bg-muted/40"
                  >
                    <div className="col-span-12 flex items-center gap-1 text-xs text-muted-foreground sm:col-span-3">
                      <ChevronRight className={`h-3 w-3 shrink-0 transition-transform ${open ? "rotate-90" : ""}`} aria-hidden />
                      {new Date(e.createdAt).toLocaleString()}
                    </div>
                    <div className="col-span-6 truncate sm:col-span-3">
                      {e.user ? e.user.name || e.user.email || e.user.id.slice(0, 8) : "system"}
                    </div>
                    <div className="col-span-6 sm:col-span-3">
                      <Badge variant={e.action.includes("fail") || e.action.endsWith("deleted") || e.action.endsWith("removed") ? "destructive" : "outline"}>
                        {e.action}
                      </Badge>
                    </div>
                    <div className="col-span-12 truncate text-xs text-muted-foreground sm:col-span-3">
                      {e.resource}
                      {e.resourceId ? `: ${e.resourceId.slice(0, 8)}` : ""}
                      {e.ipAddress ? ` • ${e.ipAddress}` : ""}
                    </div>
                  </button>
                  {open && (
                    <div className="space-y-1 bg-muted/30 px-5 py-3 text-xs">
                      <div className="text-muted-foreground">
                        {e.user?.email ? `${e.user.email} · ` : ""}
                        {e.resource}
                        {e.resourceId ? ` ${e.resourceId}` : ""}
                        {e.ipAddress ? ` · ${e.ipAddress}` : ""}
                      </div>
                      <pre className="overflow-x-auto whitespace-pre-wrap break-all font-mono">
                        {e.details ? JSON.stringify(e.details, null, 2) : "No details"}
                      </pre>
                    </div>
                  )}
                </Fragment>
              );
            })}
          </div>
          {next && (
            <Button variant="outline" size="sm" className="mt-3" disabled={loading} onClick={() => void load(next)}>
              Load more
            </Button>
          )}
        </CardContent>
      </Card>

      {retention && (
        <Card>
          <CardHeader>
            <CardTitle>Retention</CardTitle>
            <CardDescription>
              Entries are {describeDays(retention.effectiveDays)}
              {retention.effectiveDays != null
                ? retention.archive
                  ? "; older entries are archived to object storage, then deleted."
                  : "; older entries are deleted."
                : "."}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1">
                <Label>Keep entries for</Label>
                <Select value={retentionChoice} onValueChange={setRetentionChoice}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={INSTANCE_DEFAULT}>
                      Instance default ({retention.instanceDefaultDays ? `${retention.instanceDefaultDays} days` : "forever"})
                    </SelectItem>
                    {retentionOptions.map((d) => (
                      <SelectItem key={d} value={String(d)}>
                        {d % 365 === 0 ? `${d / 365} year${d === 365 ? "" : "s"}` : `${d} days`}
                      </SelectItem>
                    ))}
                    <SelectItem value="0">Forever</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-start justify-between gap-3 rounded-md border p-3">
                <div>
                  <Label htmlFor="audit-archive">Archive before deleting</Label>
                  <p className="text-xs text-muted-foreground">
                    Gzipped JSON lines in object storage, downloadable below.
                  </p>
                </div>
                <Switch id="audit-archive" checked={archive} onCheckedChange={setArchive} />
              </div>
            </div>
            {pendingDays != null && !archive && (
              <p className="text-xs text-amber-600 dark:text-amber-400">
                Entries older than {pendingDays} days will be permanently deleted.
              </p>
            )}
            <div className="flex flex-wrap items-center gap-3">
              <Button size="sm" disabled={!dirty || saving} onClick={() => void saveRetention()}>
                {saving ? "Saving…" : "Save retention"}
              </Button>
              {retention.lastPurge && (
                <span className="text-xs text-muted-foreground">
                  Last run {new Date(retention.lastPurge.createdAt).toLocaleString()}:{" "}
                  {retention.lastPurge.action === "audit.purge_failed"
                    ? `stopped (${String(retention.lastPurge.details?.error ?? "error")})`
                    : `${Number(retention.lastPurge.details?.deleted ?? 0)} entries ${retention.lastPurge.details?.archived ? "archived and " : ""}removed`}
                </span>
              )}
            </div>

            <div className="border-t pt-3">
              {archives === null ? (
                <Button variant="ghost" size="sm" className="gap-1.5 px-0" onClick={() => void loadArchives()}>
                  <Archive className="h-3.5 w-3.5" aria-hidden /> Show archives
                </Button>
              ) : archives.length === 0 ? (
                <p className="text-xs text-muted-foreground">No archives yet.</p>
              ) : (
                <div className="space-y-1">
                  {archives.map((a) => (
                    <div key={a.key} className="flex items-center justify-between gap-2 text-xs">
                      <span className="truncate font-mono">{a.name}</span>
                      <span className="flex shrink-0 items-center gap-3 text-muted-foreground">
                        {formatBytes(a.size)}
                        <a
                          className="font-medium text-foreground underline-offset-4 hover:underline"
                          href={`/api/audit-log/archives/download?key=${encodeURIComponent(a.key)}`}
                        >
                          Download
                        </a>
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
