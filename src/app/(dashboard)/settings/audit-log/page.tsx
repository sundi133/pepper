"use client";

import { useEffect, useState } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

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

export default function AuditLogPage() {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function load(c?: string) {
    setLoading(true);
    try {
      const q = c ? `?cursor=${c}` : "";
      const res = await fetch(`/api/audit-log${q}`);
      if (!res.ok) return;
      const j = (await res.json()) as { entries: Entry[]; nextCursor: string | null };
      setEntries(c ? [...entries, ...j.entries] : j.entries);
      setNext(j.nextCursor);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function actionBadge(action: string) {
    const sev = action.startsWith("apikey")
      ? "destructive"
      : action.startsWith("integration") || action.startsWith("settings")
        ? "default"
        : "outline";
    return <Badge variant={sev as "destructive" | "default" | "outline"}>{action}</Badge>;
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
      <div>
        <h1 className="text-2xl font-bold">Audit log</h1>
        <p className="text-muted-foreground">
          Immutable record of security-relevant actions in this organization.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Events</CardTitle>
          <CardDescription>Most recent first.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-1 text-sm">
          {entries.length === 0 && !loading && (
            <p className="text-muted-foreground">No events yet.</p>
          )}
          {entries.map((e) => (
            <div
              key={e.id}
              className="grid grid-cols-12 items-baseline gap-2 border-b py-2 last:border-0"
            >
              <div className="col-span-3 text-xs text-muted-foreground">
                {new Date(e.createdAt).toLocaleString()}
              </div>
              <div className="col-span-3 truncate">
                {e.user
                  ? e.user.name || e.user.email || e.user.id.slice(0, 8)
                  : "system"}
              </div>
              <div className="col-span-3">{actionBadge(e.action)}</div>
              <div className="col-span-3 truncate text-xs text-muted-foreground">
                {e.resource}
                {e.resourceId ? `: ${e.resourceId.slice(0, 8)}` : ""}
                {e.ipAddress ? ` • ${e.ipAddress}` : ""}
              </div>
            </div>
          ))}
          {next && (
            <Button
              variant="outline"
              size="sm"
              className="mt-3"
              disabled={loading}
              onClick={() => void load(next)}
            >
              Load more
            </Button>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
