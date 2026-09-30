"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Loader2, ExternalLink } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

type Target = { id: string; name: string; kind: "AZURE_BOARDS" | "JIRA"; kindLabel: string };

type Result = {
  integrationId: string;
  name: string;
  kind: "AZURE_BOARDS" | "JIRA";
  created: number;
  existing: number;
  tickets: Array<{ findingId: string; id: string; url: string; existing: boolean }>;
  failed: Array<{ findingId: string; title: string; error: string }>;
  stoppedEarly?: string;
};

const ticketLabel = (kind: Result["kind"], id: string) => (kind === "AZURE_BOARDS" ? `AB#${id}` : id);

/** File the selected findings in one or more ticket systems (Azure Boards, Jira). */
export function RaiseTicketsDialog({
  open,
  onOpenChange,
  scanId,
  findingIds,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  scanId: string;
  findingIds: string[];
}) {
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [limit, setLimit] = useState(200);
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<Result[] | null>(null);

  useEffect(() => {
    if (!open) return;
    setResults(null);
    setTargets(null);
    let cancelled = false;
    fetch(`/api/scans/${scanId}/tickets`)
      .then((r) => (r.ok ? (r.json() as Promise<{ targets: Target[]; limit: number }>) : { targets: [], limit: 200 }))
      .then((j) => {
        if (cancelled) return;
        setTargets(j.targets);
        setLimit(j.limit);
        setChosen(new Set(j.targets.map((t) => t.id)));
      })
      .catch(() => !cancelled && setTargets([]));
    return () => {
      cancelled = true;
    };
  }, [open, scanId]);

  const tooMany = findingIds.length > limit;

  async function raise() {
    setRunning(true);
    try {
      const res = await fetch(`/api/scans/${scanId}/tickets`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ findingIds, integrationIds: [...chosen] }),
      });
      const j = (await res.json()) as { results?: Result[]; error?: string };
      if (!j.results) throw new Error(j.error || "Raising tickets failed");
      setResults(j.results);
      const created = j.results.reduce((n, r) => n + r.created, 0);
      const failed = j.results.reduce((n, r) => n + r.failed.length, 0);
      if (created > 0) toast.success(`${created} ticket${created === 1 ? "" : "s"} created`);
      else if (failed === 0) toast.success("All selected findings were already tracked");
      if (failed > 0) toast.error(`${failed} could not be filed. See the details.`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Raising tickets failed");
    } finally {
      setRunning(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !running && onOpenChange(o)}>
      <DialogContent className="max-h-[85vh] max-w-lg gap-0 overflow-hidden p-0 sm:max-w-lg">
        <DialogHeader className="border-b border-border/60 px-6 py-4">
          <DialogTitle className="text-left text-base">Raise tickets</DialogTitle>
          <DialogDescription className="text-left">
            File {findingIds.length} selected finding{findingIds.length === 1 ? "" : "s"}. Each issue gets one ticket per
            board or Jira project; findings already tracked there are not filed again.
          </DialogDescription>
        </DialogHeader>

        <div className="max-h-[calc(85vh-10rem)] space-y-4 overflow-y-auto px-6 py-4 text-sm">
          {targets === null ? (
            <div className="flex items-center gap-2 text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> Loading ticket systems…
            </div>
          ) : targets.length === 0 ? (
            <p className="text-muted-foreground">
              No ticket system is configured. Add Azure Boards or Jira under{" "}
              <Link className="underline underline-offset-4" href="/settings/integrations/outbound">
                Settings → Integrations → Outbound
              </Link>
              .
            </p>
          ) : results ? (
            <div className="space-y-4">
              {results.map((r) => (
                <div key={r.integrationId} className="space-y-1.5 rounded-md border p-3">
                  <p className="font-medium">{r.name}</p>
                  <p className="text-muted-foreground">
                    {r.created} created · {r.existing} already tracked · {r.failed.length} failed
                  </p>
                  {r.tickets.filter((t) => !t.existing).length > 0 && (
                    <div className="flex flex-wrap gap-x-3 gap-y-1">
                      {r.tickets
                        .filter((t) => !t.existing)
                        .slice(0, 20)
                        .map((t) => (
                          <a
                            key={t.findingId}
                            href={t.url}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 text-xs underline underline-offset-4"
                          >
                            {ticketLabel(r.kind, t.id)}
                            <ExternalLink className="h-3 w-3" aria-hidden />
                          </a>
                        ))}
                    </div>
                  )}
                  {r.failed.slice(0, 5).map((f) => (
                    <p key={f.findingId} className="text-xs text-destructive">
                      {f.title}: {f.error}
                    </p>
                  ))}
                  {r.failed.length > 5 && (
                    <p className="text-xs text-destructive">…and {r.failed.length - 5} more</p>
                  )}
                  {r.stoppedEarly && <p className="text-xs text-muted-foreground">{r.stoppedEarly}</p>}
                </div>
              ))}
            </div>
          ) : (
            <div className="space-y-2">
              <p className="font-medium">Send to</p>
              {targets.map((t) => (
                <label key={t.id} className="flex cursor-pointer items-center gap-2">
                  <Checkbox
                    checked={chosen.has(t.id)}
                    onCheckedChange={(v) =>
                      setChosen((prev) => {
                        const next = new Set(prev);
                        if (v) next.add(t.id);
                        else next.delete(t.id);
                        return next;
                      })
                    }
                  />
                  <span>{t.name}</span>
                  <span className="text-xs text-muted-foreground">{t.kindLabel}</span>
                </label>
              ))}
              {tooMany && (
                <p className="text-xs text-destructive">
                  Select at most {limit} findings at a time ({findingIds.length} selected).
                </p>
              )}
            </div>
          )}
        </div>

        <DialogFooter className="border-t border-border/60 px-6 py-3">
          {results ? (
            <Button size="sm" onClick={() => onOpenChange(false)}>
              Done
            </Button>
          ) : (
            <>
              <Button size="sm" variant="ghost" onClick={() => onOpenChange(false)} disabled={running}>
                Cancel
              </Button>
              <Button
                size="sm"
                onClick={() => void raise()}
                disabled={running || !targets?.length || chosen.size === 0 || tooMany}
              >
                {running ? (
                  <>
                    <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden /> Filing…
                  </>
                ) : (
                  `Raise ${findingIds.length} ticket${findingIds.length === 1 ? "" : "s"}`
                )}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
