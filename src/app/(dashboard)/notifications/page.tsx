"use client";

import { useEffect, useState } from "react";
import useSWRInfinite from "swr/infinite";
import { mutate as globalMutate } from "swr";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import {
  Ban,
  Bell,
  Check,
  CheckCircle2,
  Clock,
  FileWarning,
  Pause,
  Play,
  ShieldAlert,
  Siren,
  Trash2,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import { formatRelativeTime } from "@/lib/relative-time";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

const fetcher = (url: string) =>
  fetch(url).then((r) => {
    if (!r.ok) throw new Error("Failed to load notifications");
    return r.json();
  });

type NotificationRow = {
  id: string;
  type: string;
  title: string;
  body: string | null;
  read: boolean;
  scanId: string | null;
  createdAt: string;
};

type NotificationsResponse = {
  notifications: NotificationRow[];
  unreadCount: number;
  total: number;
  nextCursor: string | null;
};

type Prefs = {
  emailOnScanComplete: boolean;
  emailOnGateFail: boolean;
  emailOnCritical: boolean;
};

type Tone = "critical" | "warning" | "success" | "neutral";

const TONE_CLASS: Record<Tone, string> = {
  critical: "bg-red-500/10 text-red-600 ring-red-500/25 dark:text-red-400",
  warning: "bg-amber-500/10 text-amber-600 ring-amber-500/25 dark:text-amber-400",
  success: "bg-emerald-500/10 text-emerald-600 ring-emerald-500/25 dark:text-emerald-400",
  neutral: "bg-muted text-muted-foreground ring-border",
};

/** Icon and tone per type; a completed scan with critical/high issues is urgent. */
function presentation(n: NotificationRow): { icon: LucideIcon; tone: Tone; label: string } {
  switch (n.type) {
    case "SCAN_COMPLETED":
      if (/critical/i.test(n.title)) return { icon: Siren, tone: "critical", label: "Critical issues" };
      if (/high/i.test(n.title)) return { icon: ShieldAlert, tone: "warning", label: "High issues" };
      return { icon: CheckCircle2, tone: "success", label: "Scan completed" };
    case "SCAN_GATE_FAILED":
      return { icon: ShieldAlert, tone: "critical", label: "Gate failed" };
    case "SCAN_FAILED":
      return { icon: XCircle, tone: "critical", label: "Scan failed" };
    case "SIGNING_FAILED":
      return { icon: FileWarning, tone: "warning", label: "Signing failed" };
    case "SCAN_PAUSED":
      return { icon: Pause, tone: "neutral", label: "Paused" };
    case "SCAN_RESUMED":
      return { icon: Play, tone: "neutral", label: "Resumed" };
    case "SCAN_STOPPED":
    case "SCAN_CANCELLED":
      return { icon: Ban, tone: "neutral", label: "Stopped" };
    case "SCAN_QUEUED":
      return { icon: Clock, tone: "neutral", label: "Queued" };
    default:
      return { icon: Bell, tone: "neutral", label: "Notification" };
  }
}

function dayGroup(iso: string): string {
  const d = new Date(iso);
  const today = new Date();
  const startOf = (x: Date) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diffDays = Math.round((startOf(today) - startOf(d)) / 86_400_000);
  if (diffDays <= 0) return "Today";
  if (diffDays === 1) return "Yesterday";
  if (diffDays < 7) return "This week";
  return "Earlier";
}

const PREF_ROWS: Array<{ key: keyof Prefs; label: string; hint: string }> = [
  { key: "emailOnCritical", label: "Critical findings", hint: "A scan finds at least one critical issue" },
  { key: "emailOnGateFail", label: "Build gate failures", hint: "A scan doesn't pass the build gate" },
  { key: "emailOnScanComplete", label: "Every completed scan", hint: "A summary each time a scan finishes" },
];

function refreshUnreadBadge() {
  void globalMutate("/api/notifications?summary=unread");
}

export default function NotificationsPage() {
  const router = useRouter();
  const [filter, setFilter] = useState<"all" | "unread">("all");
  const [prefs, setPrefs] = useState<Prefs | null>(null);

  const getKey = (index: number, previous: NotificationsResponse | null) => {
    if (previous && !previous.nextCursor) return null;
    const params = new URLSearchParams();
    if (filter === "unread") params.set("filter", "unread");
    if (index > 0 && previous?.nextCursor) params.set("cursor", previous.nextCursor);
    const qs = params.toString();
    return `/api/notifications${qs ? `?${qs}` : ""}`;
  };

  const { data, error, mutate, isLoading, size, setSize, isValidating } =
    useSWRInfinite<NotificationsResponse>(getKey, fetcher, { refreshInterval: 30_000 });

  useEffect(() => {
    fetch("/api/notifications/preferences")
      .then((r) => (r.ok ? r.json() : null))
      .then((j: Prefs | null) => setPrefs(j))
      .catch(() => setPrefs(null));
  }, []);

  const notifications = data?.flatMap((page) => page.notifications) ?? [];
  const first = data?.[0];
  const unreadCount = first?.unreadCount ?? 0;
  const total = first?.total ?? 0;
  const hasMore = Boolean(data?.[data.length - 1]?.nextCursor);
  const readCount = total - unreadCount;

  /** Apply a change to every loaded page right away; revalidate after. */
  function optimistic(change: (rows: NotificationRow[]) => NotificationRow[], unreadDelta = 0) {
    void mutate(
      (pages) =>
        pages?.map((p) => ({
          ...p,
          notifications: change(p.notifications),
          unreadCount: Math.max(0, p.unreadCount + unreadDelta),
        })),
      { revalidate: false },
    );
  }

  async function request(url: string, init: RequestInit, failure: string) {
    try {
      const res = await fetch(url, init);
      if (!res.ok) throw new Error();
      return true;
    } catch {
      toast.error(failure);
      return false;
    } finally {
      await mutate();
      refreshUnreadBadge();
    }
  }

  async function markAllRead() {
    optimistic((rows) => rows.map((r) => ({ ...r, read: true })), -unreadCount);
    if (await request("/api/notifications/mark-all-read", { method: "POST" }, "Could not update notifications")) {
      toast.success("All notifications marked as read");
    }
  }

  async function markOneRead(id: string) {
    optimistic((rows) => rows.map((r) => (r.id === id ? { ...r, read: true } : r)), -1);
    await request(
      `/api/notifications/${id}`,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ read: true }),
      },
      "Could not update notification",
    );
  }

  async function removeOne(n: NotificationRow) {
    optimistic((rows) => rows.filter((r) => r.id !== n.id), n.read ? 0 : -1);
    await request(`/api/notifications/${n.id}`, { method: "DELETE" }, "Could not delete notification");
  }

  async function clearRead() {
    if (!confirm(`Delete ${readCount} read notification${readCount === 1 ? "" : "s"}?`)) return;
    optimistic((rows) => rows.filter((r) => !r.read));
    if (await request("/api/notifications?scope=read", { method: "DELETE" }, "Could not clear notifications")) {
      toast.success("Read notifications cleared");
    }
  }

  function open(n: NotificationRow) {
    if (!n.read) void markOneRead(n.id);
    if (n.scanId) router.push(`/scans/${n.scanId}`);
  }

  async function savePref(key: keyof Prefs, value: boolean) {
    if (!prefs) return;
    const previous = prefs;
    setPrefs({ ...prefs, [key]: value });
    try {
      const res = await fetch("/api/notifications/preferences", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ [key]: value }),
      });
      if (!res.ok) throw new Error();
    } catch {
      setPrefs(previous);
      toast.error("Could not save email preferences");
    }
  }

  let lastGroup = "";

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground sm:text-3xl">
            Notifications
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {isLoading
              ? "Loading…"
              : unreadCount === 0
                ? "You're all caught up"
                : `You have ${unreadCount} unread notification${unreadCount === 1 ? "" : "s"}`}
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          <Button
            type="button"
            variant="outline"
            className="border-border/60 bg-card/50"
            disabled={!data || unreadCount === 0}
            onClick={() => void markAllRead()}
          >
            <Check className="mr-2 h-4 w-4" aria-hidden />
            Mark all as read
          </Button>
          <Button
            type="button"
            variant="outline"
            className="border-border/60 bg-card/50"
            disabled={!data || readCount <= 0}
            onClick={() => void clearRead()}
          >
            <Trash2 className="mr-2 h-4 w-4" aria-hidden />
            Clear read
          </Button>
        </div>
      </div>

      <div className="inline-flex rounded-lg border border-border/60 bg-card/40 p-0.5 text-sm" role="tablist">
        {(["all", "unread"] as const).map((f) => (
          <button
            key={f}
            type="button"
            role="tab"
            aria-selected={filter === f}
            onClick={() => setFilter(f)}
            className={cn(
              "rounded-md px-3 py-1.5 font-medium transition-colors",
              filter === f
                ? "bg-background text-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            {f === "all" ? "All" : `Unread${unreadCount > 0 ? ` (${unreadCount})` : ""}`}
          </button>
        ))}
      </div>

      {error && (
        <div className="flex items-center justify-between rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300">
          <span>Couldn&apos;t load notifications.</span>
          <Button size="sm" variant="outline" onClick={() => void mutate()}>
            Retry
          </Button>
        </div>
      )}

      <ul className="overflow-hidden rounded-xl border border-border/50 bg-card/40">
        {isLoading && (
          <li className="px-4 py-10 text-center text-sm text-muted-foreground sm:px-5">
            Loading notifications…
          </li>
        )}
        {!isLoading && !error && notifications.length === 0 && (
          <li className="px-4 py-10 text-center text-sm text-muted-foreground sm:px-5">
            {filter === "unread"
              ? "No unread notifications."
              : "No notifications yet. Scan results, failed build gates and signing problems will appear here."}
          </li>
        )}
        {notifications.map((n) => {
          const { icon: Icon, tone, label } = presentation(n);
          const group = dayGroup(n.createdAt);
          const showGroup = group !== lastGroup;
          lastGroup = group;
          return (
            <li key={n.id} className="border-t border-border/40 first:border-t-0">
              {showGroup && (
                <div className="bg-muted/30 px-4 py-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground sm:px-5">
                  {group}
                </div>
              )}
              <div
                className={cn(
                  "flex gap-3 px-4 py-3.5 transition-colors hover:bg-muted/20 sm:gap-4 sm:px-5",
                  !n.read && "bg-primary/[0.03]",
                )}
              >
                <span
                  className={cn(
                    "mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-full ring-1",
                    TONE_CLASS[tone],
                  )}
                  title={label}
                >
                  <Icon className="h-4 w-4" aria-hidden />
                  <span className="sr-only">{label}</span>
                </span>
                <button
                  type="button"
                  className="min-w-0 flex-1 space-y-1 rounded-md text-left outline-none ring-offset-background focus-visible:ring-2 focus-visible:ring-ring"
                  onClick={() => open(n)}
                >
                  <p className={cn("text-foreground", n.read ? "font-medium" : "font-semibold")}>
                    {n.title}
                  </p>
                  {n.body && (
                    <p className="text-sm leading-relaxed text-muted-foreground">{n.body}</p>
                  )}
                  <p
                    className="text-xs text-muted-foreground/90"
                    title={new Date(n.createdAt).toLocaleString()}
                  >
                    {formatRelativeTime(n.createdAt)}
                    {n.scanId ? " · View scan" : ""}
                  </p>
                </button>
                <div className="flex shrink-0 items-center gap-1 sm:gap-2">
                  {!n.read && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="h-9 w-9 text-muted-foreground hover:text-foreground"
                      aria-label="Mark as read"
                      title="Mark as read"
                      onClick={() => void markOneRead(n.id)}
                    >
                      <Check className="h-4 w-4" />
                    </Button>
                  )}
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-9 w-9 text-muted-foreground hover:text-destructive"
                    aria-label="Delete notification"
                    title="Delete"
                    onClick={() => void removeOne(n)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                  {!n.read && (
                    <span className="ml-1 h-2 w-2 shrink-0 rounded-full bg-primary" aria-label="Unread" />
                  )}
                </div>
              </div>
            </li>
          );
        })}
      </ul>

      {hasMore && (
        <div className="flex justify-center">
          <Button
            variant="outline"
            disabled={isValidating}
            onClick={() => void setSize(size + 1)}
          >
            {isValidating ? "Loading…" : "Load more"}
          </Button>
        </div>
      )}

      <section className="rounded-xl border border-border/50 bg-card/40 p-4 sm:p-5">
        <h2 className="font-semibold text-foreground">Email me when</h2>
        <p className="mt-0.5 text-sm text-muted-foreground">
          For scans you start. Applies to the current organization.
        </p>
        {prefs ? (
          <div className="mt-4 space-y-3">
            {PREF_ROWS.map((row) => (
              <div key={row.key} className="flex items-center justify-between gap-4">
                <div>
                  <Label htmlFor={`pref-${row.key}`}>{row.label}</Label>
                  <p className="text-xs text-muted-foreground">{row.hint}</p>
                </div>
                <Switch
                  id={`pref-${row.key}`}
                  checked={prefs[row.key]}
                  onCheckedChange={(v) => void savePref(row.key, v)}
                />
              </div>
            ))}
          </div>
        ) : (
          <p className="mt-3 text-sm text-muted-foreground">Email preferences aren&apos;t available.</p>
        )}
        <p className="mt-4 text-xs text-muted-foreground">
          Read notifications are removed after 30 days, unread after 90.
        </p>
      </section>
    </div>
  );
}
