"use client";

import { useState } from "react";
import Link from "next/link";
import { useSWRConfig } from "swr";
import useSWRInfinite from "swr/infinite";
import { Button } from "@/components/ui/button";
import {
  Ban,
  Bell,
  CheckCircle2,
  Check,
  Clock,
  Pause,
  Play,
  RefreshCw,
  Square,
  Trash2,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import { formatRelativeTime } from "@/lib/relative-time";
import { toast } from "sonner";

const PAGE_SIZE = 30;
const UNREAD_BADGE_KEY = "/api/notifications?summary=unread";

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
  nextCursor: string | null;
};

type Filter = "all" | "unread";

/** Icon and tone per scan notification type; unknown types fall back to a bell. */
const TYPE_META: Record<string, { icon: LucideIcon; tone: string }> = {
  SCAN_QUEUED: { icon: Clock, tone: "bg-indigo-500/15 text-indigo-500 ring-indigo-500/25" },
  SCAN_COMPLETED: { icon: CheckCircle2, tone: "bg-emerald-500/15 text-emerald-500 ring-emerald-500/25" },
  SCAN_FAILED: { icon: XCircle, tone: "bg-red-500/15 text-red-500 ring-red-500/25" },
  SCAN_CANCELLED: { icon: Ban, tone: "bg-slate-500/15 text-slate-500 ring-slate-500/25" },
  SCAN_STOPPED: { icon: Square, tone: "bg-amber-500/15 text-amber-500 ring-amber-500/25" },
  SCAN_PAUSED: { icon: Pause, tone: "bg-amber-500/15 text-amber-500 ring-amber-500/25" },
  SCAN_RESUMED: { icon: Play, tone: "bg-blue-500/15 text-blue-500 ring-blue-500/25" },
};

const FALLBACK_META = { icon: Bell, tone: "bg-primary/15 text-primary ring-primary/25" };

export default function NotificationsPage() {
  const [filter, setFilter] = useState<Filter>("all");
  const { mutate: globalMutate } = useSWRConfig();

  const {
    data,
    error,
    setSize,
    size,
    isLoading,
    isValidating,
    mutate,
  } = useSWRInfinite<NotificationsResponse>(
    (_index, previous) => {
      // The previous page carries the cursor for the next one; null means the end.
      if (previous && !previous.nextCursor) return null;
      const params = new URLSearchParams({ limit: String(PAGE_SIZE) });
      if (filter === "unread") params.set("unread", "true");
      if (previous?.nextCursor) params.set("cursor", previous.nextCursor);
      return `/api/notifications?${params.toString()}`;
    },
    fetcher,
    { refreshInterval: 30_000 },
  );

  const pages = data ?? [];
  const notifications = pages.flatMap((page) => page.notifications);
  const unreadCount = pages[0]?.unreadCount ?? 0;
  const hasMore = Boolean(pages[pages.length - 1]?.nextCursor);
  const loadingMore = size > 0 && isValidating && pages.length < size;

  /** Refresh the list and the topbar badge after any change. */
  async function refreshAll() {
    await Promise.all([mutate(), globalMutate(UNREAD_BADGE_KEY)]);
  }

  async function markAllRead() {
    try {
      const res = await fetch("/api/notifications/mark-all-read", { method: "POST" });
      if (!res.ok) throw new Error();
      await refreshAll();
      toast.success("All notifications marked as read");
    } catch {
      toast.error("Could not update notifications");
    }
  }

  async function markOneRead(id: string) {
    try {
      const res = await fetch(`/api/notifications/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ read: true }),
      });
      if (!res.ok) throw new Error();
      await refreshAll();
    } catch {
      toast.error("Could not update notification");
    }
  }

  async function removeOne(id: string) {
    try {
      const res = await fetch(`/api/notifications/${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error();
      await refreshAll();
    } catch {
      toast.error("Could not delete notification");
    }
  }

  async function deleteRead() {
    if (!window.confirm("Delete all read notifications? This cannot be undone.")) return;
    try {
      const res = await fetch("/api/notifications?read=true", { method: "DELETE" });
      if (!res.ok) throw new Error();
      const { deleted } = (await res.json()) as { deleted: number };
      await refreshAll();
      toast.success(`Deleted ${deleted} read notification${deleted === 1 ? "" : "s"}`);
    } catch {
      toast.error("Could not delete read notifications");
    }
  }

  const headline = isLoading
    ? "Loading…"
    : error
      ? "Could not load notifications"
      : unreadCount === 0
        ? "You have no unread notifications"
        : `You have ${unreadCount} unread notification${unreadCount === 1 ? "" : "s"}`;

  const emptyMessage =
    filter === "unread"
      ? "No unread notifications."
      : "No notifications yet. Scan activity (queued, completed, paused, and more) will appear here.";

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground sm:text-3xl">
            Notifications
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">{headline}</p>
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
            className="border-border/60 bg-card/50 hover:text-destructive"
            disabled={!data || notifications.length === 0}
            onClick={() => void deleteRead()}
          >
            <Trash2 className="mr-2 h-4 w-4" aria-hidden />
            Delete read
          </Button>
        </div>
      </div>

      <div role="tablist" aria-label="Filter notifications" className="flex gap-2">
        {(["all", "unread"] as const).map((value) => (
          <button
            key={value}
            type="button"
            role="tab"
            aria-selected={filter === value}
            onClick={() => {
              setFilter(value);
              void setSize(1);
            }}
            className={`rounded-full px-3 py-1 text-sm transition-colors ${
              filter === value
                ? "bg-primary/15 text-primary ring-1 ring-primary/25"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {value === "all" ? "All" : `Unread${unreadCount > 0 ? ` (${unreadCount})` : ""}`}
          </button>
        ))}
      </div>

      <ul className="overflow-hidden rounded-xl border border-border/50 bg-card/40 divide-y divide-border/40">
        {isLoading && (
          <li className="px-4 py-10 text-center text-sm text-muted-foreground sm:px-5">
            Loading notifications…
          </li>
        )}

        {!isLoading && error && (
          <li className="flex flex-col items-center gap-3 px-4 py-10 text-center text-sm text-muted-foreground sm:px-5">
            <span>We could not reach the notifications service.</span>
            <Button type="button" variant="outline" size="sm" onClick={() => void mutate()}>
              <RefreshCw className="mr-2 h-4 w-4" aria-hidden />
              Try again
            </Button>
          </li>
        )}

        {!isLoading && !error && notifications.length === 0 && (
          <li className="px-4 py-10 text-center text-sm text-muted-foreground sm:px-5">
            {emptyMessage}
          </li>
        )}

        {!isLoading &&
          !error &&
          notifications.map((n) => {
            const meta = TYPE_META[n.type] ?? FALLBACK_META;
            const Icon = meta.icon;

            const content = (
              <>
                <p className={`font-semibold ${n.read ? "text-muted-foreground" : "text-foreground"}`}>
                  {n.title}
                </p>
                {n.body && (
                  <p className="text-sm leading-relaxed text-muted-foreground">{n.body}</p>
                )}
                <p className="text-xs text-muted-foreground/90">
                  <time dateTime={n.createdAt}>{formatRelativeTime(n.createdAt)}</time>
                </p>
              </>
            );

            return (
              <li key={n.id} className="flex gap-3 px-4 py-3.5 transition-colors hover:bg-muted/15 sm:gap-4 sm:px-5">
                <div className="flex shrink-0 items-start pt-0.5">
                  <span className={`flex h-10 w-10 items-center justify-center rounded-full ring-1 ${meta.tone}`}>
                    <Icon className="h-4 w-4" aria-hidden />
                  </span>
                </div>

                <div className="min-w-0 flex-1 space-y-1">
                  {n.scanId ? (
                    <Link
                      href={`/scans/${n.scanId}`}
                      onClick={() => {
                        if (!n.read) void markOneRead(n.id);
                      }}
                      className="block min-w-0 space-y-1 rounded-md outline-none ring-offset-background focus-visible:ring-2 focus-visible:ring-ring"
                    >
                      {content}
                    </Link>
                  ) : (
                    <div className="min-w-0 space-y-1">{content}</div>
                  )}
                </div>

                <div className="flex shrink-0 items-center gap-1 sm:gap-2">
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-9 w-9 text-muted-foreground hover:text-foreground"
                    disabled={n.read}
                    aria-label={n.read ? "Already read" : "Mark as read"}
                    onClick={() => {
                      if (!n.read) void markOneRead(n.id);
                    }}
                  >
                    <Check className="h-4 w-4" />
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-9 w-9 text-muted-foreground hover:text-destructive"
                    aria-label="Delete notification"
                    onClick={() => void removeOne(n.id)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                  {!n.read && (
                    <span
                      className="ml-1 h-2 w-2 shrink-0 rounded-full bg-primary shadow-[0_0_8px_hsl(var(--primary)/0.6)]"
                      aria-label="Unread"
                    />
                  )}
                </div>
              </li>
            );
          })}
      </ul>

      {!isLoading && !error && hasMore && (
        <div className="flex justify-center">
          <Button
            type="button"
            variant="outline"
            className="border-border/60 bg-card/50"
            disabled={loadingMore}
            onClick={() => void setSize(size + 1)}
          >
            {loadingMore ? "Loading…" : "Load more"}
          </Button>
        </div>
      )}
    </div>
  );
}
