"use client";

import useSWR from "swr";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Phone, Check, Trash2 } from "lucide-react";
import { formatRelativeTime } from "@/lib/relative-time";
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
};

export default function NotificationsPage() {
  const { data, mutate, isLoading } = useSWR<NotificationsResponse>(
    "/api/notifications",
    fetcher,
  );

  const notifications = data?.notifications ?? [];
  const unreadCount = data?.unreadCount ?? 0;

  async function markAllRead() {
    try {
      const res = await fetch("/api/notifications/mark-all-read", {
        method: "POST",
      });
      if (!res.ok) throw new Error();
      await mutate();
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
      await mutate();
    } catch {
      toast.error("Could not update notification");
    }
  }

  async function removeOne(id: string) {
    try {
      const res = await fetch(`/api/notifications/${id}`, {
        method: "DELETE",
      });
      if (!res.ok) throw new Error();
      await mutate();
    } catch {
      toast.error("Could not delete notification");
    }
  }

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
                ? "You have no unread notifications"
                : `You have ${unreadCount} unread notification${unreadCount === 1 ? "" : "s"}`}
          </p>
        </div>
        <Button
          type="button"
          variant="outline"
          className="shrink-0 border-border/60 bg-card/50"
          disabled={!data || unreadCount === 0}
          onClick={() => void markAllRead()}
        >
          <Check className="mr-2 h-4 w-4" aria-hidden />
          Mark all as read
        </Button>
      </div>

      <ul className="overflow-hidden rounded-xl border border-border/50 bg-card/40 divide-y divide-border/40">
        {isLoading && (
          <li className="px-4 py-10 text-center text-sm text-muted-foreground sm:px-5">
            Loading notifications…
          </li>
        )}
        {!isLoading && notifications.length === 0 && (
          <li className="px-4 py-10 text-center text-sm text-muted-foreground sm:px-5">
            No notifications yet. Scan activity (queued, completed, paused, and more) will appear here.
          </li>
        )}
        {!isLoading &&
          notifications.map((n) => {
            const rowClass =
              "flex gap-3 px-4 py-3.5 transition-colors hover:bg-muted/15 sm:gap-4 sm:px-5";

            const textBlock = n.scanId ? (
              <Link
                href={`/scans/${n.scanId}`}
                className="block min-w-0 space-y-1 rounded-md outline-none ring-offset-background focus-visible:ring-2 focus-visible:ring-ring"
              >
                <p className="font-semibold text-foreground">{n.title}</p>
                {n.body && (
                  <p className="text-sm leading-relaxed text-muted-foreground">
                    {n.body}
                  </p>
                )}
                <p className="text-xs text-muted-foreground/90">
                  {formatRelativeTime(n.createdAt)}
                </p>
              </Link>
            ) : (
              <div className="min-w-0 space-y-1">
                <p className="font-semibold text-foreground">{n.title}</p>
                {n.body && (
                  <p className="text-sm leading-relaxed text-muted-foreground">
                    {n.body}
                  </p>
                )}
                <p className="text-xs text-muted-foreground/90">
                  {formatRelativeTime(n.createdAt)}
                </p>
              </div>
            );

            return (
              <li key={n.id} className={rowClass}>
                <div className="flex shrink-0 items-start pt-0.5">
                  <span className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/15 text-primary ring-1 ring-primary/25">
                    <Phone className="h-4 w-4" aria-hidden />
                  </span>
                </div>
                <div className="min-w-0 flex-1">{textBlock}</div>
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
                      aria-hidden
                    />
                  )}
                </div>
              </li>
            );
          })}
      </ul>
    </div>
  );
}
