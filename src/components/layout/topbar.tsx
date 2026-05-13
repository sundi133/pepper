"use client";

import { useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import useSWR from "swr";
import { signOut, useSession } from "next-auth/react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Input } from "@/components/ui/input";
import { LogOut, Search, User, Bell, Shield } from "lucide-react";
import { ThemeToggle } from "@/components/layout/theme-toggle";

const unreadFetcher = (url: string) => fetch(url).then((r) => r.json());

export function Topbar() {
  const pathname = usePathname();
  const { data: session } = useSession();
  const { data: unreadData, mutate: mutateUnread } = useSWR<{
    unreadCount: number;
  }>("/api/notifications?summary=unread", unreadFetcher, {
    refreshInterval: 30_000,
    dedupingInterval: 2_000,
  });

  useEffect(() => {
    void mutateUnread();
  }, [pathname, mutateUnread]);

  const unreadCount = unreadData?.unreadCount ?? 0;

  const isOrgAdmin = Boolean(
    session?.user?.memberships?.some((m) => m.role === "ADMIN"),
  );

  const initials = session?.user?.name
    ? session.user.name
        .split(" ")
        .map((n) => n[0])
        .join("")
        .toUpperCase()
    : session?.user?.email?.[0]?.toUpperCase() || "U";

  return (
    <header className="sticky top-0 z-40 flex h-16 w-full shrink-0 items-center justify-between gap-x-3 border-b border-border/50 bg-background/90 px-4 backdrop-blur-md supports-[backdrop-filter]:bg-background/75 sm:gap-x-5 sm:px-6 lg:px-8">
      <div className="relative min-w-0 max-w-xl flex-1">
        <Search
          className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden
        />
        <Input
          type="search"
          placeholder="Search projects, vulnerabilities…"
          className="h-10 w-full border-border/60 bg-background/80 pl-9 shadow-none"
          aria-label="Search"
        />
      </div>
      <div className="flex shrink-0 items-center gap-x-1 sm:gap-x-2">
        <ThemeToggle />
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="relative h-9 w-9 text-muted-foreground hover:text-foreground"
          asChild
        >
          <Link href="/notifications" aria-label="Notifications">
            <Bell className="h-5 w-5" aria-hidden />
            {unreadCount > 0 && (
              <Badge
                variant="destructive"
                className="pointer-events-none absolute -right-0.5 -top-0.5 h-4 min-w-4 px-1 text-[10px] leading-none"
              >
                {unreadCount > 99 ? "99+" : unreadCount}
              </Badge>
            )}
          </Link>
        </Button>
        {isOrgAdmin ? (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="h-9 w-9 text-muted-foreground hover:text-foreground"
            asChild
          >
            <Link href="/settings/team" aria-label="Organization admin">
              <Shield className="h-5 w-5 text-primary" aria-hidden />
            </Link>
          </Button>
        ) : null}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="relative h-9 w-9 rounded-full">
              <Avatar className="h-9 w-9 border border-border/60">
                <AvatarFallback className="bg-primary/15 text-xs font-semibold text-primary">
                  {initials}
                </AvatarFallback>
              </Avatar>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="min-w-[12rem]">
            <div className="px-2 py-1.5">
              <p className="text-sm font-medium">
                {session?.user?.name || "User"}
              </p>
              <p className="text-xs text-muted-foreground">
                {session?.user?.email}
              </p>
            </div>
            <DropdownMenuSeparator />
            <DropdownMenuItem>
              <User className="mr-2 h-4 w-4" />
              Profile
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => signOut({ callbackUrl: "/login" })}
            >
              <LogOut className="mr-2 h-4 w-4" />
              Sign Out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
