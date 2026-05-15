"use client";

import Link from "next/link";
import { Shield } from "lucide-react";
import { SidebarNav } from "@/components/layout/sidebar-nav";

export function SidebarBrand({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <Link
      href="/dashboard"
      onClick={onNavigate}
      className="flex shrink-0 items-center gap-3 border-b border-sidebar-border px-2 pb-4"
    >
      <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/15 text-primary ring-1 ring-primary/25">
        <Shield className="h-5 w-5" aria-hidden />
      </div>
      <div className="flex flex-col leading-tight">
        <span className="text-lg font-bold tracking-tight text-sidebar-foreground">
          Pepper
        </span>
        <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
          Security
        </span>
      </div>
    </Link>
  );
}

export function Sidebar() {
  return (
    <aside className="hidden lg:fixed lg:inset-y-0 lg:z-50 lg:flex lg:w-64 lg:flex-col">
      <div className="flex grow flex-col gap-y-4 overflow-y-auto border-r border-sidebar-border bg-sidebar px-4 pb-4 pt-5 shadow-sm">
        <SidebarBrand />
        <SidebarNav className="flex-1 px-1" />
      </div>
    </aside>
  );
}
