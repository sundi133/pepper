"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import {
  Shield,
  LayoutDashboard,
  FolderOpen,
  PlusCircle,
  Users,
  Zap,
  ShieldCheck,
  Webhook,
  ScrollText,
} from "lucide-react";

const navigation = [
  { name: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
  { name: "New Scan", href: "/scans/new", icon: PlusCircle },
  { name: "Projects", href: "/projects", icon: FolderOpen },
];

const settingsNav = [
  { name: "LLM Config", href: "/settings/llm", icon: Zap },
  { name: "Policies", href: "/settings/policies", icon: ScrollText },
  { name: "Build Gates", href: "/settings/build-gates", icon: ShieldCheck },
  { name: "Team", href: "/settings/team", icon: Users },
  { name: "Integrations", href: "/settings/integrations", icon: Webhook },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="hidden lg:fixed lg:inset-y-0 lg:z-50 lg:flex lg:w-64 lg:flex-col">
      <div className="flex grow flex-col gap-y-4 overflow-y-auto border-r border-sidebar-border bg-sidebar px-4 pb-4 pt-5 shadow-[4px_0_24px_-12px_rgba(0,0,0,0.5)]">
        <div className="flex shrink-0 items-center gap-3 border-b border-sidebar-border/80 px-2 pb-4">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/20 text-primary ring-1 ring-primary/30">
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
        </div>

        <nav className="flex flex-1 flex-col">
          <ul className="flex flex-1 flex-col gap-y-5">
            <li>
              <ul className="space-y-1">
                {navigation.map((item) => {
                  const isActive =
                    pathname === item.href ||
                    pathname.startsWith(`${item.href}/`);
                  return (
                    <li key={item.name}>
                      <Link
                        href={item.href}
                        className={cn(
                          "group flex gap-x-3 rounded-lg py-2.5 pl-3 pr-2 text-sm font-medium leading-6 transition-colors",
                          isActive
                            ? "border-l-2 border-primary bg-primary/15 text-primary shadow-sm"
                            : "border-l-2 border-transparent text-muted-foreground hover:bg-sidebar-accent/50 hover:text-sidebar-foreground",
                        )}
                      >
                        <item.icon
                          className={cn(
                            "h-5 w-5 shrink-0",
                            isActive
                              ? "text-primary"
                              : "text-muted-foreground group-hover:text-sidebar-foreground",
                          )}
                          aria-hidden
                        />
                        {item.name}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </li>

            <li>
              <div className="px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                Settings
              </div>
              <ul className="mt-2 space-y-1">
                {settingsNav.map((item) => {
                  const isActive = pathname === item.href;
                  return (
                    <li key={item.name}>
                      <Link
                        href={item.href}
                        className={cn(
                          "group flex gap-x-3 rounded-lg py-2.5 pl-3 pr-2 text-sm font-medium leading-6 transition-colors",
                          isActive
                            ? "border-l-2 border-primary bg-primary/15 text-primary shadow-sm"
                            : "border-l-2 border-transparent text-muted-foreground hover:bg-sidebar-accent/50 hover:text-sidebar-foreground",
                        )}
                      >
                        <item.icon
                          className={cn(
                            "h-5 w-5 shrink-0",
                            isActive
                              ? "text-primary"
                              : "text-muted-foreground group-hover:text-sidebar-foreground",
                          )}
                          aria-hidden
                        />
                        {item.name}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </li>
          </ul>
        </nav>
      </div>
    </aside>
  );
}
