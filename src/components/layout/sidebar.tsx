"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import {
  Shield,
  LayoutDashboard,
  FolderOpen,
  Scan,
  Users,
  Zap,
  ShieldCheck,
  Webhook,
  ScrollText,
} from "lucide-react";

const navigation = [
  { name: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
  { name: "Projects", href: "/projects", icon: FolderOpen },
  { name: "Scans", href: "/scans", icon: Scan },
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
      <div className="flex grow flex-col gap-y-5 overflow-y-auto border-r border-border/80 bg-card px-6 pb-4 shadow-sm">
        <div className="flex shrink-0 items-center gap-2 border-b border-border/60 pb-4">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
            <Shield className="h-5 w-5" aria-hidden />
          </div>
          <div className="flex flex-col leading-tight">
            <span className="text-lg font-bold tracking-tight">Pepper</span>
            <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
              SAST
            </span>
          </div>
        </div>

        <nav className="flex flex-1 flex-col">
          <ul className="flex flex-1 flex-col gap-y-7">
            <li>
              <ul className="-mx-2 space-y-0.5">
                {navigation.map((item) => {
                  const isActive = pathname.startsWith(item.href);
                  return (
                    <li key={item.name}>
                      <Link
                        href={item.href}
                        className={cn(
                          "flex gap-x-3 rounded-lg px-2.5 py-2 text-sm font-medium leading-6 transition-colors duration-150",
                          isActive
                            ? "bg-primary/12 text-primary shadow-sm ring-1 ring-primary/15"
                            : "text-muted-foreground hover:bg-muted/80 hover:text-foreground",
                        )}
                      >
                        <item.icon
                          className={cn(
                            "h-5 w-5 shrink-0 transition-opacity",
                            isActive ? "opacity-100" : "opacity-80",
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
              <div className="px-2.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                Settings
              </div>
              <ul className="-mx-2 mt-2 space-y-0.5">
                {settingsNav.map((item) => {
                  const isActive = pathname === item.href;
                  return (
                    <li key={item.name}>
                      <Link
                        href={item.href}
                        className={cn(
                          "flex gap-x-3 rounded-lg px-2.5 py-2 text-sm font-medium leading-6 transition-colors duration-150",
                          isActive
                            ? "bg-primary/12 text-primary shadow-sm ring-1 ring-primary/15"
                            : "text-muted-foreground hover:bg-muted/80 hover:text-foreground",
                        )}
                      >
                        <item.icon
                          className={cn(
                            "h-5 w-5 shrink-0 transition-opacity",
                            isActive ? "opacity-100" : "opacity-80",
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
