"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import {
  LayoutDashboard,
  FolderOpen,
  Github,
  PlusCircle,
  Users,
  Zap,
  ShieldCheck,
  Webhook,
  ScrollText,
  BookOpen,
  type LucideIcon,
} from "lucide-react";

type NavItem = { name: string; href: string; icon: LucideIcon };

export const mainNavigation: NavItem[] = [
  { name: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
  { name: "New Scan", href: "/scans/new", icon: PlusCircle },
  { name: "Projects", href: "/projects", icon: FolderOpen },
  { name: "Repositories", href: "/repositories", icon: Github },
];

export const settingsNavigation: NavItem[] = [
  { name: "LLM Config", href: "/settings/llm", icon: Zap },
  { name: "Policies", href: "/settings/policies", icon: ScrollText },
  { name: "Build Gates", href: "/settings/build-gates", icon: ShieldCheck },
  { name: "Team", href: "/settings/team", icon: Users },
  { name: "Integrations", href: "/settings/integrations", icon: Webhook },
  { name: "Documentation", href: "/settings/documentation", icon: BookOpen },
];

function isNavActive(pathname: string, href: string, exact?: boolean) {
  if (exact) return pathname === href;
  return pathname === href || pathname.startsWith(`${href}/`);
}

export function SidebarNav({
  className,
  onNavigate,
}: {
  className?: string;
  onNavigate?: () => void;
}) {
  const pathname = usePathname();

  return (
    <nav className={cn("flex flex-col gap-5", className)}>
      <ul className="space-y-0.5">
        {mainNavigation.map((item) => {
          const active = isNavActive(pathname, item.href);
          return (
            <li key={item.href}>
              <Link
                href={item.href}
                onClick={onNavigate}
                className={cn(
                  "group flex gap-x-3 rounded-lg py-2.5 pl-3 pr-2 text-sm font-medium transition-colors",
                  active
                    ? "border-l-2 border-primary bg-primary/10 text-primary"
                    : "border-l-2 border-transparent text-muted-foreground hover:bg-muted/80 hover:text-foreground",
                )}
              >
                <item.icon
                  className={cn(
                    "h-5 w-5 shrink-0",
                    active ? "text-primary" : "text-muted-foreground group-hover:text-foreground",
                  )}
                  aria-hidden
                />
                {item.name}
              </Link>
            </li>
          );
        })}
      </ul>

      <div>
        <p className="mb-2 px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
          Settings
        </p>
        <ul className="space-y-0.5">
          {settingsNavigation.map((item) => {
            const active = isNavActive(pathname, item.href, true);
            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  onClick={onNavigate}
                  className={cn(
                    "group flex gap-x-3 rounded-lg py-2.5 pl-3 pr-2 text-sm font-medium transition-colors",
                    active
                      ? "border-l-2 border-primary bg-primary/10 text-primary"
                      : "border-l-2 border-transparent text-muted-foreground hover:bg-muted/80 hover:text-foreground",
                  )}
                >
                  <item.icon
                    className={cn(
                      "h-5 w-5 shrink-0",
                      active
                        ? "text-primary"
                        : "text-muted-foreground group-hover:text-foreground",
                    )}
                    aria-hidden
                  />
                  {item.name}
                </Link>
              </li>
            );
          })}
        </ul>
      </div>
    </nav>
  );
}
