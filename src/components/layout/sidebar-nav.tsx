"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { resolveActiveNavHref } from "@/lib/nav-active";
import {
  LayoutDashboard,
  FolderOpen,
  PlusCircle,
  ListChecks,
  Users,
  Zap,
  ShieldCheck,
  Webhook,
  ScrollText,
  BookOpen,
  TrendingUp,
  KeyRound,
  History,
  FileSignature,
  ShieldOff,
  type LucideIcon,
} from "lucide-react";

type NavItem = { name: string; href: string; icon: LucideIcon };
type NavGroup = { label?: string; items: NavItem[] };

/**
 * Sidebar structure.
 *
 * Grouped so that day-to-day work, the rules that govern it, and platform
 * configuration are distinguishable. "Settings" previously held all ten
 * non-primary entries, mixing security policy with credentials, an audit record
 * and the documentation link.
 */
export const navGroups: NavGroup[] = [
  {
    items: [{ name: "Dashboard", href: "/dashboard", icon: LayoutDashboard }],
  },
  {
    label: "Security",
    items: [
      // An action, not a section — the old label was just "Scan", which read as
      // a peer of Projects while actually opening a create form.
      { name: "New scan", href: "/scans/new", icon: PlusCircle },
      { name: "Projects", href: "/projects", icon: FolderOpen },
      // Previously unreachable: nothing in the UI linked to /scans, so the list
      // holding retry and delete could only be reached by typing the URL.
      { name: "Scans", href: "/scans", icon: ListChecks },
      { name: "Trends", href: "/trends", icon: TrendingUp },
    ],
  },
  {
    label: "Policy",
    items: [
      { name: "Policies", href: "/settings/policies", icon: ScrollText },
      { name: "Build Gates", href: "/settings/build-gates", icon: ShieldCheck },
      { name: "Suppressions", href: "/settings/suppressions", icon: ShieldOff },
      { name: "Code Signing", href: "/settings/signing", icon: FileSignature },
    ],
  },
  {
    label: "Configuration",
    items: [
      { name: "LLM Config", href: "/settings/llm", icon: Zap },
      { name: "Integrations", href: "/settings/integrations", icon: Webhook },
      { name: "API Keys", href: "/settings/apikeys", icon: KeyRound },
      { name: "Team", href: "/settings/team", icon: Users },
      { name: "Audit Log", href: "/settings/audit-log", icon: History },
    ],
  },
];

/** Pinned to the bottom: help is not a setting. */
export const footerNavigation: NavItem[] = [
  { name: "Documentation", href: "/settings/documentation", icon: BookOpen },
];

/** Every href the sidebar knows about, for active-state resolution. */
export const allNavHrefs: string[] = [
  ...navGroups.flatMap((g) => g.items.map((i) => i.href)),
  ...footerNavigation.map((i) => i.href),
];

function NavLink({
  item,
  active,
  onNavigate,
}: {
  item: NavItem;
  active: boolean;
  onNavigate?: () => void;
}) {
  return (
    <li>
      <Link
        href={item.href}
        onClick={onNavigate}
        aria-current={active ? "page" : undefined}
        className={cn(
          "nav-link group",
          active ? "nav-link-active" : "nav-link-inactive",
        )}
      >
        <item.icon
          className={cn(
            "h-5 w-5 shrink-0",
            active
              ? "text-primary"
              : "text-muted-foreground transition-colors group-hover:text-primary",
          )}
          aria-hidden
        />
        {item.name}
      </Link>
    </li>
  );
}

export function SidebarNav({
  className,
  onNavigate,
}: {
  className?: string;
  onNavigate?: () => void;
}) {
  const pathname = usePathname();
  // Resolved once across every entry so the most specific match wins.
  const activeHref = resolveActiveNavHref(pathname, allNavHrefs);

  return (
    <nav className={cn("flex flex-col gap-5", className)}>
      {navGroups.map((group, index) => (
        <div key={group.label ?? `group-${index}`}>
          {group.label ? (
            <p className="mb-2 px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              {group.label}
            </p>
          ) : null}
          <ul className="space-y-0.5">
            {group.items.map((item) => (
              <NavLink
                key={item.href}
                item={item}
                active={activeHref === item.href}
                onNavigate={onNavigate}
              />
            ))}
          </ul>
        </div>
      ))}

      <ul className="mt-auto space-y-0.5 border-t border-border/40 pt-3">
        {footerNavigation.map((item) => (
          <NavLink
            key={item.href}
            item={item}
            active={activeHref === item.href}
            onNavigate={onNavigate}
          />
        ))}
      </ul>
    </nav>
  );
}
