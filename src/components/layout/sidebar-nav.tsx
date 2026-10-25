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
  FileText,
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
/**
 * "New scan" is an action, not a destination, so it renders as a prominent
 * button above the navigation rather than as a nav link.
 */
export const newScanAction: NavItem = {
  name: "New scan",
  href: "/scans/new",
  icon: PlusCircle,
};

export const navGroups: NavGroup[] = [
  {
    items: [{ name: "Overview", href: "/dashboard", icon: LayoutDashboard }],
  },
  {
    label: "Code Security",
    items: [
      { name: "Repositories", href: "/projects", icon: FolderOpen },
      { name: "Scans", href: "/scans", icon: ListChecks },
      { name: "Security Trends", href: "/trends", icon: TrendingUp },
    ],
  },
  {
    label: "Security Policies",
    items: [
      { name: "Security Policies", href: "/settings/policies", icon: ScrollText },
      { name: "Quality Gates", href: "/settings/build-gates", icon: ShieldCheck },
      { name: "Exceptions", href: "/settings/suppressions", icon: ShieldOff },
      { name: "Code Signing", href: "/settings/signing", icon: FileSignature },
    ],
  },
  {
    label: "Reporting",
    items: [
      { name: "Report Templates", href: "/settings/report-templates", icon: FileText },
    ],
  },
  {
    label: "Configuration",
    items: [
      { name: "AI Models", href: "/settings/llm", icon: Zap },
      { name: "Integrations", href: "/settings/integrations", icon: Webhook },
      { name: "API Keys", href: "/settings/apikeys", icon: KeyRound },
    ],
  },
  {
    label: "Organization",
    items: [
      { name: "Team & Access", href: "/settings/team", icon: Users },
      { name: "Audit Logs", href: "/settings/audit-log", icon: History },
    ],
  },
];

/** Pinned to the bottom: help is not a setting. */
export const footerNavigation: NavItem[] = [
  { name: "Documentation", href: "/settings/documentation", icon: BookOpen },
];

/** Every href the sidebar knows about, for active-state resolution. */
export const allNavHrefs: string[] = [
  newScanAction.href,
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
      {/* Primary action, surfaced as a button rather than a nav destination. */}
      <Link
        href={newScanAction.href}
        onClick={onNavigate}
        aria-current={activeHref === newScanAction.href ? "page" : undefined}
        className="flex items-center justify-center gap-2 rounded-lg bg-primary px-3 py-2 text-sm font-medium text-primary-foreground shadow-sm transition-colors hover:bg-primary/90"
      >
        <newScanAction.icon className="h-5 w-5 shrink-0" aria-hidden />
        {newScanAction.name}
      </Link>

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
