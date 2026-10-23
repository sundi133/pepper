"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useSession } from "next-auth/react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Building2, Check, ChevronsUpDown } from "lucide-react";
import { toast } from "sonner";

/**
 * Lets a user who belongs to more than one organisation choose which one they
 * are currently working in. The selection is stored server-side in the
 * `active_org` cookie (see POST /api/org/active); after switching we refresh so
 * every server component re-resolves against the new active org.
 *
 * Renders nothing for single-org users, so their experience is unchanged.
 */
export function OrgSwitcher({ activeOrgId }: { activeOrgId?: string | null }) {
  const { data: session } = useSession();
  const router = useRouter();
  const [switching, setSwitching] = useState(false);

  const memberships = session?.user?.memberships ?? [];
  if (memberships.length <= 1) return null;

  const active =
    memberships.find((m) => m.organizationId === activeOrgId) ?? memberships[0];
  const activeName =
    active.organizationName || active.organizationSlug || "Organization";

  async function selectOrg(organizationId: string) {
    if (organizationId === active.organizationId || switching) return;
    setSwitching(true);
    try {
      const res = await fetch("/api/org/active", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ organizationId }),
      });
      if (!res.ok) {
        toast.error("Could not switch organization");
        return;
      }
      // Re-resolve server components (settings, scans, dashboard) for the new org.
      router.refresh();
    } catch {
      toast.error("Could not switch organization");
    } finally {
      setSwitching(false);
    }
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-9 max-w-[12rem] gap-2 border-border/80 bg-muted/40 px-2.5 font-medium text-foreground hover:bg-card"
          disabled={switching}
          aria-label="Switch organization"
        >
          <Building2 className="h-4 w-4 shrink-0 text-primary" aria-hidden />
          <span className="truncate">{activeName}</span>
          <ChevronsUpDown
            className="ml-auto h-4 w-4 shrink-0 text-muted-foreground"
            aria-hidden
          />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="min-w-[14rem]">
        <DropdownMenuLabel>Organizations</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {memberships.map((m) => {
          const isActive = m.organizationId === active.organizationId;
          return (
            <DropdownMenuItem
              key={m.organizationId}
              onClick={() => selectOrg(m.organizationId)}
              className="gap-2"
            >
              <Building2
                className="h-4 w-4 shrink-0 text-muted-foreground"
                aria-hidden
              />
              <span className="truncate">
                {m.organizationName || m.organizationSlug || m.organizationId}
              </span>
              {isActive ? (
                <Check className="ml-auto h-4 w-4 shrink-0 text-primary" aria-hidden />
              ) : null}
            </DropdownMenuItem>
          );
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
