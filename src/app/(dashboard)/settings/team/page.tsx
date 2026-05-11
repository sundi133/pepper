"use client";

import { useState, useEffect, useMemo } from "react";
import { useSession } from "next-auth/react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Trash2, UserPlus } from "lucide-react";
import Link from "next/link";
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

const ORG_ROLES = [
  { value: "ADMIN", label: "Admin" },
  { value: "SECURITY", label: "Security" },
  { value: "DEVELOPER", label: "Developer" },
  { value: "VIEWER", label: "Viewer" },
] as const;

export default function TeamPage() {
  const { data: session } = useSession();
  const [members, setMembers] = useState<Array<Record<string, unknown>>>([]);
  const [loading, setLoading] = useState(false);
  const [removingId, setRemovingId] = useState<string | null>(null);
  const [removeTarget, setRemoveTarget] = useState<{
    memberId: string;
    email: string;
  } | null>(null);
  const [roleUpdatingId, setRoleUpdatingId] = useState<string | null>(null);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState("DEVELOPER");
  const [password, setPassword] = useState("");

  useEffect(() => {
    fetch("/api/users")
      .then((res) => res.json())
      .then((data) => setMembers(data.members || []));
  }, []);

  const orgRole = session?.user?.memberships?.[0]?.role;
  const isOrgAdmin = orgRole === "ADMIN";
  const adminCount = useMemo(
    () => members.filter((m) => m.role === "ADMIN").length,
    [members],
  );

  async function confirmRemoveMember() {
    if (!removeTarget) return;

    setRemovingId(removeTarget.memberId);
    try {
      const res = await fetch(`/api/users/${removeTarget.memberId}`, {
        method: "DELETE",
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || "Failed to remove member");
      }
      toast.success("Member removed");
      setRemoveTarget(null);
      const refreshed = await fetch("/api/users").then((r) => r.json());
      setMembers(refreshed.members || []);
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to remove member",
      );
    } finally {
      setRemovingId(null);
    }
  }

  async function handleRoleChange(
    memberId: string,
    memberUserId: string,
    newRole: string,
  ) {
    setRoleUpdatingId(memberId);
    try {
      const res = await fetch(`/api/users/${memberId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ role: newRole }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || "Failed to update role");
      }
      toast.success("Role updated");
      const refreshed = await fetch("/api/users").then((r) => r.json());
      setMembers(refreshed.members || []);
      if (session?.user?.id === memberUserId) {
        toast.info("Sign out and back in if your own role changed.");
      }
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to update role",
      );
    } finally {
      setRoleUpdatingId(null);
    }
  }

  async function handleInvite(e: React.FormEvent) {
    e.preventDefault();
    if (!email || password.length < 8) {
      toast.error("Email and an initial password of at least 8 characters are required");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/api/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          name,
          role,
          password,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Failed to invite");

      toast.success("User invited");
      setEmail("");
      setName("");
      setPassword("");

      // Refresh members
      const refreshed = await fetch("/api/users").then((r) => r.json());
      setMembers(refreshed.members || []);
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to invite user",
      );
    } finally {
      setLoading(false);
    }
  }

  const roleColors: Record<
    string,
    "default" | "secondary" | "outline" | "destructive"
  > = {
    ADMIN: "destructive",
    SECURITY: "default",
    DEVELOPER: "secondary",
    VIEWER: "outline",
  };

  return (
    <div className="max-w-4xl space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Team" },
        ]}
      />
      <div>
        <h1 className="text-2xl font-bold">Team Management</h1>
        <p className="text-muted-foreground">
          Manage team members and their roles
        </p>
        <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
          There is no public sign-up page. New users are created here: fill{" "}
          <strong>Invite Member</strong> with their email, role, and an initial
          password (at least 8 characters). They sign in at{" "}
          <Link href="/login" className="font-medium text-foreground underline">
            /login
          </Link>{" "}
          with that email and password. When SMTP is configured (see{" "}
          <code className="rounded bg-muted px-1 py-0.5 text-xs">.env</code>
          ), <strong>new</strong> accounts receive an invitation email with
          sign-in link, email address, and initial password. Email is not a
          secure channel—use Mailpit, internal relay, or trusted mail only.
          Existing users added to the org get an email without a new password
          (their password is unchanged).
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Invite Member</CardTitle>
          <CardDescription>
            Add a new member to your organization
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleInvite} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Email *</Label>
                <Input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="user@example.com"
                  required
                />
              </div>
              <div className="space-y-2">
                <Label>Name</Label>
                <Input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="John Doe"
                />
              </div>
              <div className="space-y-2">
                <Label>Role</Label>
                <Select value={role} onValueChange={setRole}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {ORG_ROLES.map((r) => (
                      <SelectItem key={r.value} value={r.value}>
                        {r.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Password</Label>
                <Input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Initial password"
                  minLength={8}
                  required
                />
                <p className="text-xs text-muted-foreground">
                  Required for first login. Minimum 8 characters.
                </p>
              </div>
            </div>
            <Button type="submit" disabled={loading}>
              <UserPlus className="mr-2 h-4 w-4" />
              {loading ? "Inviting..." : "Invite Member"}
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Team Members</CardTitle>
          <CardDescription>
            {isOrgAdmin
              ? "Change roles from the table or remove members from the organization."
              : "Only organization admins can change roles or remove members."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Joined</TableHead>
                {isOrgAdmin ? (
                  <TableHead className="w-[72px] text-right">Actions</TableHead>
                ) : null}
              </TableRow>
            </TableHeader>
            <TableBody>
              {members.map((member) => {
                const user = member.user as Record<string, unknown>;
                const userId = user.id as string;
                const memberEmail = user.email as string;
                const memberId = member.id as string;
                const currentRole = member.role as string;
                const isSoleAdminSelf =
                  member.role === "ADMIN" &&
                  adminCount === 1 &&
                  session?.user?.id === userId;
                const cannotDemoteLastAdmin =
                  member.role === "ADMIN" && adminCount === 1;
                const removeDisabled =
                  removingId === memberId || isSoleAdminSelf;
                const roleBusy = roleUpdatingId === memberId;

                return (
                  <TableRow key={memberId}>
                    <TableCell className="font-medium">
                      {(user.name as string) || "Unnamed"}
                    </TableCell>
                    <TableCell>{memberEmail}</TableCell>
                    <TableCell>
                      {isOrgAdmin && !cannotDemoteLastAdmin ? (
                        <Select
                          value={currentRole}
                          disabled={roleBusy}
                          onValueChange={(value) =>
                            handleRoleChange(memberId, userId, value)
                          }
                        >
                          <SelectTrigger className="h-8 w-[140px]">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {ORG_ROLES.map((r) => (
                              <SelectItem key={r.value} value={r.value}>
                                {r.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      ) : (
                        <Badge
                          variant={
                            roleColors[currentRole] || "outline"
                          }
                        >
                          {currentRole}
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {new Date(
                        member.createdAt as string,
                      ).toLocaleDateString()}
                    </TableCell>
                    {isOrgAdmin ? (
                      <TableCell className="text-right">
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                          disabled={removeDisabled}
                          aria-label={`Remove ${memberEmail} from team`}
                          title={
                            isSoleAdminSelf
                              ? "Add another admin before removing yourself"
                              : "Remove from organization"
                          }
                          onClick={() =>
                            setRemoveTarget({ memberId, email: memberEmail })
                          }
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    ) : null}
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog
        open={removeTarget !== null}
        onOpenChange={(open) => {
          if (!open && !removingId) setRemoveTarget(null);
        }}
      >
        <DialogContent
          showCloseButton={!removingId}
          onPointerDownOutside={(e) => {
            if (removingId) e.preventDefault();
          }}
          onEscapeKeyDown={(e) => {
            if (removingId) e.preventDefault();
          }}
        >
          <DialogHeader>
            <DialogTitle>Remove member?</DialogTitle>
            <DialogDescription>
              Remove{" "}
              <span className="font-medium text-foreground">
                {removeTarget?.email ?? ""}
              </span>{" "}
              from this organization? They will lose access until invited again.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              disabled={!!removingId}
              onClick={() => setRemoveTarget(null)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={!!removingId}
              onClick={() => void confirmRemoveMember()}
            >
              {removingId ? "Removing…" : "Remove member"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
