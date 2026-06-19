"use client";

import { useEffect, useState } from "react";
import { useRouter, useParams } from "next/navigation";
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { ArrowLeft, Trash2, Users, Calendar, Mail, Shield } from "lucide-react";
import Link from "next/link";
import { toast } from "sonner";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

type OrgMember = {
  id: string;
  user: {
    id: string;
    email: string;
    name: string | null;
  };
  role: "ADMIN" | "SECURITY" | "DEVELOPER" | "VIEWER";
  createdAt: string;
};

type Organization = {
  id: string;
  name: string;
  slug: string;
  createdAt: string;
  members: OrgMember[];
};

type SystemUser = {
  id: string;
  email: string;
  name: string | null;
  createdAt: string;
};

const ROLES = ["ADMIN", "SECURITY", "DEVELOPER", "VIEWER"] as const;
const ROLE_DESCRIPTIONS: Record<string, string> = {
  ADMIN: "Full control: manage members, settings, and organization",
  SECURITY: "Manage security policies and review findings",
  DEVELOPER: "Create scans and view findings",
  VIEWER: "Read-only access to findings and reports",
};

export default function OrgManagePage() {
  const router = useRouter();
  const params = useParams();
  const orgId = params.orgId as string;

  const [org, setOrg] = useState<Organization | null>(null);
  const [allUsers, setAllUsers] = useState<SystemUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [deletingMemberId, setDeletingMemberId] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<{
    memberId: string;
    email: string;
  } | null>(null);
  const [updatingRoleId, setUpdatingRoleId] = useState<string | null>(null);
  const [addingUserId, setAddingUserId] = useState<string | null>(null);
  const [selectedRole, setSelectedRole] = useState("DEVELOPER");

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [orgRes, usersRes] = await Promise.all([
          fetch(`/api/admin/organizations/${orgId}`),
          fetch("/api/admin/users"),
        ]);

        if (!orgRes.ok) {
          toast.error("Organization not found");
          router.push("/admin");
          return;
        }

        const orgData = await orgRes.json();
        setOrg(orgData.organization);

        if (usersRes.ok) {
          const usersData = await usersRes.json();
          setAllUsers(usersData.users || []);
        }
      } catch (error) {
        toast.error("Failed to load data");
        router.push("/admin");
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [orgId, router]);

  const handleDeleteMember = async () => {
    if (!deleteTarget) return;

    setDeletingMemberId(deleteTarget.memberId);
    try {
      const res = await fetch(
        `/api/admin/organizations/${orgId}/members/${deleteTarget.memberId}`,
        { method: "DELETE" }
      );
      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.error || "Failed to remove member");
      }

      if (org) {
        setOrg({
          ...org,
          members: org.members.filter((m) => m.id !== deleteTarget.memberId),
        });
      }

      toast.success("Member removed");
      setDeleteTarget(null);
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to remove member"
      );
    } finally {
      setDeletingMemberId(null);
    }
  };

  const handleRoleChange = async (memberId: string, newRole: string) => {
    setUpdatingRoleId(memberId);
    try {
      const res = await fetch(
        `/api/admin/organizations/${orgId}/members/${memberId}`,
        {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ role: newRole }),
        }
      );
      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.error || "Failed to update role");
      }

      if (org) {
        setOrg({
          ...org,
          members: org.members.map((m) =>
            m.id === memberId ? { ...m, role: newRole as OrgMember["role"] } : m
          ),
        });
      }

      toast.success("Role updated");
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to update role"
      );
    } finally {
      setUpdatingRoleId(null);
    }
  };

  const handleAddUser = async (userId: string) => {
    setAddingUserId(userId);
    try {
      const res = await fetch(`/api/admin/organizations/assign`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userId,
          organizationId: orgId,
          role: selectedRole,
        }),
      });
      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.error || "Failed to add user");
      }

      // Refresh organization data
      const refreshRes = await fetch(`/api/admin/organizations/${orgId}`);
      if (refreshRes.ok) {
        const refreshData = await refreshRes.json();
        setOrg(refreshData.organization);
      }

      toast.success("User added to organization");
      setAddingUserId(null);
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to add user"
      );
    } finally {
      setAddingUserId(null);
    }
  };

  // Get users not in the organization
  const usersNotInOrg = allUsers.filter(
    (user) => !org?.members.some((m) => m.user.id === user.id)
  );

  if (loading) {
    return <div className="p-8">Loading...</div>;
  }

  if (!org) {
    return <div className="p-8">Organization not found</div>;
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="px-8 py-6">
        <div className="mx-auto max-w-5xl space-y-6">
          {/* Header */}
          <div className="flex items-center gap-4">
            <Button
              variant="outline"
              size="icon"
              onClick={() => router.push("/admin")}
              className="h-10 w-10"
            >
              <ArrowLeft className="h-5 w-5" />
            </Button>
            <div className="space-y-1">
              <h1 className="text-3xl font-bold flex items-center gap-2">
                <Shield className="h-8 w-8 text-primary" />
                {org.name}
              </h1>
              <p className="text-muted-foreground">Super Admin - Manage organization members</p>
            </div>
          </div>

          {/* Organization Details */}
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            <Card className="border-border/60 bg-card/80">
              <CardContent className="pt-6">
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <p className="text-sm text-muted-foreground">Organization Slug</p>
                  </div>
                  <p className="font-mono font-medium text-lg">{org.slug}</p>
                </div>
              </CardContent>
            </Card>

            <Card className="border-border/60 bg-card/80">
              <CardContent className="pt-6">
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <Users className="h-4 w-4 text-primary" />
                    <p className="text-sm text-muted-foreground">Total Members</p>
                  </div>
                  <p className="text-2xl font-bold">{org.members.length}</p>
                </div>
              </CardContent>
            </Card>

            <Card className="border-border/60 bg-card/80">
              <CardContent className="pt-6">
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <Calendar className="h-4 w-4 text-primary" />
                    <p className="text-sm text-muted-foreground">Created</p>
                  </div>
                  <p className="font-medium">{new Date(org.createdAt).toLocaleDateString()}</p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Members Management */}
          <Card className="border-border/60">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Users className="h-5 w-5" />
                Team Members Management
              </CardTitle>
              <CardDescription>
                Change roles or remove members from the organization
              </CardDescription>
            </CardHeader>
            <CardContent>
              {org.members.length === 0 ? (
                <div className="text-center py-12">
                  <Users className="h-12 w-12 text-muted-foreground mx-auto mb-4 opacity-50" />
                  <p className="text-muted-foreground mb-2">No members in this organization yet</p>
                  <p className="text-xs text-muted-foreground">Members will appear here once added</p>
                </div>
              ) : (
                <div className="border rounded-lg overflow-hidden">
                  <Table>
                    <TableHeader>
                      <TableRow className="bg-muted/50">
                        <TableHead className="font-semibold">Email</TableHead>
                        <TableHead className="font-semibold">Name</TableHead>
                        <TableHead className="font-semibold">Role</TableHead>
                        <TableHead className="font-semibold">Joined</TableHead>
                        <TableHead className="text-right font-semibold">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {org.members.map((member) => (
                        <TableRow key={member.id} className="hover:bg-muted/30">
                          <TableCell className="font-medium font-mono text-sm">
                            {member.user.email}
                          </TableCell>
                          <TableCell>{member.user.name || "-"}</TableCell>
                          <TableCell>
                            <Select
                              value={member.role}
                              disabled={updatingRoleId === member.id}
                              onValueChange={(value) =>
                                void handleRoleChange(member.id, value)
                              }
                            >
                              <SelectTrigger className="h-8 w-[140px]">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                {ROLES.map((role) => (
                                  <SelectItem key={role} value={role}>
                                    <div className="flex flex-col">
                                      <span className="font-medium">{role}</span>
                                      <span className="text-xs text-muted-foreground">
                                        {ROLE_DESCRIPTIONS[role]}
                                      </span>
                                    </div>
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {new Date(member.createdAt).toLocaleDateString()}
                          </TableCell>
                          <TableCell className="text-right">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() =>
                                setDeleteTarget({
                                  memberId: member.id,
                                  email: member.user.email,
                                })
                              }
                              disabled={deletingMemberId === member.id}
                              className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>

          {/* System Users */}
          {usersNotInOrg.length > 0 && (
            <Card className="border-border/60">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Users className="h-5 w-5" />
                  Add Users to Organization
                </CardTitle>
                <CardDescription>
                  Available system users that are not yet members
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex gap-2 items-end">
                    <div className="flex-1">
                      <Label className="text-sm mb-2 block">Default Role</Label>
                      <Select value={selectedRole} onValueChange={setSelectedRole}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {ROLES.map((role) => (
                            <SelectItem key={role} value={role}>
                              {role}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="border rounded-lg overflow-hidden">
                    <Table>
                      <TableHeader>
                        <TableRow className="bg-muted/50">
                          <TableHead className="font-semibold">Email</TableHead>
                          <TableHead className="font-semibold">Name</TableHead>
                          <TableHead className="font-semibold">Registered</TableHead>
                          <TableHead className="text-right font-semibold">Actions</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {usersNotInOrg.map((user) => (
                          <TableRow key={user.id} className="hover:bg-muted/30">
                            <TableCell className="font-medium font-mono text-sm">
                              {user.email}
                            </TableCell>
                            <TableCell>{user.name || "-"}</TableCell>
                            <TableCell className="text-sm text-muted-foreground">
                              {new Date(user.createdAt).toLocaleDateString()}
                            </TableCell>
                            <TableCell className="text-right">
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => void handleAddUser(user.id)}
                                disabled={addingUserId === user.id}
                              >
                                {addingUserId === user.id ? "Adding..." : "Add"}
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Role Reference */}
          <Card className="border-border/60 bg-muted/20">
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Shield className="h-4 w-4" />
                Role Descriptions
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                {ROLES.map((role) => (
                  <div key={role} className="space-y-1 p-3 rounded-lg bg-background/50 border border-border/40">
                    <p className="font-semibold text-sm">{role}</p>
                    <p className="text-xs text-muted-foreground">{ROLE_DESCRIPTIONS[role]}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open && !deletingMemberId) setDeleteTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Remove member?</DialogTitle>
            <DialogDescription>
              Remove{" "}
              <span className="font-medium text-foreground">
                {deleteTarget?.email}
              </span>{" "}
              from this organization?
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              disabled={!!deletingMemberId}
              onClick={() => setDeleteTarget(null)}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={!!deletingMemberId}
              onClick={() => void handleDeleteMember()}
            >
              {deletingMemberId ? "Removing..." : "Remove"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
