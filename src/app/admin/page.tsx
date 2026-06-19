"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Users,
  Building2,
  Trash2,
  Eye,
  Calendar,
  Mail,
  Shield,
  Search,
  BarChart3,
} from "lucide-react";
import Link from "next/link";
import { toast } from "sonner";

type Organization = {
  id: string;
  name: string;
  slug: string;
  createdAt: string;
  memberCount: number;
};

type User = {
  id: string;
  email: string;
  name: string | null;
  createdAt: string;
};

export default function AdminPage() {
  const router = useRouter();
  const { data: session } = useSession();
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [orgSearch, setOrgSearch] = useState("");
  const [userSearch, setUserSearch] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<{
    type: "org" | "user";
    id: string;
    name: string;
  } | null>(null);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    const checkSuperAdmin = async () => {
      try {
        const res = await fetch("/api/admin/verify");
        if (!res.ok) {
          router.push("/");
        }
      } catch {
        router.push("/");
      }
    };
    checkSuperAdmin();
  }, [router]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [orgsRes, usersRes] = await Promise.all([
          fetch("/api/admin/organizations"),
          fetch("/api/admin/users"),
        ]);

        if (orgsRes.ok) {
          const data = await orgsRes.json();
          setOrganizations(data.organizations || []);
        }

        if (usersRes.ok) {
          const data = await usersRes.json();
          setUsers(data.users || []);
        }
      } catch (error) {
        console.error("Error fetching data:", error);
        toast.error("Failed to load data");
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const handleDelete = async () => {
    if (!deleteTarget) return;

    setDeleting(true);
    try {
      const endpoint =
        deleteTarget.type === "org"
          ? `/api/admin/organizations/${deleteTarget.id}`
          : `/api/admin/users/${deleteTarget.id}`;

      const res = await fetch(endpoint, { method: "DELETE" });
      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.error || "Failed to delete");
      }

      if (deleteTarget.type === "org") {
        setOrganizations(
          organizations.filter((o) => o.id !== deleteTarget.id)
        );
      } else {
        setUsers(users.filter((u) => u.id !== deleteTarget.id));
      }

      toast.success(
        `${deleteTarget.type === "org" ? "Organization" : "User"} deleted`
      );
      setDeleteTarget(null);
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to delete"
      );
    } finally {
      setDeleting(false);
    }
  };

  const filteredOrgs = organizations.filter((org) =>
    org.name.toLowerCase().includes(orgSearch.toLowerCase()) ||
    org.slug.toLowerCase().includes(orgSearch.toLowerCase())
  );

  const filteredUsers = users.filter((user) =>
    user.email.toLowerCase().includes(userSearch.toLowerCase()) ||
    (user.name?.toLowerCase().includes(userSearch.toLowerCase()) ?? false)
  );

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="px-8 py-6">
        <div className="mx-auto max-w-7xl space-y-8">
          {/* Header */}
          <div className="space-y-2">
            <h1 className="text-4xl font-bold flex items-center gap-3">
              <Shield className="h-10 w-10 text-primary" />
              Super Admin Dashboard
            </h1>
            <p className="text-muted-foreground text-lg">
              Centralized management for all organizations and users
            </p>
          </div>

          {/* Quick Stats */}
          <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
            <Card className="border-border/60 bg-card/80">
              <CardContent className="pt-6">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <p className="text-sm text-muted-foreground">Organizations</p>
                    <Building2 className="h-4 w-4 text-primary" />
                  </div>
                  <p className="text-3xl font-bold">{organizations.length}</p>
                  <p className="text-xs text-muted-foreground">Total in system</p>
                </div>
              </CardContent>
            </Card>

            <Card className="border-border/60 bg-card/80">
              <CardContent className="pt-6">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <p className="text-sm text-muted-foreground">Total Users</p>
                    <Users className="h-4 w-4 text-primary" />
                  </div>
                  <p className="text-3xl font-bold">{users.length}</p>
                  <p className="text-xs text-muted-foreground">Registered</p>
                </div>
              </CardContent>
            </Card>

            <Card className="border-border/60 bg-card/80">
              <CardContent className="pt-6">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <p className="text-sm text-muted-foreground">Avg Members</p>
                    <BarChart3 className="h-4 w-4 text-primary" />
                  </div>
                  <p className="text-3xl font-bold">
                    {organizations.length > 0
                      ? (
                          organizations.reduce((sum, org) => sum + org.memberCount, 0) /
                          organizations.length
                        ).toFixed(1)
                      : "0"}
                  </p>
                  <p className="text-xs text-muted-foreground">Per organization</p>
                </div>
              </CardContent>
            </Card>

            <Card className="border-border/60 bg-card/80">
              <CardContent className="pt-6">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <p className="text-sm text-muted-foreground">Total Members</p>
                    <Mail className="h-4 w-4 text-primary" />
                  </div>
                  <p className="text-3xl font-bold">
                    {organizations.reduce((sum, org) => sum + org.memberCount, 0)}
                  </p>
                  <p className="text-xs text-muted-foreground">Across all orgs</p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Tabs */}
          <Tabs defaultValue="organizations" className="w-full">
            <TabsList className="grid w-full grid-cols-2 lg:w-[400px]">
              <TabsTrigger value="organizations">Organizations</TabsTrigger>
              <TabsTrigger value="users">Users</TabsTrigger>
            </TabsList>

            {/* Organizations Tab */}
            <TabsContent value="organizations" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Building2 className="h-5 w-5" />
                    Manage Organizations
                  </CardTitle>
                  <CardDescription>
                    {filteredOrgs.length} organization{filteredOrgs.length !== 1 ? "s" : ""}
                    {orgSearch && ` matching "${orgSearch}"`}
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Search */}
                  <div className="flex gap-2">
                    <div className="flex-1 relative">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                      <Input
                        placeholder="Search by name or slug..."
                        value={orgSearch}
                        onChange={(e) => setOrgSearch(e.target.value)}
                        className="pl-10"
                      />
                    </div>
                  </div>

                  {/* Table */}
                  <div className="border rounded-lg overflow-hidden">
                    <Table>
                      <TableHeader>
                        <TableRow className="bg-muted/50">
                          <TableHead className="font-semibold">Name</TableHead>
                          <TableHead className="font-semibold">Slug</TableHead>
                          <TableHead className="font-semibold">Members</TableHead>
                          <TableHead className="font-semibold">Created</TableHead>
                          <TableHead className="text-right font-semibold">Actions</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredOrgs.length === 0 ? (
                          <TableRow>
                            <TableCell colSpan={5} className="text-center py-8">
                              <p className="text-muted-foreground">
                                {orgSearch
                                  ? "No organizations match your search"
                                  : "No organizations yet"}
                              </p>
                            </TableCell>
                          </TableRow>
                        ) : (
                          filteredOrgs.map((org) => (
                            <TableRow key={org.id} className="hover:bg-muted/30">
                              <TableCell className="font-medium">{org.name}</TableCell>
                              <TableCell className="text-muted-foreground font-mono text-sm">
                                {org.slug}
                              </TableCell>
                              <TableCell>
                                <Badge variant="secondary" className="font-semibold">
                                  {org.memberCount}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-sm text-muted-foreground">
                                {new Date(org.createdAt).toLocaleDateString()}
                              </TableCell>
                              <TableCell className="text-right">
                                <div className="flex justify-end gap-2">
                                  <Button
                                    asChild
                                    variant="outline"
                                    size="sm"
                                    className="gap-2"
                                  >
                                    <Link href={`/admin/organizations/${org.id}`}>
                                      <Eye className="h-4 w-4" />
                                      Manage
                                    </Link>
                                  </Button>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() =>
                                      setDeleteTarget({
                                        type: "org",
                                        id: org.id,
                                        name: org.name,
                                      })
                                    }
                                    className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                                  >
                                    <Trash2 className="h-4 w-4" />
                                  </Button>
                                </div>
                              </TableCell>
                            </TableRow>
                          ))
                        )}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Users Tab */}
            <TabsContent value="users" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Users className="h-5 w-5" />
                    Manage Users
                  </CardTitle>
                  <CardDescription>
                    {filteredUsers.length} user{filteredUsers.length !== 1 ? "s" : ""}
                    {userSearch && ` matching "${userSearch}"`}
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Search */}
                  <div className="flex gap-2">
                    <div className="flex-1 relative">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                      <Input
                        placeholder="Search by email or name..."
                        value={userSearch}
                        onChange={(e) => setUserSearch(e.target.value)}
                        className="pl-10"
                      />
                    </div>
                  </div>

                  {/* Table */}
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
                        {filteredUsers.length === 0 ? (
                          <TableRow>
                            <TableCell colSpan={4} className="text-center py-8">
                              <p className="text-muted-foreground">
                                {userSearch
                                  ? "No users match your search"
                                  : "No users yet"}
                              </p>
                            </TableCell>
                          </TableRow>
                        ) : (
                          filteredUsers.map((user) => (
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
                                  variant="ghost"
                                  size="sm"
                                  onClick={() =>
                                    setDeleteTarget({
                                      type: "user",
                                      id: user.id,
                                      name: user.email,
                                    })
                                  }
                                  className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                                >
                                  <Trash2 className="h-4 w-4" />
                                </Button>
                              </TableCell>
                            </TableRow>
                          ))
                        )}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </div>

      {/* Delete Dialog */}
      <Dialog open={deleteTarget !== null} onOpenChange={(open) => {
        if (!open && !deleting) setDeleteTarget(null);
      }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete {deleteTarget?.type === "org" ? "Organization" : "User"}?</DialogTitle>
            <DialogDescription>
              This will permanently delete{" "}
              <span className="font-semibold text-foreground">
                {deleteTarget?.name}
              </span>
              . This action cannot be undone.
              {deleteTarget?.type === "org" && (
                <p className="mt-2 text-xs">
                  All members and projects in this organization will also be deleted.
                </p>
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              disabled={deleting}
              onClick={() => setDeleteTarget(null)}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={deleting}
              onClick={() => void handleDelete()}
            >
              {deleting ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
