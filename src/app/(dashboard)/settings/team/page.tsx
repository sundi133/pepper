"use client";

import { useState, useEffect } from "react";
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
import { UserPlus } from "lucide-react";
import { toast } from "sonner";

export default function TeamPage() {
  const [members, setMembers] = useState<Array<Record<string, unknown>>>([]);
  const [loading, setLoading] = useState(false);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState("DEVELOPER");
  const [password, setPassword] = useState("");

  useEffect(() => {
    fetch("/api/users")
      .then((res) => res.json())
      .then((data) => setMembers(data.members || []));
  }, []);

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
    <div className="max-w-3xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Team Management</h1>
        <p className="text-muted-foreground">
          Manage team members and their roles
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
                    <SelectItem value="ADMIN">Admin</SelectItem>
                    <SelectItem value="SECURITY">Security</SelectItem>
                    <SelectItem value="DEVELOPER">Developer</SelectItem>
                    <SelectItem value="VIEWER">Viewer</SelectItem>
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
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Joined</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {members.map((member) => {
                const user = member.user as Record<string, unknown>;
                return (
                  <TableRow key={member.id as string}>
                    <TableCell className="font-medium">
                      {(user.name as string) || "Unnamed"}
                    </TableCell>
                    <TableCell>{user.email as string}</TableCell>
                    <TableCell>
                      <Badge
                        variant={roleColors[member.role as string] || "outline"}
                      >
                        {member.role as string}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {new Date(
                        member.createdAt as string,
                      ).toLocaleDateString()}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
