"use client";

import { useState, useEffect } from "react";
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
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";
import { toast } from "sonner";

export default function ProfilePage() {
  const { data: session, update: updateSession } = useSession();
  const [organizationName, setOrganizationName] = useState("");
  const [loading, setLoading] = useState(false);
  const [isEditing, setIsEditing] = useState(false);

  useEffect(() => {
    if (session?.user?.memberships?.[0]?.organizationName) {
      setOrganizationName(session.user.memberships[0].organizationName);
    }
  }, [session]);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    if (!organizationName.trim()) {
      toast.error("Organization name cannot be empty");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/api/organization", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: organizationName }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || "Failed to update organization");
      }

      // Refresh the session to get updated organization name
      const result = await updateSession();

      if (result?.user?.memberships?.[0]?.organizationName === organizationName) {
        toast.success("Organization name updated");
      } else {
        toast.success("Organization name updated. Refresh the page if dashboard doesn't update immediately.");
      }
      setIsEditing(false);
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to update organization"
      );
    } finally {
      setLoading(false);
    }
  }

  const userEmail = session?.user?.email || "Not available";
  const orgRole = session?.user?.memberships?.[0]?.role || "Unknown";

  return (
    <div className="max-w-2xl space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Profile" },
        ]}
      />
      <div>
        <h1 className="text-2xl font-bold">Profile Settings</h1>
        <p className="text-muted-foreground">
          Manage your organization information
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Organization Details</CardTitle>
          <CardDescription>
            View and manage your organization information
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid gap-6">
            <div className="space-y-2">
              <Label>Organization Name</Label>
              {isEditing ? (
                <form onSubmit={handleSave} className="space-y-2">
                  <Input
                    value={organizationName}
                    onChange={(e) => setOrganizationName(e.target.value)}
                    placeholder="Enter organization name"
                  />
                  <div className="flex gap-2">
                    <Button
                      type="submit"
                      disabled={loading}
                      size="sm"
                    >
                      {loading ? "Saving..." : "Save"}
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setIsEditing(false);
                        if (session?.user?.memberships?.[0]?.organizationName) {
                          setOrganizationName(
                            session.user.memberships[0].organizationName
                          );
                        }
                      }}
                      disabled={loading}
                    >
                      Cancel
                    </Button>
                  </div>
                </form>
              ) : (
                <div className="flex items-center justify-between">
                  <p className="text-sm">{organizationName || "Not set"}</p>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => setIsEditing(true)}
                  >
                    Edit
                  </Button>
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Account Information</CardTitle>
          <CardDescription>
            Your account details in this organization
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4">
            <div className="space-y-1">
              <p className="text-xs font-semibold text-muted-foreground uppercase">
                Email
              </p>
              <p className="text-sm">{userEmail}</p>
            </div>
            <div className="space-y-1">
              <p className="text-xs font-semibold text-muted-foreground uppercase">
                Role
              </p>
              <p className="text-sm font-medium">{orgRole}</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
