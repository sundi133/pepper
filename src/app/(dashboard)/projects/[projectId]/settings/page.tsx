"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { toast } from "sonner";
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
import { Textarea } from "@/components/ui/textarea";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

type ProjectSettings = {
  id: string;
  name: string;
  description: string | null;
};

export default function ProjectSettingsPage() {
  const params = useParams();
  const router = useRouter();
  const projectId = params.projectId as string;

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [crumbProjectName, setCrumbProjectName] = useState("Project");
  const [nameTouched, setNameTouched] = useState(false);
  const [submitAttempted, setSubmitAttempted] = useState(false);

  const nameError =
    !name.trim() && (nameTouched || submitAttempted)
      ? "Project name is required."
      : null;

  useEffect(() => {
    let mounted = true;

    async function loadProject() {
      try {
        const res = await fetch(`/api/projects/${projectId}`);
        if (!res.ok) throw new Error("Failed to load project");

        const project = (await res.json()) as ProjectSettings;
        if (!mounted) return;

        setName(project.name || "");
        setDescription(project.description || "");
        setCrumbProjectName(project.name || "Project");
      } catch (error) {
        toast.error(
          error instanceof Error ? error.message : "Failed to load project",
        );
      } finally {
        if (mounted) setLoading(false);
      }
    }

    loadProject();
    return () => {
      mounted = false;
    };
  }, [projectId]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitAttempted(true);
    if (!name.trim()) {
      toast.error("Project name is required");
      return;
    }

    setSaving(true);
    try {
      const res = await fetch(`/api/projects/${projectId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name.trim(),
          description: description.trim() || "",
        }),
      });

      if (!res.ok) throw new Error("Failed to update project");

      toast.success("Project updated");
      router.push(`/projects/${projectId}`);
      router.refresh();
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to update project",
      );
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <div className="max-w-2xl space-y-6">
        <PageBreadcrumb
          items={[
            { label: "Dashboard", href: "/dashboard" },
            { label: "Projects", href: "/projects" },
            { label: crumbProjectName, href: `/projects/${projectId}` },
            { label: "Settings" },
          ]}
        />
        <p className="py-12 text-center text-muted-foreground">Loading...</p>
      </div>
    );
  }

  return (
    <div className="max-w-2xl space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Projects", href: "/projects" },
          { label: crumbProjectName, href: `/projects/${projectId}` },
          { label: "Settings" },
        ]}
      />
      <div className="flex items-center gap-3">
        <Link href={`/projects/${projectId}`}>
          <Button variant="outline" size="sm">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back
          </Button>
        </Link>
        <div>
          <h1 className="text-2xl font-bold">Project Settings</h1>
          <p className="text-muted-foreground">
            Update the basic project details shown throughout Pepper.
          </p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>General</CardTitle>
          <CardDescription>Edit the project name and description.</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Project name *</Label>
              <Input
                id="name"
                value={name}
                onBlur={() => setNameTouched(true)}
                onChange={(e) => setName(e.target.value)}
                placeholder="My Application"
                required
                aria-invalid={Boolean(nameError)}
              />
              {nameError && (
                <p className="text-sm text-destructive" role="alert">
                  {nameError}
                </p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="description">Description</Label>
              <Textarea
                id="description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Brief description of the project"
              />
            </div>

            <div className="flex gap-2 pt-4">
              <Button type="submit" disabled={saving}>
                {saving ? "Saving..." : "Save Changes"}
              </Button>
              <Link href={`/projects/${projectId}`}>
                <Button type="button" variant="outline">
                  Cancel
                </Button>
              </Link>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
