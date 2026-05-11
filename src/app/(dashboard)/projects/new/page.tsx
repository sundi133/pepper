"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
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
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

export default function NewProjectPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [nameTouched, setNameTouched] = useState(false);
  const [submitAttempted, setSubmitAttempted] = useState(false);

  const nameError =
    !name.trim() && (nameTouched || submitAttempted)
      ? "Project name is required."
      : null;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitAttempted(true);
    if (!name.trim()) {
      toast.error("Project name is required");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/api/projects", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, description }),
      });

      if (!res.ok) throw new Error("Failed to create project");

      const project = await res.json();
      toast.success("Project created");
      router.push(`/projects/${project.id}`);
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to create project",
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-2xl">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Projects", href: "/projects" },
          { label: "New project" },
        ]}
      />
      <h1 className="text-2xl font-bold mb-6">Create New Project</h1>

      <Card>
        <CardHeader>
          <CardTitle>Project Details</CardTitle>
          <CardDescription>
            Create a project to organize scans and manage project-level
            settings.
          </CardDescription>
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
              <Button type="submit" disabled={loading}>
                {loading ? "Creating..." : "Create Project"}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => router.back()}
              >
                Cancel
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
