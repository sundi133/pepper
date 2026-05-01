"use client";

import { useState } from "react";
import { useProjects } from "@/hooks/use-scan-polling";
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
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";

export default function BuildGatesPage() {
  const { projects } = useProjects();
  const [selectedProject, setSelectedProject] = useState("");
  const [loading, setLoading] = useState(false);
  const [gate, setGate] = useState({
    maxCritical: 0,
    maxHigh: 5,
    maxMedium: 20,
    maxLow: -1,
    failOnNew: true,
  });

  async function loadGate(projectId: string) {
    setSelectedProject(projectId);
    const project = projects.find((p: { id: string }) => p.id === projectId);
    if (project?.buildGate) {
      setGate(project.buildGate);
    }
  }

  async function handleSave() {
    if (!selectedProject) {
      toast.error("Select a project first");
      return;
    }
    setLoading(true);
    try {
      const res = await fetch("/api/settings/build-gates", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ projectId: selectedProject, ...gate }),
      });
      if (!res.ok) throw new Error("Failed to save");
      toast.success("Build gate saved");
    } catch {
      toast.error("Failed to save build gate");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Build Gates</h1>
        <p className="text-muted-foreground">
          Configure severity thresholds that determine pass/fail for CI builds
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Build Gate Configuration</CardTitle>
          <CardDescription>
            Set maximum allowed findings per severity. Use -1 for unlimited.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Project</Label>
            <Select value={selectedProject} onValueChange={loadGate}>
              <SelectTrigger>
                <SelectValue placeholder="Select a project" />
              </SelectTrigger>
              <SelectContent>
                {projects.map((p: { id: string; name: string }) => (
                  <SelectItem key={p.id} value={p.id}>
                    {p.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {selectedProject && (
            <>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Max Critical</Label>
                  <Input
                    type="number"
                    value={gate.maxCritical}
                    onChange={(e) =>
                      setGate((g) => ({
                        ...g,
                        maxCritical: parseInt(e.target.value),
                      }))
                    }
                    min={-1}
                  />
                  <p className="text-xs text-muted-foreground">
                    -1 = unlimited
                  </p>
                </div>
                <div className="space-y-2">
                  <Label>Max High</Label>
                  <Input
                    type="number"
                    value={gate.maxHigh}
                    onChange={(e) =>
                      setGate((g) => ({
                        ...g,
                        maxHigh: parseInt(e.target.value),
                      }))
                    }
                    min={-1}
                  />
                </div>
                <div className="space-y-2">
                  <Label>Max Medium</Label>
                  <Input
                    type="number"
                    value={gate.maxMedium}
                    onChange={(e) =>
                      setGate((g) => ({
                        ...g,
                        maxMedium: parseInt(e.target.value),
                      }))
                    }
                    min={-1}
                  />
                </div>
                <div className="space-y-2">
                  <Label>Max Low</Label>
                  <Input
                    type="number"
                    value={gate.maxLow}
                    onChange={(e) =>
                      setGate((g) => ({
                        ...g,
                        maxLow: parseInt(e.target.value),
                      }))
                    }
                    min={-1}
                  />
                </div>
              </div>

              <div className="flex items-center justify-between pt-2">
                <div>
                  <Label>Fail on New Findings</Label>
                  <p className="text-sm text-muted-foreground">
                    Fail incremental scans if new findings are introduced
                  </p>
                </div>
                <Switch
                  checked={gate.failOnNew}
                  onCheckedChange={(v) =>
                    setGate((g) => ({ ...g, failOnNew: v }))
                  }
                />
              </div>

              <Button onClick={handleSave} disabled={loading}>
                {loading ? "Saving..." : "Save Build Gate"}
              </Button>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
