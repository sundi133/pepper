"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Plus, Upload } from "lucide-react";
import { toast } from "sonner";

interface Project {
  id: string;
  name: string;
}

export function CreateScanDialog({ projects }: { projects: Project[] }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [projectId, setProjectId] = useState("");
  const [scanType, setScanType] = useState("FULL");
  const [sourceMode, setSourceMode] = useState<"upload" | "git" | "svn">(
    "upload",
  );
  const [file, setFile] = useState<File | null>(null);
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("");
  const [svnUrl, setSvnUrl] = useState("");
  const [svnRevision, setSvnRevision] = useState("");
  const [svnUsername, setSvnUsername] = useState("");
  const [svnPassword, setSvnPassword] = useState("");

  async function handleSubmit() {
    if (!projectId) {
      toast.error("Please select a project");
      return;
    }
    if (!file && !repoUrl && !svnUrl) {
      toast.error("Please upload a file or provide a repository URL");
      return;
    }

    setLoading(true);

    try {
      const formData = new FormData();
      const data = {
        projectId,
        scanType,
        repoUrl: sourceMode === "git" ? repoUrl : undefined,
        branch: sourceMode === "git" ? branch : undefined,
        svnUrl: sourceMode === "svn" ? svnUrl : undefined,
        svnRevision:
          sourceMode === "svn" ? svnRevision || undefined : undefined,
        svnUsername:
          sourceMode === "svn" ? svnUsername || undefined : undefined,
        svnPassword:
          sourceMode === "svn" ? svnPassword || undefined : undefined,
      };
      formData.append("data", JSON.stringify(data));
      if (sourceMode === "upload" && file) formData.append("file", file);

      const res = await fetch("/api/scans", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Failed to create scan");
      }

      const result = await res.json();
      toast.success("Scan created successfully");
      setOpen(false);
      router.push(`/scans/${result.scanId}`);
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to create scan",
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus className="mr-2 h-4 w-4" />
          New Scan
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Create New Scan</DialogTitle>
          <DialogDescription>
            Upload source code or provide a repository URL to scan for
            vulnerabilities.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          <div className="space-y-2">
            <Label>Project</Label>
            <Select value={projectId} onValueChange={setProjectId}>
              <SelectTrigger>
                <SelectValue placeholder="Select a project" />
              </SelectTrigger>
              <SelectContent>
                {projects.map((p) => (
                  <SelectItem key={p.id} value={p.id}>
                    {p.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label>Scan Type</Label>
            <Select value={scanType} onValueChange={setScanType}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="FULL">Full Scan</SelectItem>
                <SelectItem value="SAST_ONLY">SAST Only</SelectItem>
                <SelectItem value="SCA_ONLY">SCA Only</SelectItem>
                <SelectItem value="SECRETS_ONLY">Secrets Only</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label>Source</Label>
            <div className="flex gap-1 rounded-md border p-1">
              {(["upload", "git", "svn"] as const).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => setSourceMode(mode)}
                  className={`flex-1 rounded px-3 py-1.5 text-sm font-medium transition-colors ${
                    sourceMode === mode
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {mode === "upload"
                    ? "ZIP / TAR"
                    : mode === "git"
                      ? "Git"
                      : "SVN"}
                </button>
              ))}
            </div>
          </div>

          {sourceMode === "upload" && (
            <div className="space-y-2">
              <Label>Source Code (ZIP/TAR)</Label>
              <div className="flex items-center gap-2">
                <Input
                  type="file"
                  accept=".zip,.tar,.tar.gz,.tgz"
                  onChange={(e) => setFile(e.target.files?.[0] || null)}
                />
                {file && (
                  <span className="text-sm text-muted-foreground">
                    {(file.size / 1024 / 1024).toFixed(1)} MB
                  </span>
                )}
              </div>
            </div>
          )}

          {sourceMode === "git" && (
            <>
              <div className="space-y-2">
                <Label>Repository URL</Label>
                <Input
                  placeholder="https://github.com/org/repo.git"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label>Branch (optional)</Label>
                <Input
                  placeholder="main"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                />
              </div>
            </>
          )}

          {sourceMode === "svn" && (
            <>
              <div className="space-y-2">
                <Label>SVN Repository URL</Label>
                <Input
                  placeholder="https://svn.example.com/repos/project/trunk"
                  value={svnUrl}
                  onChange={(e) => setSvnUrl(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label>Revision (optional)</Label>
                <Input
                  placeholder="HEAD"
                  value={svnRevision}
                  onChange={(e) => setSvnRevision(e.target.value)}
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div className="space-y-2">
                  <Label>Username (optional)</Label>
                  <Input
                    placeholder="svn-user"
                    value={svnUsername}
                    onChange={(e) => setSvnUsername(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label>Password (optional)</Label>
                  <Input
                    type="password"
                    placeholder="password"
                    value={svnPassword}
                    onChange={(e) => setSvnPassword(e.target.value)}
                  />
                </div>
              </div>
              <div className="rounded-md bg-muted p-3 text-sm text-muted-foreground">
                SVN requires the <code>svn</code> CLI installed on the worker.
                Supports standard SVN URLs including trunk, branches, and tags
                paths.
              </div>
            </>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={loading}>
            {loading ? (
              "Creating..."
            ) : (
              <>
                <Upload className="mr-2 h-4 w-4" />
                Start Scan
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
