"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
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
import { Checkbox } from "@/components/ui/checkbox";
import { Github, Upload, AlertTriangle, Scan, FolderArchive } from "lucide-react";
import { toast } from "sonner";
import { mutate } from "swr";
import {
  validateCreateScanFields,
  CREATE_PROJECT_ON_SCAN_VALUE,
  isExistingProjectSelection,
  type CreateScanFieldErrors,
} from "@/lib/create-scan-validation";
import type { ScanProject } from "./types";
import { cn } from "@/lib/utils";
import { MANUAL_SCAN_TYPE_OPTIONS } from "@/lib/scan-types";

type SourceTab = "repository" | "upload" | "svn";

interface NewSecurityScanFormProps {
  projects?: ScanProject[];
  onCancel?: () => void;
  onCreated?: () => void;
  embedded?: boolean;
}

export function NewSecurityScanForm({
  projects = [],
  onCancel,
  onCreated,
  embedded = false,
}: NewSecurityScanFormProps) {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState<SourceTab>("repository");
  const [projectId, setProjectId] = useState(CREATE_PROJECT_ON_SCAN_VALUE);
  const [newProjectName, setNewProjectName] = useState("");
  const [scanType, setScanType] = useState<string>("FULL");
  const scanTypeHelp =
    MANUAL_SCAN_TYPE_OPTIONS.find((o) => o.value === scanType)?.description ??
    "";
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("");
  const [repoToken, setRepoToken] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [svnUrl, setSvnUrl] = useState("");
  const [svnRevision, setSvnRevision] = useState("");
  const [svnUsername, setSvnUsername] = useState("");
  const [svnPassword, setSvnPassword] = useState("");
  const [legalConfirm, setLegalConfirm] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<CreateScanFieldErrors>({});
  const [touched, setTouched] = useState<{ project?: boolean; source?: boolean }>(
    {},
  );
  const [submitAttempted, setSubmitAttempted] = useState(false);
  const [githubOAuthConnected, setGithubOAuthConnected] = useState(false);

  useEffect(() => {
    void fetch("/api/integrations/github")
      .then((r) => r.json())
      .then((d: { connected?: boolean }) =>
        setGithubOAuthConnected(Boolean(d.connected)),
      )
      .catch(() => setGithubOAuthConnected(false));
  }, []);

  useEffect(() => {
    if (!isExistingProjectSelection(projectId)) return;
    const p = projects.find((x) => x.id === projectId);
    if (p?.repoUrl && tab === "repository") {
      setRepoUrl(p.repoUrl);
      setBranch(p.defaultBranch || "");
    }
  }, [projectId, projects, tab]);

  const sourceMode =
    tab === "svn" ? "svn" : tab === "upload" ? "upload" : "git";

  function runValidation(): CreateScanFieldErrors {
    return validateCreateScanFields({
      projectId,
      sourceMode,
      file,
      repoUrl,
      svnUrl,
    });
  }

  function showProjectError() {
    return Boolean(fieldErrors.project && (touched.project || submitAttempted));
  }

  function showSourceError() {
    return Boolean(fieldErrors.source && (touched.source || submitAttempted));
  }

  function switchTab(next: SourceTab) {
    setTab(next);
    setFieldErrors((e) => ({ ...e, source: undefined }));
  }

  async function handleSubmit() {
    setSubmitAttempted(true);
    if (!legalConfirm) {
      toast.error("Confirm you have permission to scan this code.");
      return;
    }

    const errors = runValidation();
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) {
      if (errors.project) toast.error(errors.project);
      else if (errors.source) toast.error(errors.source);
      return;
    }

    setLoading(true);
    try {
      const formData = new FormData();
      const data: Record<string, unknown> = {
        scanType,
        repoUrl: sourceMode === "git" ? repoUrl : undefined,
        branch: sourceMode === "git" ? branch || undefined : undefined,
        repoToken:
          sourceMode === "git" && repoToken.trim() ? repoToken : undefined,
        svnUrl: sourceMode === "svn" ? svnUrl : undefined,
        svnRevision: sourceMode === "svn" ? svnRevision || undefined : undefined,
        svnUsername: sourceMode === "svn" ? svnUsername || undefined : undefined,
        svnPassword: sourceMode === "svn" ? svnPassword || undefined : undefined,
      };
      if (isExistingProjectSelection(projectId)) {
        data.projectId = projectId;
      }
      if (!isExistingProjectSelection(projectId) && newProjectName.trim()) {
        data.newProjectName = newProjectName.trim();
      }
      formData.append("data", JSON.stringify(data));
      if (sourceMode === "upload" && file) formData.append("file", file);

      const res = await fetch("/api/scans", { method: "POST", body: formData });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Failed to create scan");
      }

      const result = await res.json();
      toast.success("Scan queued");
      await Promise.all([
        mutate("/api/notifications?summary=unread"),
        mutate("/api/notifications"),
      ]);
      onCreated?.();
      router.push(`/scans/${result.scanId}`);
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to create scan",
      );
    } finally {
      setLoading(false);
    }
  }

  const tabBtn = (active: boolean) =>
    cn(
      "flex flex-1 items-center justify-center gap-1.5 rounded-md px-2 py-2 text-sm font-medium transition-colors",
      active
        ? "bg-card text-foreground shadow-sm"
        : "text-muted-foreground hover:text-foreground",
    );

  return (
    <div className={cn("w-full", embedded && "max-w-lg")}>
      <div className="rounded-xl border border-border bg-card p-5 shadow-sm sm:p-6">
        <div
          className="mb-5 flex gap-2.5 rounded-lg border border-amber-300 bg-amber-50 px-3 py-2.5 text-sm text-amber-950 dark:border-amber-500/50 dark:bg-amber-950/40 dark:text-amber-50"
          role="note"
        >
          <AlertTriangle
            className="mt-0.5 h-4 w-4 shrink-0 text-amber-700 dark:text-amber-400"
            aria-hidden
          />
          <p className="leading-snug">
            Only scan code you own or may test. Confirm below before starting.
          </p>
        </div>

        <div className="mb-5 grid grid-cols-3 gap-1 rounded-lg border border-border bg-muted/50 p-1">
          <button type="button" onClick={() => switchTab("repository")} className={tabBtn(tab === "repository")}>
            <Github className="h-4 w-4 shrink-0" />
            Git
          </button>
          <button type="button" onClick={() => switchTab("svn")} className={tabBtn(tab === "svn")}>
            <FolderArchive className="h-4 w-4 shrink-0" />
            SVN
          </button>
          <button type="button" onClick={() => switchTab("upload")} className={tabBtn(tab === "upload")}>
            <Upload className="h-4 w-4 shrink-0" />
            Upload
          </button>
        </div>

        <div className="grid gap-6 lg:grid-cols-2 lg:gap-8">
          {/* Left column: project + source */}
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="nss-project" className="text-sm text-foreground">
                Project
              </Label>
              <Select
                value={projectId}
                onValueChange={(v) => {
                  setProjectId(v);
                  setTouched((t) => ({ ...t, project: true }));
                  setFieldErrors(
                    validateCreateScanFields({
                      projectId: v,
                      sourceMode,
                      file,
                      repoUrl,
                      svnUrl,
                    }),
                  );
                }}
              >
                <SelectTrigger id="nss-project" className="h-9 bg-card" aria-invalid={showProjectError()}>
                  <SelectValue placeholder="New project" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={CREATE_PROJECT_ON_SCAN_VALUE}>
                    New project (auto)
                  </SelectItem>
                  {projects.map((p) => (
                    <SelectItem key={p.id} value={p.id}>
                      {p.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {showProjectError() && (
                <p className="text-xs text-destructive">{fieldErrors.project}</p>
              )}
            </div>

            {!isExistingProjectSelection(projectId) && (
              <div className="space-y-1.5">
                <Label htmlFor="nss-new-project-name" className="text-sm text-foreground">
                  Project name <span className="font-normal text-muted-foreground">(optional)</span>
                </Label>
                <Input
                  id="nss-new-project-name"
                  className="h-9 bg-card"
                  placeholder="From repo or file if empty"
                  value={newProjectName}
                  onChange={(e) => setNewProjectName(e.target.value)}
                />
              </div>
            )}

            {tab === "repository" && (
              <div className="space-y-4">
                <div className="space-y-1.5">
                  <Label htmlFor="nss-repo" className="text-sm text-foreground">
                    Repository URL *
                  </Label>
                  <Input
                    id="nss-repo"
                    className="h-9 bg-card"
                    placeholder="https://github.com/org/repo.git"
                    value={repoUrl}
                    aria-invalid={showSourceError()}
                    onBlur={() => {
                      setTouched((t) => ({ ...t, source: true }));
                      setFieldErrors(
                        validateCreateScanFields({
                          projectId,
                          sourceMode: "git",
                          file,
                          repoUrl,
                          svnUrl,
                        }),
                      );
                    }}
                    onChange={(e) => {
                      setRepoUrl(e.target.value);
                      setFieldErrors((err) => ({ ...err, source: undefined }));
                    }}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="nss-branch" className="text-sm text-foreground">
                    Branch
                  </Label>
                  <Input
                    id="nss-branch"
                    className="h-9 bg-card"
                    placeholder="main"
                    value={branch}
                    onChange={(e) => setBranch(e.target.value)}
                  />
                </div>
                {!githubOAuthConnected ? (
                  <div className="space-y-1.5">
                    <Label htmlFor="nss-token" className="text-sm text-foreground">
                      Token <span className="font-normal text-muted-foreground">(private repos)</span>
                    </Label>
                    <Input
                      id="nss-token"
                      type="password"
                      className="h-9 bg-card"
                      placeholder="Optional PAT"
                      value={repoToken}
                      onChange={(e) => setRepoToken(e.target.value)}
                    />
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground">
                    GitHub connected — private repos use OAuth.{" "}
                    <Link href="/repositories" className="text-primary hover:underline">
                      Repositories
                    </Link>
                  </p>
                )}
              </div>
            )}

            {tab === "svn" && (
              <div className="space-y-4">
                <div className="space-y-1.5">
                  <Label htmlFor="nss-svn-url" className="text-sm text-foreground">
                    SVN URL *
                  </Label>
                  <Input
                    id="nss-svn-url"
                    className="h-9 bg-card"
                    placeholder="https://svn.example.com/repo/trunk"
                    value={svnUrl}
                    aria-invalid={showSourceError()}
                    onBlur={() => {
                      setTouched((t) => ({ ...t, source: true }));
                      setFieldErrors(
                        validateCreateScanFields({
                          projectId,
                          sourceMode: "svn",
                          file,
                          repoUrl,
                          svnUrl,
                        }),
                      );
                    }}
                    onChange={(e) => {
                      setSvnUrl(e.target.value);
                      setFieldErrors((err) => ({ ...err, source: undefined }));
                    }}
                  />
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label htmlFor="nss-svn-rev" className="text-sm text-foreground">
                      Revision
                    </Label>
                    <Input
                      id="nss-svn-rev"
                      className="h-9 bg-card"
                      placeholder="HEAD"
                      value={svnRevision}
                      onChange={(e) => setSvnRevision(e.target.value)}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="nss-svn-user" className="text-sm text-foreground">
                      Username
                    </Label>
                    <Input
                      id="nss-svn-user"
                      className="h-9 bg-card"
                      placeholder="Optional"
                      value={svnUsername}
                      onChange={(e) => setSvnUsername(e.target.value)}
                    />
                  </div>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="nss-svn-pass" className="text-sm text-foreground">
                    Password
                  </Label>
                  <Input
                    id="nss-svn-pass"
                    type="password"
                    className="h-9 bg-card"
                    placeholder="Optional"
                    value={svnPassword}
                    onChange={(e) => setSvnPassword(e.target.value)}
                  />
                </div>
                <p className="text-xs text-muted-foreground">
                  Requires <code className="rounded bg-muted px-1">svn</code> on the scan worker.
                </p>
              </div>
            )}

            {tab === "upload" && (
              <div className="space-y-1.5">
                <Label htmlFor="nss-archive" className="text-sm text-foreground">
                  Archive *
                </Label>
                <Input
                  id="nss-archive"
                  type="file"
                  accept=".zip,.tar,.tar.gz,.tgz"
                  className="h-9 cursor-pointer bg-card pt-1.5 file:mr-2 file:text-sm"
                  aria-invalid={showSourceError()}
                  onBlur={() => {
                    setTouched((t) => ({ ...t, source: true }));
                    setFieldErrors(
                      validateCreateScanFields({
                        projectId,
                        sourceMode: "upload",
                        file,
                        repoUrl,
                        svnUrl,
                      }),
                    );
                  }}
                  onChange={(e) => {
                    setFile(e.target.files?.[0] || null);
                    setFieldErrors((err) => ({ ...err, source: undefined }));
                  }}
                />
                {file && (
                  <p className="text-xs text-muted-foreground">
                    {(file.size / 1024 / 1024).toFixed(1)} MB selected
                  </p>
                )}
              </div>
            )}

            {showSourceError() && fieldErrors.source && (
              <p className="text-xs text-destructive" role="alert">
                {fieldErrors.source}
              </p>
            )}
          </div>

          {/* Right column: scan type + confirm + action */}
          <div className="flex flex-col justify-between gap-6 lg:border-l lg:border-border lg:pl-8">
            <div className="space-y-4">
              <div className="space-y-1.5">
                <Label className="text-sm text-foreground">Scan type</Label>
                <Select value={scanType} onValueChange={setScanType}>
                  <SelectTrigger className="h-9 bg-card">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {MANUAL_SCAN_TYPE_OPTIONS.map((o) => (
                      <SelectItem key={o.value} value={o.value}>
                        {o.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {scanTypeHelp ? (
                  <p className="text-xs text-muted-foreground">{scanTypeHelp}</p>
                ) : null}
              </div>

              <div className="rounded-lg border border-border bg-muted/30 p-4 text-sm text-muted-foreground space-y-2">
                {tab === "repository" && (
                  <p>Clones a Git repository and runs the selected scanners on the checkout.</p>
                )}
                {tab === "svn" && (
                  <p>Checks out from Subversion, then runs the same security analysis as a Git scan.</p>
                )}
                {tab === "upload" && (
                  <p>Upload a zip or tarball of your source tree. Good for air-gapped or ad-hoc drops.</p>
                )}
                <p>
                  <strong>Full</strong> includes IaC and zero-day. IaC / zero-day also
                  have dedicated scan types. Enable LLM SAST under LLM Config for those
                  AI scanners.
                </p>
              </div>
            </div>

            <div className="space-y-4">
              <div className="flex items-start gap-2">
                <Checkbox
                  id="nss-legal"
                  checked={legalConfirm}
                  onCheckedChange={(c) => setLegalConfirm(c === true)}
                  className="mt-0.5"
                />
                <Label
                  htmlFor="nss-legal"
                  className="cursor-pointer text-sm font-normal leading-snug text-foreground"
                >
                  I have permission to scan this code
                </Label>
              </div>

              <div className="flex flex-col gap-2 sm:flex-row lg:flex-col xl:flex-row">
                <Button
                  type="button"
                  className="h-10 flex-1"
                  disabled={loading}
                  onClick={() => void handleSubmit()}
                >
                  {loading ? (
                    "Starting…"
                  ) : (
                    <>
                      <Scan className="mr-2 h-4 w-4" />
                      Start scan
                    </>
                  )}
                </Button>
                {onCancel && (
                  <Button
                    type="button"
                    variant="outline"
                    className="h-10 sm:w-auto lg:w-full xl:w-auto"
                    disabled={loading}
                    onClick={onCancel}
                  >
                    Cancel
                  </Button>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
