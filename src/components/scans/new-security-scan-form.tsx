"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
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
import {
  Github,
  Upload,
  AlertTriangle,
  Scan,
  ChevronDown,
} from "lucide-react";
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

type SourceTab = "repository" | "upload";

interface NewSecurityScanFormProps {
  projects: ScanProject[];
  onCancel?: () => void;
  onCreated?: () => void;
  /** Wider layout when embedded in a dialog shell */
  embedded?: boolean;
}

export function NewSecurityScanForm({
  projects,
  onCancel,
  onCreated,
  embedded = false,
}: NewSecurityScanFormProps) {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState<SourceTab>("repository");
  const [projectId, setProjectId] = useState(CREATE_PROJECT_ON_SCAN_VALUE);
  const [newProjectName, setNewProjectName] = useState("");
  const [scanType, setScanType] = useState("FULL");
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("");
  const [repoToken, setRepoToken] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [svnUrl, setSvnUrl] = useState("");
  const [svnRevision, setSvnRevision] = useState("");
  const [svnUsername, setSvnUsername] = useState("");
  const [svnPassword, setSvnPassword] = useState("");
  const [useSvn, setUseSvn] = useState(false);
  const [legalConfirm, setLegalConfirm] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<CreateScanFieldErrors>({});
  const [touched, setTouched] = useState<{
    project?: boolean;
    source?: boolean;
  }>({});
  const [submitAttempted, setSubmitAttempted] = useState(false);

  useEffect(() => {
    if (!isExistingProjectSelection(projectId)) return;
    const p = projects.find((x) => x.id === projectId);
    if (p?.repoUrl && tab === "repository") {
      setRepoUrl(p.repoUrl);
      setBranch(p.defaultBranch || "");
    }
  }, [projectId, projects, tab]);

  const sourceMode = useSvn ? "svn" : tab === "upload" ? "upload" : "git";

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
    return Boolean(
      fieldErrors.project && (touched.project || submitAttempted),
    );
  }

  function showSourceError() {
    return Boolean(
      fieldErrors.source && (touched.source || submitAttempted),
    );
  }

  async function handleSubmit() {
    setSubmitAttempted(true);
    if (!legalConfirm) {
      toast.error(
        "Confirm that you have the legal right to analyze this code before starting a scan.",
      );
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
          sourceMode === "git" && repoToken.trim()
            ? repoToken
            : undefined,
        svnUrl: sourceMode === "svn" ? svnUrl : undefined,
        svnRevision:
          sourceMode === "svn" ? svnRevision || undefined : undefined,
        svnUsername:
          sourceMode === "svn" ? svnUsername || undefined : undefined,
        svnPassword:
          sourceMode === "svn" ? svnPassword || undefined : undefined,
      };
      if (isExistingProjectSelection(projectId)) {
        data.projectId = projectId;
      }
      if (
        !isExistingProjectSelection(projectId) &&
        newProjectName.trim()
      ) {
        data.newProjectName = newProjectName.trim();
      }
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

  return (
    <div
      className={cn(
        "mx-auto w-full",
        embedded ? "max-w-5xl" : "max-w-6xl",
      )}
    >
      <div className="grid gap-6 lg:grid-cols-[1fr_min(380px,36%)] lg:items-start lg:gap-8">
        <div className="min-w-0 space-y-6">
          <div className="flex items-start gap-3 rounded-lg border border-amber-500/40 bg-amber-500/5 px-4 py-3 text-sm text-amber-100/95">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
            <div>
              <p className="font-semibold text-amber-100">Important security notice</p>
              <p className="mt-1 text-amber-100/85">
                This tool is for analyzing code you own or have explicit permission
                to scan. By proceeding, you confirm you have the legal right to
                analyze the submitted source code.
              </p>
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="nss-project" className="text-foreground">
              Project
            </Label>
            <p className="text-xs text-muted-foreground">
              Defaults to a new project named from your repository or archive. Pick
              an existing project to replace that project&apos;s scan.
            </p>
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
              <SelectTrigger
                id="nss-project"
                className="h-11 border-border/60 bg-card/80"
                aria-invalid={showProjectError()}
              >
                <SelectValue placeholder="New project from this scan" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={CREATE_PROJECT_ON_SCAN_VALUE}>
                  New project (from this scan)
                </SelectItem>
                {projects.map((p) => (
                  <SelectItem key={p.id} value={p.id}>
                    {p.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {!isExistingProjectSelection(projectId) && (
              <div className="space-y-2 pt-1">
                <Label htmlFor="nss-new-project-name" className="text-muted-foreground">
                  Project name (optional)
                </Label>
                <Input
                  id="nss-new-project-name"
                  className="h-10 border-border/60 bg-card/80"
                  placeholder="Uses repo path or file name if empty"
                  value={newProjectName}
                  onChange={(e) => setNewProjectName(e.target.value)}
                />
              </div>
            )}
            {showProjectError() && (
              <p className="text-sm text-destructive" role="alert">
                {fieldErrors.project}
              </p>
            )}
          </div>

          <div>
            <p className="mb-3 text-sm font-medium text-muted-foreground">
              Source
            </p>
            <div className="inline-flex rounded-full border border-border/60 bg-muted/30 p-1">
              <button
                type="button"
                onClick={() => {
                  setTab("repository");
                  setUseSvn(false);
                  setFieldErrors((e) => ({ ...e, source: undefined }));
                }}
                className={cn(
                  "inline-flex items-center gap-2 rounded-full px-4 py-2 text-sm font-medium transition-colors",
                  tab === "repository" && !useSvn
                    ? "bg-card text-foreground shadow-sm ring-1 ring-border/60"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                <Github className="h-4 w-4" />
                Git repository
              </button>
              <button
                type="button"
                onClick={() => {
                  setTab("upload");
                  setUseSvn(false);
                  setFieldErrors((e) => ({ ...e, source: undefined }));
                }}
                className={cn(
                  "inline-flex items-center gap-2 rounded-full px-4 py-2 text-sm font-medium transition-colors",
                  tab === "upload"
                    ? "bg-card text-foreground shadow-sm ring-1 ring-border/60"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                <Upload className="h-4 w-4" />
                File upload
              </button>
            </div>
          </div>

          {tab === "repository" && !useSvn && (
            <div className="space-y-5 rounded-xl border border-border/50 bg-card/40 p-4 sm:p-5">
              <p className="text-sm text-muted-foreground">
                Enter the Git repository URL to clone and scan.
              </p>
              <div className="space-y-2">
                <Label htmlFor="nss-repo">Repository URL *</Label>
                <Input
                  id="nss-repo"
                  className="h-11 border-border/60 bg-background/80"
                  placeholder="https://github.com/org/repository.git"
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
              <div className="space-y-2">
                <Label htmlFor="nss-branch">Branch (optional)</Label>
                <Input
                  id="nss-branch"
                  className="h-11 border-border/60 bg-background/80"
                  placeholder="main — leave blank for default branch"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="nss-token">Personal access token (optional)</Label>
                <Input
                  id="nss-token"
                  type="password"
                  autoComplete="new-password"
                  className="h-11 border-border/60 bg-background/80"
                  placeholder="••••••••••••••••"
                  value={repoToken}
                  onChange={(e) => setRepoToken(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Required for many private repositories. The token is used only for
                  the clone step and is not stored on the scan record.
                </p>
              </div>
            </div>
          )}

          {tab === "upload" && (
            <div className="space-y-5 rounded-xl border border-border/50 bg-card/40 p-4 sm:p-5">
              <p className="text-sm text-muted-foreground">
                Upload a ZIP or tarball of your source tree.
              </p>
              <div className="space-y-2">
                <Label htmlFor="nss-archive">Archive file *</Label>
                <Input
                  id="nss-archive"
                  type="file"
                  accept=".zip,.tar,.tar.gz,.tgz"
                  className="h-11 cursor-pointer border-border/60 bg-background/80 pt-2 file:mr-3"
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
            </div>
          )}

          {showSourceError() && fieldErrors.source && (
            <p className="text-sm text-destructive" role="alert">
              {fieldErrors.source}
            </p>
          )}

          <details className="group rounded-xl border border-border/50 bg-card/30">
            <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-4 py-3 text-sm font-medium text-foreground marker:hidden [&::-webkit-details-marker]:hidden">
              <span>Advanced: SVN &amp; scan profile</span>
              <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground transition-transform group-open:rotate-180" />
            </summary>
            <div className="space-y-4 border-t border-border/40 px-4 py-4">
              <div className="flex items-center gap-2">
                <Checkbox
                  id="nss-svn-mode"
                  checked={useSvn}
                  onCheckedChange={(c) => {
                    const on = c === true;
                    setUseSvn(on);
                    if (on) setTab("repository");
                    setFieldErrors((e) => ({ ...e, source: undefined }));
                  }}
                />
                <Label htmlFor="nss-svn-mode" className="font-normal leading-snug">
                  Use SVN checkout instead of Git for this scan
                </Label>
              </div>
              {useSvn && (
                <div className="space-y-3 rounded-lg border border-border/40 bg-background/40 p-3">
                  <div className="space-y-2">
                    <Label htmlFor="nss-svn-url">SVN repository URL *</Label>
                    <Input
                      id="nss-svn-url"
                      className="border-border/60 bg-background/80"
                      placeholder="https://svn.example.com/repo/trunk"
                      value={svnUrl}
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
                    <div className="space-y-2">
                      <Label htmlFor="nss-svn-rev">Revision</Label>
                      <Input
                        id="nss-svn-rev"
                        placeholder="HEAD"
                        value={svnRevision}
                        onChange={(e) => setSvnRevision(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="nss-svn-user">Username</Label>
                      <Input
                        id="nss-svn-user"
                        value={svnUsername}
                        onChange={(e) => setSvnUsername(e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="nss-svn-pass">Password</Label>
                    <Input
                      id="nss-svn-pass"
                      type="password"
                      value={svnPassword}
                      onChange={(e) => setSvnPassword(e.target.value)}
                    />
                  </div>
                </div>
              )}
              <div className="space-y-2">
                <Label>Scan profile</Label>
                <Select value={scanType} onValueChange={setScanType}>
                  <SelectTrigger className="border-border/60 bg-background/80">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="FULL">Full scan</SelectItem>
                    <SelectItem value="SAST_ONLY">SAST only</SelectItem>
                    <SelectItem value="SCA_ONLY">SCA only</SelectItem>
                    <SelectItem value="SECRETS_ONLY">Secrets only</SelectItem>
                    <SelectItem value="INCREMENTAL">Incremental</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </details>

          <div className="flex items-start gap-3 rounded-lg border border-border/50 bg-card/40 px-4 py-3">
            <Checkbox
              id="nss-legal"
              checked={legalConfirm}
              onCheckedChange={(c) => setLegalConfirm(c === true)}
              className="mt-0.5"
            />
            <div>
              <Label
                htmlFor="nss-legal"
                className="cursor-pointer text-sm font-medium leading-snug text-foreground"
              >
                I confirm ownership or permission to scan this code
              </Label>
              <p className="mt-1 text-xs text-muted-foreground">
                You must confirm before a scan can be queued.
              </p>
            </div>
          </div>

          <div className="flex flex-col gap-3 pt-2 sm:flex-row sm:items-center">
            <Button
              type="button"
              size="lg"
              className="h-12 w-full bg-primary font-semibold text-primary-foreground shadow-lg shadow-primary/20 hover:bg-primary/90 sm:flex-1"
              disabled={loading}
              onClick={handleSubmit}
            >
              {loading ? (
                "Starting…"
              ) : (
                <>
                  <Scan className="mr-2 h-5 w-5" />
                  Start security scan
                </>
              )}
            </Button>
            {onCancel && (
              <Button
                type="button"
                variant="outline"
                className="h-12 border-border/60 sm:w-auto"
                disabled={loading}
                onClick={onCancel}
              >
                Cancel
              </Button>
            )}
          </div>
        </div>

        <aside className="min-w-0 space-y-4 lg:sticky lg:top-20">
          <p className="text-sm font-medium text-muted-foreground">
            What we analyze
          </p>
          <p className="text-xs text-muted-foreground">
            AI-assisted and pattern-based checks across your codebase.
          </p>
          <ul className="space-y-3">
            <FeatureCard
              accent="border-l-red-500 bg-red-500/5"
              title="Vulnerability detection"
              body="SQL injection, XSS, CSRF, path traversal, unsafe deserialization, and more."
            />
            <FeatureCard
              accent="border-l-orange-500 bg-orange-500/5"
              title="Secret detection"
              body="API keys, tokens, passwords, private keys, and other leaked credentials."
            />
            <FeatureCard
              accent="border-l-amber-500 bg-amber-500/5"
              title="Dependency risks"
              body="Known CVEs and vulnerable packages (npm, pip, Maven, and more)."
            />
            <FeatureCard
              accent="border-l-sky-500 bg-sky-500/5"
              title="Code quality signals"
              body="Complexity, risky patterns, and hardcoded values worth reviewing."
            />
          </ul>
        </aside>
      </div>
    </div>
  );
}
function FeatureCard({
  accent,
  title,
  body,
}: {
  accent: string;
  title: string;
  body: string;
}) {
  return (
    <li
      className={cn(
        "rounded-lg border border-border/40 border-l-4 px-4 py-3 text-sm shadow-sm",
        accent,
      )}
    >
      <p className="font-semibold text-foreground">{title}</p>
      <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{body}</p>
    </li>
  );
}

