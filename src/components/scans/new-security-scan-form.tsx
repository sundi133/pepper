"use client";

import { useState, useEffect, useRef } from "react";
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
import {
  Github,
  Upload,
  AlertTriangle,
  Scan,
  FolderArchive,
  Sparkles,
  FileArchive,
  Info,
  KeyRound,
  Link2,
  X,
  FolderGit2,
} from "lucide-react";
import { SubversionLogo } from "@/components/icons/source-logos";
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
import type { ScanJobData } from "@/lib/queue";
import { ScanTypeSelector } from "@/components/scan-hub/scan-type-selector";
import { UPLOADABLE_ARTIFACT_EXTENSIONS } from "@/lib/compiled-scan/upload";
import { maxUploadBytes, maxUploadMb } from "@/lib/upload-limits";
import { isAgentArtifact } from "@/scanners/mobile-agent/artifact";
import { projectNameFromUploadFilename } from "@/lib/project-name-from-source";

type SourceTab = "repository" | "upload" | "svn";

interface NewSecurityScanFormProps {
  projects?: ScanProject[];
  onCancel?: () => void;
  onCreated?: () => void;
  embedded?: boolean;
  /** Limit visible source tabs (default: all). */
  allowedTabs?: SourceTab[];
  defaultTab?: SourceTab;
  /** When false, omit outer card chrome (parent provides layout). */
  showOuterCard?: boolean;
  /** Controlled scan type (e.g. from Scan hub Add Source). */
  scanType?: ScanJobData["scanType"];
  /** Controlled scanner combination, paired with scanType. */
  scanModules?: string[];
  onScanTypeChange?: (value: ScanJobData["scanType"], modules?: string[]) => void;
  /** Hide built-in scan type UI when parent renders ScanTypeSelector. */
  hideScanTypeSelector?: boolean;
}

export function NewSecurityScanForm({
  projects = [],
  onCancel,
  onCreated,
  embedded = false,
  allowedTabs,
  defaultTab,
  showOuterCard = true,
  scanType: controlledScanType,
  scanModules: controlledScanModules,
  onScanTypeChange,
  hideScanTypeSelector = false,
}: NewSecurityScanFormProps) {
  const router = useRouter();
  const tabs = allowedTabs ?? (["repository", "svn", "upload"] as SourceTab[]);
  const initialTab = defaultTab && tabs.includes(defaultTab) ? defaultTab : tabs[0];
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState<SourceTab>(initialTab);
  const [projectId, setProjectId] = useState(CREATE_PROJECT_ON_SCAN_VALUE);
  const [newProjectName, setNewProjectName] = useState("");
  const [internalScanType, setInternalScanType] =
    useState<ScanJobData["scanType"]>("FULL");
  const [internalScanModules, setInternalScanModules] = useState<string[]>([]);
  const scanType = controlledScanType ?? internalScanType;
  const scanModules = controlledScanModules ?? internalScanModules;
  const setScanSelection = (value: ScanJobData["scanType"], modules: string[] = []) => {
    if (onScanTypeChange) return onScanTypeChange(value, modules);
    setInternalScanType(value);
    setInternalScanModules(modules);
  };
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("");
  const [repoToken, setRepoToken] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [svnUrl, setSvnUrl] = useState("");
  const [svnRevision, setSvnRevision] = useState("");
  const [svnUsername, setSvnUsername] = useState("");
  const [svnPassword, setSvnPassword] = useState("");
  const [legalConfirm, setLegalConfirm] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
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
  // A compiled/binary upload (.apk/.aab/.ipa/.dex/.jar/.war/.ear/.dll/.exe) is
  // reviewed by the agent deep scan automatically when the instance is
  // configured for it — no opt-in. Shown as an informational note only.
  const uploadIsBinary = sourceMode === "upload" && isAgentArtifact(file?.name);

  const uploadExtensions = [".zip", ".tar", ".tar.gz", ".tgz", ...UPLOADABLE_ARTIFACT_EXTENSIONS];

  /** Validate and accept a file from the picker or a drop; false if rejected. */
  function acceptFile(selected: File | null): boolean {
    if (selected && selected.size > maxUploadBytes()) {
      toast.error(`File too large. Maximum allowed size is ${maxUploadMb()} MB.`);
      return false;
    }
    if (
      selected &&
      !uploadExtensions.some((ext) => selected.name.toLowerCase().endsWith(ext))
    ) {
      toast.error(`Invalid file type. Allowed: ${uploadExtensions.join(", ")}`);
      return false;
    }
    setFile(selected);
    setTouched((t) => ({ ...t, source: true }));
    setFieldErrors((err) => ({ ...err, source: undefined }));
    return true;
  }

  function clearFile() {
    setFile(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

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
    // The repository picker is hidden for uploads (the repository comes from
    // the file name); don't keep a choice the user can no longer see.
    if (next === "upload") {
      setProjectId(CREATE_PROJECT_ON_SCAN_VALUE);
      setNewProjectName("");
    }
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
        ...(scanModules.length > 0 && { scanModules }),
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
      // Re-uploading the same app updates its repository (and keeps the scan
      // history for comparisons) instead of creating a duplicate each time.
      if (sourceMode === "upload" && file && !data.projectId && !data.newProjectName) {
        data.projectName = projectNameFromUploadFilename(file.name);
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

  const inner = (
    <>
        {showOuterCard && (
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
        )}

        {tabs.length > 1 && (
        <div
          className={cn(
            "mb-5 grid gap-1 rounded-lg border border-border bg-muted/50 p-1",
            tabs.length === 2 && "grid-cols-2",
            tabs.length >= 3 && "grid-cols-3",
          )}
        >
          {tabs.includes("repository") && (
          <button type="button" onClick={() => switchTab("repository")} className={tabBtn(tab === "repository")}>
            <Github className="h-4 w-4 shrink-0" />
            Git
          </button>
          )}
          {tabs.includes("svn") && (
          <button type="button" onClick={() => switchTab("svn")} className={tabBtn(tab === "svn")}>
            <FolderArchive className="h-4 w-4 shrink-0" />
            SVN
          </button>
          )}
          {tabs.includes("upload") && (
          <button type="button" onClick={() => switchTab("upload")} className={tabBtn(tab === "upload")}>
            <Upload className="h-4 w-4 shrink-0" />
            Upload
          </button>
          )}
        </div>
        )}

        <div
          className={cn(
            "grid gap-6",
            !hideScanTypeSelector && "lg:grid-cols-2 lg:gap-8",
          )}
        >
          {/* Left column: project + source */}
          <div className="space-y-5">
            {/* Uploads go to the repository named after the file (created on first upload). */}
            {tab !== "upload" && (
            <div className="space-y-4 rounded-lg border border-border bg-card/60 p-4">
              <SectionTitle icon={<FolderGit2 className="h-4 w-4" />} title="Where results go" />
            <div className="space-y-1.5">
              <Label htmlFor="nss-project" className="text-sm text-foreground">
                Repository
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
                  <SelectValue placeholder="New repository" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={CREATE_PROJECT_ON_SCAN_VALUE}>
                    New repository (auto)
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
                  Repository name <span className="font-normal text-muted-foreground">(optional)</span>
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
                    <Link href="/scans/new" className="text-primary hover:underline">
                      Scan hub
                    </Link>
                  </p>
                )}
              </div>
            )}

            {tab === "svn" && (
              <div className="space-y-4 rounded-lg border border-border bg-card/60 p-4">
                <SectionTitle
                  icon={<SubversionLogo className="h-4 w-5" />}
                  title="Subversion source"
                />
                <div className="space-y-1.5">
                  <Label htmlFor="nss-svn-url" className="text-sm text-foreground">
                    Repository URL <span className="text-destructive">*</span>
                  </Label>
                  <div className="relative">
                    <Link2 className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
                    <Input
                      id="nss-svn-url"
                      className="h-10 bg-background pl-9 font-mono text-[13px]"
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
                  <p className="text-xs text-muted-foreground">
                    Point at trunk, a branch or a tag, e.g. <code className="rounded bg-muted px-1">…/repo/branches/release</code>.
                  </p>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="nss-svn-rev" className="text-sm text-foreground">
                    Revision <span className="font-normal text-muted-foreground">(optional)</span>
                  </Label>
                  <Input
                    id="nss-svn-rev"
                    className="h-10 bg-background font-mono text-[13px] sm:max-w-[12rem]"
                    placeholder="HEAD"
                    value={svnRevision}
                    onChange={(e) => setSvnRevision(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">A number, HEAD, or a date like {"{2026-01-31}"}.</p>
                </div>

                <fieldset className="space-y-3 rounded-md border border-dashed border-border p-3">
                  <legend className="flex items-center gap-1.5 px-1 text-xs font-medium text-muted-foreground">
                    <KeyRound className="h-3.5 w-3.5" aria-hidden />
                    Credentials (optional, for private repositories)
                  </legend>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label htmlFor="nss-svn-user" className="text-sm text-foreground">
                        Username
                      </Label>
                      <Input
                        id="nss-svn-user"
                        className="h-10 bg-background"
                        autoComplete="username"
                        value={svnUsername}
                        onChange={(e) => setSvnUsername(e.target.value)}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="nss-svn-pass" className="text-sm text-foreground">
                        Password
                      </Label>
                      <Input
                        id="nss-svn-pass"
                        type="password"
                        className="h-10 bg-background"
                        autoComplete="current-password"
                        value={svnPassword}
                        onChange={(e) => setSvnPassword(e.target.value)}
                      />
                    </div>
                  </div>
                </fieldset>

                <p className="flex items-start gap-2 rounded-md bg-muted/50 px-3 py-2 text-xs text-muted-foreground">
                  <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
                  <span>
                    The scan worker checks out the code with the{" "}
                    <code className="rounded bg-muted px-1">svn</code> client, so it must be installed there.
                  </span>
                </p>
              </div>
            )}

            {tab === "upload" && (
              <div className="space-y-4 rounded-lg border border-border bg-card/60 p-4">
                <SectionTitle icon={<Upload className="h-4 w-4" />} title="Source archive or app" />
                <input
                  ref={fileInputRef}
                  id="nss-archive"
                  type="file"
                  className="sr-only"
                  accept={uploadExtensions.join(",")}
                  onChange={(e) => {
                    if (!acceptFile(e.target.files?.[0] || null)) e.target.value = "";
                  }}
                />
                {file ? (
                  <div className="flex items-center gap-3 rounded-lg border border-indigo-200 bg-indigo-50/60 p-3 dark:border-indigo-900/60 dark:bg-indigo-950/30">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-indigo-100 text-indigo-600 dark:bg-indigo-900/50 dark:text-indigo-300">
                      <FileArchive className="h-5 w-5" aria-hidden />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium text-foreground">{file.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {(file.size / 1024 / 1024).toFixed(1)} MB
                        {uploadIsBinary ? " · compiled app, will be decompiled" : " · source archive"}
                      </p>
                      <p className="mt-0.5 truncate text-xs text-muted-foreground">
                        {(() => {
                          const name = projectNameFromUploadFilename(file.name);
                          return projects.some((p) => p.name === name)
                            ? `Updates repository “${name}” (keeps its scan history)`
                            : `Creates repository “${name}”`;
                        })()}
                      </p>
                    </div>
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8 shrink-0"
                      onClick={clearFile}
                      aria-label="Remove file"
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  </div>
                ) : (
                  <label
                    htmlFor="nss-archive"
                    onDragOver={(e) => {
                      e.preventDefault();
                      setDragOver(true);
                    }}
                    onDragLeave={() => setDragOver(false)}
                    onDrop={(e) => {
                      e.preventDefault();
                      setDragOver(false);
                      acceptFile(e.dataTransfer.files?.[0] || null);
                    }}
                    className={cn(
                      "flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed px-4 py-8 text-center transition-colors",
                      dragOver
                        ? "border-indigo-400 bg-indigo-50/70 dark:bg-indigo-950/30"
                        : "border-border bg-background hover:border-indigo-300 hover:bg-muted/40",
                      showSourceError() && "border-destructive/60",
                    )}
                  >
                    <div className="flex h-11 w-11 items-center justify-center rounded-full bg-indigo-50 text-indigo-600 dark:bg-indigo-950/50 dark:text-indigo-300">
                      <Upload className="h-5 w-5" aria-hidden />
                    </div>
                    <p className="text-sm font-medium text-foreground">
                      Drop a file here, or <span className="text-indigo-600 underline-offset-2 hover:underline dark:text-indigo-400">browse</span>
                    </p>
                    <p className="text-xs text-muted-foreground">Up to {maxUploadMb()} MB</p>
                  </label>
                )}
                <div className="space-y-1.5">
                  <p className="text-xs font-medium text-muted-foreground">Accepted</p>
                  <div className="flex flex-wrap gap-1.5">
                    {[
                      { label: "Source", exts: ".zip .tar .tar.gz .tgz" },
                      { label: "Java", exts: ".jar .war .ear" },
                      { label: "Mobile", exts: ".apk .aab .ipa .dex" },
                      { label: ".NET", exts: ".dll .exe" },
                    ].map((g) => (
                      <span
                        key={g.label}
                        className="inline-flex items-center gap-1 rounded-md border border-border bg-muted/40 px-2 py-0.5 text-[11px] text-muted-foreground"
                      >
                        <span className="font-semibold text-foreground">{g.label}</span>
                        {g.exts}
                      </span>
                    ))}
                  </div>
                  <p className="text-xs text-muted-foreground">Compiled code is decompiled, then scanned like source.</p>
                </div>
                {uploadIsBinary && (
                  <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-2.5">
                    <Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-indigo-600 dark:text-indigo-400" aria-hidden />
                    <p className="text-xs leading-snug text-muted-foreground">
                      When the agent deep scan is enabled on this instance, this binary is reviewed by
                      glm-5.3 in an E2B cloud sandbox — it installs the right decompiler, decompiles and
                      inspects the app, and is the sole reviewer for the upload. If it is not enabled, the
                      binary falls back to the standard decompile-and-scan pipeline.
                    </p>
                  </div>
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
          <div
            className={cn(
              "flex flex-col justify-between gap-6",
              !hideScanTypeSelector && "lg:border-l lg:border-border lg:pl-8",
            )}
          >
            {!hideScanTypeSelector && (
            <div className="space-y-4">
              <div className="space-y-1.5">
                <ScanTypeSelector
                  value={scanType}
                  modules={scanModules}
                  onChange={setScanSelection}
                  compact
                />
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
              </div>
            </div>
            )}

            <div className="space-y-4 rounded-lg border border-border bg-muted/30 p-4">
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
                  I own this code or have permission to scan it
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
    </>
  );

  return (
    <div className={cn("w-full", embedded && "max-w-lg")}>
      {showOuterCard ? (
        <div className="rounded-xl border border-border bg-card p-5 shadow-sm sm:p-6">
          {inner}
        </div>
      ) : (
        inner
      )}
    </div>
  );
}

function SectionTitle({ icon, title }: { icon: React.ReactNode; title: string }) {
  return (
    <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
      <span className="flex h-7 w-7 items-center justify-center rounded-md bg-muted text-muted-foreground">
        {icon}
      </span>
      {title}
    </div>
  );
}
