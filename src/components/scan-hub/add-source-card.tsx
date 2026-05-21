"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import {
  AlertCircle,
  CheckCircle2,
  Cloud,
  FolderArchive,
  Github,
  GitBranch,
  Import,
  Link2,
  Loader2,
  Settings,
  Shield,
  Unplug,
  Upload,
  UploadCloud,
} from "lucide-react";
import {
  detectRepoProviderFromInput,
  PROVIDER_HINT_LABEL,
} from "@/lib/detect-repo-provider";
import { cn } from "@/lib/utils";
import type { ScanJobData } from "@/lib/queue";
import { NewSecurityScanForm } from "@/components/scans/new-security-scan-form";
import type { ScanProject } from "@/components/scans/types";
import { ScanTypeSelector } from "./scan-type-selector";
import type { RepoProvider } from "./types";
import type { useScanHubIntegrations } from "./use-scan-hub-integrations";

export type SourcePill =
  | RepoProvider
  | "url"
  | "svn"
  | "upload";

type Hub = ReturnType<typeof useScanHubIntegrations>;

type AddSourceCardProps = {
  hub: Hub;
  projects: ScanProject[];
  scanType: ScanJobData["scanType"];
  onScanTypeChange: (value: ScanJobData["scanType"]) => void;
};

const PILL_BASE =
  "inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-medium transition-all sm:text-sm";

export function AddSourceCard({
  hub,
  projects,
  scanType,
  onScanTypeChange,
}: AddSourceCardProps) {
  const router = useRouter();
  const [activePill, setActivePill] = useState<SourcePill>("github");
  const [smartUrl, setSmartUrl] = useState("");
  const [smartBranch, setSmartBranch] = useState("");
  const [smartConnecting, setSmartConnecting] = useState(false);
  const [urlLegalConfirm, setUrlLegalConfirm] = useState(false);

  const providerHint = useMemo(
    () =>
      detectRepoProviderFromInput(
        smartUrl,
        hub.azureStatus?.azureOrganization,
      ),
    [smartUrl, hub.azureStatus?.azureOrganization],
  );

  async function handleSmartConnect() {
    setSmartConnecting(true);
    try {
      const outcome = await hub.connectSmartRepoUrl(smartUrl, smartBranch);
      if (outcome === "adhoc") {
        if (!urlLegalConfirm) {
          toast.error("Confirm you have permission to scan this code.");
          return;
        }
        const scanId = await hub.createAdHocGitScan(
          smartUrl,
          smartBranch,
          scanType,
        );
        toast.success("Scan queued");
        setSmartUrl("");
        setSmartBranch("");
        router.push(`/scans/${scanId}`);
        return;
      }
      setSmartUrl("");
      setSmartBranch("");
    } finally {
      setSmartConnecting(false);
    }
  }

  function selectPill(pill: SourcePill) {
    setActivePill(pill);
    if (pill === "github" || pill === "bitbucket" || pill === "azure") {
      hub.setProvider(pill);
    }
  }

  const pill = (
    id: SourcePill,
    label: string,
    icon: React.ReactNode,
  ) => (
    <button
      type="button"
      onClick={() => selectPill(id)}
      className={cn(
        PILL_BASE,
        activePill === id
          ? "border-teal-500/60 bg-teal-500/10 text-teal-800 shadow-sm dark:text-teal-100"
          : "border-slate-200/90 bg-white/80 text-slate-600 hover:border-teal-400/50 hover:text-teal-800 dark:border-slate-700 dark:bg-slate-900/50 dark:text-slate-300",
      )}
    >
      {icon}
      {label}
    </button>
  );

  const isIntegration =
    activePill === "github" ||
    activePill === "bitbucket" ||
    activePill === "azure";

  return (
    <div className="flex h-full flex-col overflow-hidden rounded-2xl border border-slate-200/90 bg-gradient-to-br from-teal-50/90 via-white to-cyan-50/40 shadow-[0_4px_24px_-4px_rgba(13,148,136,0.12)] dark:border-slate-800 dark:from-teal-950/30 dark:via-slate-950 dark:to-cyan-950/20">
      <div className="border-b border-teal-100/80 px-5 py-4 dark:border-teal-900/40">
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-teal-500 to-cyan-500 text-white shadow-md shadow-teal-500/25">
            <UploadCloud className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold tracking-tight text-slate-900 dark:text-slate-50">
              Add Source
            </h2>
            <p className="mt-0.5 text-sm text-slate-600 dark:text-slate-400">
              Import from integrations, paste a repo URL, or run an ad-hoc scan.
            </p>
          </div>
        </div>
      </div>

      <div className="flex flex-1 flex-col gap-4 px-5 py-4">
        <div className="flex flex-wrap gap-2">
          {pill("github", "GitHub", <Github className="h-3.5 w-3.5" />)}
          {pill("bitbucket", "Bitbucket", <GitBranch className="h-3.5 w-3.5" />)}
          {pill("azure", "Azure DevOps", <Cloud className="h-3.5 w-3.5" />)}
          {pill("url", "Repository URL", <Link2 className="h-3.5 w-3.5" />)}
          {pill("svn", "SVN", <FolderArchive className="h-3.5 w-3.5" />)}
          {pill("upload", "Upload", <Upload className="h-3.5 w-3.5" />)}
        </div>

        <ScanTypeSelector value={scanType} onChange={onScanTypeChange} />

        <div className="min-h-[200px] flex-1 rounded-xl border border-slate-200/70 bg-white/70 p-4 shadow-inner dark:border-slate-800 dark:bg-slate-900/40">
          {isIntegration && activePill === "github" && (
            <IntegrationPanel
              connected={hub.status?.connected}
              connectedLabel={
                hub.status?.connected
                  ? `Signed in as ${hub.status.githubLogin}`
                  : "Connect GitHub to import private repositories and open fix PRs."
              }
              onConnect={hub.connectGithub}
              onImport={hub.openGithubPicker}
              onDisconnect={() => void hub.disconnectGithub()}
              disconnecting={hub.disconnecting}
              connectDisabled={hub.status?.oauthConfigured === false}
              importDisabled={!hub.status?.connected}
              oauthWarning={hub.status?.oauthConfigured === false}
            />
          )}

          {isIntegration && activePill === "bitbucket" && (
            <IntegrationPanel
              connected={hub.bitbucketStatus?.connected}
              connectedLabel={
                hub.bitbucketStatus?.connected
                  ? `Signed in as ${hub.bitbucketStatus.username}${hub.bitbucketStatus.workspace ? ` · ${hub.bitbucketStatus.workspace}` : ""}`
                  : "Connect Bitbucket in Settings → Integrations to import repositories."
              }
              onConnect={() => hub.router.push("/settings/integrations")}
              onImport={hub.openBitbucketPicker}
              importDisabled={
                !hub.bitbucketStatus?.connected ||
                !hub.bitbucketStatus.workspace
              }
              settingsLink
              extraWarning={
                hub.bitbucketStatus?.connected &&
                !hub.bitbucketStatus.workspace
                  ? "Set your workspace slug in Settings → Integrations."
                  : undefined
              }
            />
          )}

          {isIntegration && activePill === "azure" && (
            <IntegrationPanel
              connected={hub.azureStatus?.connected}
              connectedLabel={
                hub.azureStatus?.connected
                  ? `${hub.azureStatus.azureUser ?? "Connected"}${hub.azureStatus.azureOrganization ? ` · ${hub.azureStatus.azureOrganization}` : ""}`
                  : "Connect Azure DevOps in Settings → Integrations."
              }
              onConnect={() => hub.router.push("/settings/integrations")}
              onImport={hub.openAzurePicker}
              importDisabled={!hub.azureStatus?.connected}
              settingsLink
            />
          )}

          {isIntegration && (
            <p className="text-xs text-slate-500">
              Browse & import queues an <strong>All</strong> scanners scan on first
              connect. Use Repository URL, SVN, or Upload to run a specific scanner
              set from the pills above.
            </p>
          )}

          {activePill === "url" && (
            <div className="space-y-3">
              <div className="space-y-1.5">
                <Label htmlFor="smart-repo-url" className="text-xs font-medium text-slate-700">
                  Repository
                </Label>
                <Input
                  id="smart-repo-url"
                  className="h-9 border-slate-200 bg-white"
                  placeholder="owner/repo or full URL"
                  value={smartUrl}
                  onChange={(e) => setSmartUrl(e.target.value)}
                  spellCheck={false}
                />
                {providerHint && (
                  <Badge variant="secondary" className="text-[10px]">
                    {PROVIDER_HINT_LABEL[providerHint]}
                  </Badge>
                )}
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="smart-branch" className="text-xs font-medium text-slate-700">
                  Branch <span className="font-normal text-slate-500">(optional)</span>
                </Label>
                <Input
                  id="smart-branch"
                  className="h-9 border-slate-200 bg-white"
                  placeholder="main"
                  value={smartBranch}
                  onChange={(e) => setSmartBranch(e.target.value)}
                />
              </div>
              {(providerHint === "generic" || providerHint === null) && smartUrl.trim() && (
                <div className="flex items-start gap-2">
                  <Checkbox
                    id="url-legal"
                    checked={urlLegalConfirm}
                    onCheckedChange={(c) => setUrlLegalConfirm(c === true)}
                  />
                  <Label htmlFor="url-legal" className="text-xs font-normal leading-snug">
                    I have permission to scan this code
                  </Label>
                </div>
              )}
              <Button
                size="sm"
                className="bg-teal-600 hover:bg-teal-700 text-white"
                onClick={() => void handleSmartConnect()}
                disabled={smartConnecting || !smartUrl.trim()}
              >
                {smartConnecting ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Shield className="mr-2 h-4 w-4" />
                )}
                Connect & scan
              </Button>
            </div>
          )}

          {activePill === "svn" && (
            <NewSecurityScanForm
              projects={projects}
              allowedTabs={["svn"]}
              defaultTab="svn"
              embedded
              showOuterCard={false}
              scanType={scanType}
              onScanTypeChange={onScanTypeChange}
              hideScanTypeSelector
            />
          )}

          {activePill === "upload" && (
            <NewSecurityScanForm
              projects={projects}
              allowedTabs={["upload"]}
              defaultTab="upload"
              embedded
              showOuterCard={false}
              scanType={scanType}
              onScanTypeChange={onScanTypeChange}
              hideScanTypeSelector
            />
          )}
        </div>
      </div>
    </div>
  );
}

function IntegrationPanel({
  connected,
  connectedLabel,
  onConnect,
  onImport,
  onDisconnect,
  disconnecting,
  connectDisabled,
  importDisabled,
  settingsLink,
  oauthWarning,
  extraWarning,
}: {
  connected?: boolean;
  connectedLabel: string;
  onConnect: () => void;
  onImport: () => void;
  onDisconnect?: () => void;
  disconnecting?: boolean;
  connectDisabled?: boolean;
  importDisabled?: boolean;
  settingsLink?: boolean;
  oauthWarning?: boolean;
  extraWarning?: string;
}) {
  return (
    <div className="space-y-3">
      {oauthWarning && (
        <p className="flex gap-2 text-xs text-amber-800 dark:text-amber-200">
          <AlertCircle className="h-4 w-4 shrink-0" />
          GitHub OAuth is not configured on this server.
        </p>
      )}
      {extraWarning && (
        <p className="flex gap-2 text-xs text-amber-800 dark:text-amber-200">
          <AlertCircle className="h-4 w-4 shrink-0" />
          {extraWarning}
        </p>
      )}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-start gap-2.5">
          <div
            className={cn(
              "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg",
              connected
                ? "bg-teal-500/15 text-teal-700 dark:text-teal-300"
                : "bg-slate-100 text-slate-500",
            )}
          >
            {connected ? (
              <CheckCircle2 className="h-4 w-4" />
            ) : (
              <AlertCircle className="h-4 w-4" />
            )}
          </div>
          <p className="text-sm text-slate-600 dark:text-slate-400">{connectedLabel}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {connected ? (
            <>
              <Button
                size="sm"
                className="gap-1.5 bg-teal-600 hover:bg-teal-700"
                onClick={onImport}
                disabled={importDisabled}
              >
                <Import className="h-3.5 w-3.5" />
                Browse & import
              </Button>
              {settingsLink && (
                <Button variant="outline" size="sm" asChild>
                  <Link href="/settings/integrations">
                    <Settings className="h-3.5 w-3.5" />
                  </Link>
                </Button>
              )}
              {onDisconnect && (
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={disconnecting}
                  onClick={onDisconnect}
                >
                  <Unplug className="h-3.5 w-3.5" />
                </Button>
              )}
            </>
          ) : (
            <Button size="sm" onClick={onConnect} disabled={connectDisabled}>
              Connect
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
