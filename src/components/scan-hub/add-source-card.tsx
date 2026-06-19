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
    <div className="flex h-full flex-col overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
      <div className="border-b border-slate-200 px-6 py-5 dark:border-slate-800">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-teal-500/15 text-teal-600 dark:text-teal-400">
            <UploadCloud className="h-4 w-4" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-50">
              Start a Scan
            </h2>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
              Connect a repository, upload code, or use a URL
            </p>
          </div>
        </div>
      </div>

      <div className="flex flex-1 flex-col gap-5 px-6 py-5">
        <div className="flex flex-wrap gap-2">
          {pill("github", "GitHub", <Github className="h-3.5 w-3.5" />)}
          {pill("bitbucket", "Bitbucket", <GitBranch className="h-3.5 w-3.5" />)}
          {pill("azure", "Azure DevOps", <Cloud className="h-3.5 w-3.5" />)}
          {pill("url", "Repository URL", <Link2 className="h-3.5 w-3.5" />)}
          {pill("svn", "SVN", <FolderArchive className="h-3.5 w-3.5" />)}
          {pill("upload", "Upload", <Upload className="h-3.5 w-3.5" />)}
        </div>

        <ScanTypeSelector value={scanType} onChange={onScanTypeChange} />

        <div className="min-h-[200px] flex-1 rounded-lg border border-slate-200 bg-slate-50 p-5 dark:border-slate-800 dark:bg-slate-900/50">
          {isIntegration && activePill === "github" && (
            <IntegrationPanel
              connected={hub.status?.connected}
              connectedLabel={
                hub.status?.connected
                  ? `Signed in as ${hub.status.githubLogin}`
                  : "Connect GitHub in Settings → Integrations to import private repositories and open fix PRs."
              }
              onConnect={() => hub.router.push("/settings/integrations")}
              onImport={hub.openGithubPicker}
              importDisabled={!hub.status?.connected}
              settingsLink
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
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Connecting a repository queues an <strong>All</strong> scanners scan. Use Repository URL, SVN, or Upload to select a specific scanner set.
            </p>
          )}

          {activePill === "url" && (
            <div className="space-y-4">
              <div>
                <Label htmlFor="smart-repo-url" className="block text-sm font-medium text-slate-900 dark:text-slate-100 mb-2">
                  Repository URL
                </Label>
                <Input
                  id="smart-repo-url"
                  className="h-10 border-slate-200 bg-white dark:border-slate-700 dark:bg-slate-900"
                  placeholder="e.g., github.com/owner/repo or owner/repo"
                  value={smartUrl}
                  onChange={(e) => setSmartUrl(e.target.value)}
                  spellCheck={false}
                />
                {providerHint && (
                  <div className="mt-2">
                    <Badge variant="secondary" className="text-xs">
                      {PROVIDER_HINT_LABEL[providerHint]}
                    </Badge>
                  </div>
                )}
              </div>
              <div>
                <Label htmlFor="smart-branch" className="block text-sm font-medium text-slate-900 dark:text-slate-100 mb-2">
                  Branch <span className="font-normal text-slate-500">(optional)</span>
                </Label>
                <Input
                  id="smart-branch"
                  className="h-10 border-slate-200 bg-white dark:border-slate-700 dark:bg-slate-900"
                  placeholder="e.g., main, develop"
                  value={smartBranch}
                  onChange={(e) => setSmartBranch(e.target.value)}
                />
              </div>
              {(providerHint === "generic" || providerHint === null) && smartUrl.trim() && (
                <div className="flex items-start gap-2 rounded-lg bg-blue-50 p-3 dark:bg-blue-950/30">
                  <Checkbox
                    id="url-legal"
                    checked={urlLegalConfirm}
                    onCheckedChange={(c) => setUrlLegalConfirm(c === true)}
                    className="mt-1"
                  />
                  <Label htmlFor="url-legal" className="text-xs font-normal leading-snug text-slate-700 dark:text-slate-300">
                    I have permission to scan this code
                  </Label>
                </div>
              )}
              <Button
                size="lg"
                className="w-full bg-teal-600 hover:bg-teal-700 text-white font-medium"
                onClick={() => void handleSmartConnect()}
                disabled={smartConnecting || !smartUrl.trim()}
              >
                {smartConnecting ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Shield className="mr-2 h-4 w-4" />
                )}
                Start Scan
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
    <div className="space-y-4">
      {oauthWarning && (
        <div className="flex gap-2 rounded-lg bg-amber-50 p-3 text-xs text-amber-800 dark:bg-amber-950/30 dark:text-amber-200">
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
          <span>GitHub OAuth is not configured on this server.</span>
        </div>
      )}
      {extraWarning && (
        <div className="flex gap-2 rounded-lg bg-amber-50 p-3 text-xs text-amber-800 dark:bg-amber-950/30 dark:text-amber-200">
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
          <span>{extraWarning}</span>
        </div>
      )}
      <div className="flex items-center gap-3 rounded-lg bg-slate-50 p-3.5 dark:bg-slate-900/40">
        <div
          className={cn(
            "flex h-8 w-8 shrink-0 items-center justify-center rounded-lg",
            connected
              ? "bg-teal-500/15 text-teal-700 dark:text-teal-300"
              : "bg-slate-200 text-slate-500",
          )}
        >
          {connected ? (
            <CheckCircle2 className="h-4 w-4" />
          ) : (
            <AlertCircle className="h-4 w-4" />
          )}
        </div>
        <p className="flex-1 text-sm text-slate-700 dark:text-slate-300">{connectedLabel}</p>
      </div>
      <div className="flex flex-wrap gap-2">
        {connected ? (
          <>
            <Button
              size="sm"
              className="flex-1 gap-2 bg-teal-600 hover:bg-teal-700 sm:flex-none"
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
          <Button
            size="sm"
            className="w-full sm:w-auto"
            onClick={onConnect}
            disabled={connectDisabled}
          >
            Connect
          </Button>
        )}
      </div>
    </div>
  );
}
