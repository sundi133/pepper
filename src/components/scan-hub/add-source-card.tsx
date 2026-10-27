"use client";

import { useState } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import {
  AlertCircle,
  CheckCircle2,
  Import,
  Settings,
  Unplug,
  Upload,
  UploadCloud,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  AzureDevOpsLogo,
  BitbucketLogo,
  GithubLogo,
  SubversionLogo,
} from "@/components/icons/source-logos";
import type { ScanJobData } from "@/lib/queue";
import { NewSecurityScanForm } from "@/components/scans/new-security-scan-form";
import type { ScanProject } from "@/components/scans/types";
import { ScanTypeSelector } from "./scan-type-selector";
import type { RepoProvider } from "./types";
import type { useScanHubIntegrations } from "./use-scan-hub-integrations";

export type SourcePill =
  | RepoProvider
  | "svn"
  | "upload";

type Hub = ReturnType<typeof useScanHubIntegrations>;

type AddSourceCardProps = {
  hub: Hub;
  projects: ScanProject[];
  scanType: ScanJobData["scanType"];
  scanModules: string[];
  onScanTypeChange: (value: ScanJobData["scanType"], modules?: string[]) => void;
};

const SOURCE_OPTIONS: Array<{ id: SourcePill; label: string; icon: React.ReactNode; description: string }> = [
  { id: "github", label: "GitHub", icon: <GithubLogo className="h-6 w-6 text-slate-900 dark:text-slate-100" />, description: "Import from GitHub" },
  { id: "bitbucket", label: "Bitbucket", icon: <BitbucketLogo className="h-6 w-6" />, description: "Import from Bitbucket" },
  { id: "azure", label: "Azure DevOps", icon: <AzureDevOpsLogo className="h-6 w-6" />, description: "Import from Azure DevOps" },
  { id: "svn", label: "SVN", icon: <SubversionLogo className="h-6 w-6" />, description: "Scan an SVN repository" },
  { id: "upload", label: "Upload", icon: <Upload className="h-6 w-6" />, description: "Upload source archive" },
];

export function AddSourceCard({
  hub,
  projects,
  scanType,
  scanModules,
  onScanTypeChange,
}: AddSourceCardProps) {
  const [activePill, setActivePill] = useState<SourcePill>("github");
  function selectPill(pill: SourcePill) {
    setActivePill(pill);
    if (pill === "github" || pill === "bitbucket" || pill === "azure") {
      hub.setProvider(pill);
    }
  }

  const isIntegration =
    activePill === "github" ||
    activePill === "bitbucket" ||
    activePill === "azure";

  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
      <div className="border-b border-slate-100 bg-gradient-to-r from-indigo-50/80 to-white px-6 py-5 dark:border-slate-800 dark:from-indigo-950/20 dark:to-slate-950">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-500 to-blue-600 text-white shadow-sm">
            <UploadCloud className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">
              New Scan
            </h2>
            <p className="mt-0.5 text-sm text-slate-500 dark:text-slate-400">
              Choose a source to scan
            </p>
          </div>
        </div>
      </div>

      <div className="px-6 py-5">
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 mb-5">
          {SOURCE_OPTIONS.map((opt) => {
            const active = activePill === opt.id;
            return (
              <button
                key={opt.id}
                type="button"
                onClick={() => selectPill(opt.id)}
                className={cn(
                  "flex flex-col items-center gap-1.5 rounded-lg border px-3 py-3 text-sm transition-all",
                  active
                    ? "border-indigo-200 bg-indigo-50 text-indigo-700 shadow-sm dark:border-indigo-800 dark:bg-indigo-950/40 dark:text-indigo-300"
                    : "border-slate-200 bg-white text-slate-600 hover:border-indigo-200 hover:bg-indigo-50/50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400",
                )}
              >
                {opt.icon}
                <span className="text-xs font-medium leading-tight text-center">{opt.label}</span>
              </button>
            );
          })}
        </div>

        <ScanTypeSelector value={scanType} modules={scanModules} onChange={onScanTypeChange} />

        <div className="mt-5 rounded-lg border border-slate-200 bg-slate-50/50 p-5 dark:border-slate-700 dark:bg-slate-900/50">
          {isIntegration && activePill === "github" && (
            <IntegrationPanel
              connected={hub.status?.connected}
              connectedLabel={
                hub.status?.connected
                  ? `Signed in as ${hub.status.githubLogin}`
                  : "Connect GitHub to import repositories and open fix PRs."
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
                  : "Connect Bitbucket in Settings to import repositories."
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
                  : "Connect Azure DevOps in Settings to import repositories."
              }
              onConnect={() => hub.router.push("/settings/integrations")}
              onImport={hub.openAzurePicker}
              importDisabled={!hub.azureStatus?.connected}
              settingsLink
            />
          )}

          {isIntegration && (
            <p className="mt-3 text-xs text-slate-400">
              Browse & import queues a scan with the scanners selected above.
            </p>
          )}

          {activePill === "svn" && (
            <NewSecurityScanForm
              projects={projects}
              allowedTabs={["svn"]}
              defaultTab="svn"
              embedded
              showOuterCard={false}
              scanType={scanType}
              scanModules={scanModules}
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
              scanModules={scanModules}
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
        <p className="flex gap-2 text-xs text-amber-700 dark:text-amber-300">
          <AlertCircle className="h-4 w-4 shrink-0" />
          GitHub OAuth is not configured on this server.
        </p>
      )}
      {extraWarning && (
        <p className="flex gap-2 text-xs text-amber-700 dark:text-amber-300">
          <AlertCircle className="h-4 w-4 shrink-0" />
          {extraWarning}
        </p>
      )}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div
            className={cn(
              "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg",
              connected
                ? "bg-indigo-100 text-indigo-600 dark:bg-indigo-900/40 dark:text-indigo-300"
                : "bg-slate-100 text-slate-400 dark:bg-slate-800",
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
                className="gap-1.5 bg-indigo-600 hover:bg-indigo-700 text-white"
                onClick={onImport}
                disabled={importDisabled}
              >
                <Import className="h-3.5 w-3.5" />
                Browse & import
              </Button>
              {onDisconnect && (
                <Button
                  variant="outline"
                  size="sm"
                  className="gap-1.5 border-slate-300"
                  disabled={disconnecting}
                  onClick={onDisconnect}
                >
                  <Unplug className="h-3.5 w-3.5" />
                  Disconnect
                </Button>
              )}
              {settingsLink && (
                <Button variant="outline" size="sm" asChild className="border-slate-300">
                  <Link href="/settings/integrations">
                    <Settings className="h-3.5 w-3.5" />
                  </Link>
                </Button>
              )}
            </>
          ) : (
            <Button size="sm" className="bg-indigo-600 hover:bg-indigo-700 text-white" onClick={onConnect} disabled={connectDisabled}>
              Connect
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
