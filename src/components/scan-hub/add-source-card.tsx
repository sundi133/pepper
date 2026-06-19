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
          ? "border-teal-500/60 bg-teal-500/10 text-teal-800 shadow-sm"
          : "border-slate-200/90 bg-white/80 text-slate-600 hover:border-teal-400/50 hover:text-teal-800",
      )}
    >
      {icon}
      {label}
    </button>
  );


  return (
    <div className="flex flex-col overflow-hidden">
      <div className="flex flex-col gap-4">
        <div className="flex flex-wrap gap-2">
          {pill("url", "Repository URL", <Link2 className="h-3.5 w-3.5" />)}
          {pill("svn", "SVN", <FolderArchive className="h-3.5 w-3.5" />)}
          {pill("upload", "Upload", <Upload className="h-3.5 w-3.5" />)}
        </div>

        <ScanTypeSelector value={scanType} onChange={onScanTypeChange} />

        <div className="min-h-[200px] rounded-lg border border-slate-200 bg-slate-50 p-5">
          {activePill === "url" && (
            <div className="space-y-4">
              <div>
                <Label htmlFor="smart-repo-url" className="block text-sm font-medium text-slate-900 mb-2">
                  Repository URL
                </Label>
                <Input
                  id="smart-repo-url"
                  className="h-10 border-slate-200 bg-white"
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
                <Label htmlFor="smart-branch" className="block text-sm font-medium text-slate-900 mb-2">
                  Branch <span className="font-normal text-slate-500">(optional)</span>
                </Label>
                <Input
                  id="smart-branch"
                  className="h-10 border-slate-200 bg-white"
                  placeholder="e.g., main, develop"
                  value={smartBranch}
                  onChange={(e) => setSmartBranch(e.target.value)}
                />
              </div>
              {(providerHint === "generic" || providerHint === null) && smartUrl.trim() && (
                <div className="flex items-start gap-2 rounded-lg bg-blue-50 p-3">
                  <Checkbox
                    id="url-legal"
                    checked={urlLegalConfirm}
                    onCheckedChange={(c) => setUrlLegalConfirm(c === true)}
                    className="mt-1"
                  />
                  <Label htmlFor="url-legal" className="text-xs font-normal leading-snug text-slate-700">
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
        <div className="flex gap-2 rounded-lg bg-amber-50 p-3 text-xs text-amber-800">
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
          <span>GitHub OAuth is not configured on this server.</span>
        </div>
      )}
      {extraWarning && (
        <div className="flex gap-2 rounded-lg bg-amber-50 p-3 text-xs text-amber-800">
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
          <span>{extraWarning}</span>
        </div>
      )}
      <div className="flex items-center gap-3 rounded-lg bg-slate-50 p-3.5">
        <div
          className={cn(
            "flex h-8 w-8 shrink-0 items-center justify-center rounded-lg",
            connected
              ? "bg-teal-500/15 text-teal-700"
              : "bg-slate-200 text-slate-500",
          )}
        >
          {connected ? (
            <CheckCircle2 className="h-4 w-4" />
          ) : (
            <AlertCircle className="h-4 w-4" />
          )}
        </div>
        <p className="flex-1 text-sm text-slate-700">{connectedLabel}</p>
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
