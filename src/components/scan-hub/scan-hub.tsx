"use client";

import { useState } from "react";
import { useProjects } from "@/hooks/use-scan-polling";
import type { ScanJobData } from "@/lib/queue";
import {
  CheckCircle2,
  Clock,
  Lock,
  GitBranch,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { AddSourceCard } from "./add-source-card";
import { ImportRepoDialog } from "./import-repo-dialog";
import { RepositoryInventory } from "./repository-inventory";
import { useScanHubIntegrations } from "./use-scan-hub-integrations";
import type { UnifiedConnectedRepo } from "./types";

export function ScanHub() {
  const hub = useScanHubIntegrations();
  const { projects } = useProjects();
  const [scanType, setScanType] = useState<ScanJobData["scanType"]>("FULL");
  const [selectedRepo, setSelectedRepo] = useState<UnifiedConnectedRepo | null>(
    null
  );

  const handleRepoSelect = (repo: UnifiedConnectedRepo) => {
    setSelectedRepo(repo);
  };

  return (
    <div className="min-h-screen bg-white dark:bg-slate-950">
      <div className="px-8 py-8">
        {/* Page Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-slate-900 dark:text-white">
            Scan
          </h1>
          <p className="mt-2 text-base text-slate-600 dark:text-slate-400">
            Scan your code for vulnerabilities, secrets, and misconfigurations.
          </p>
        </div>

        {/* Two Column Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Left Column (75%) */}
          <div className="lg:col-span-3 space-y-6">
            {/* Card 1: Start a New Scan */}
            <div className="rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
              <div className="border-b border-slate-200 px-6 py-5 dark:border-slate-800">
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
                  Start a New Scan
                </h2>
                <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
                  Connect a repository or upload code to begin a security scan.
                </p>
              </div>
              <div className="px-6 py-5">
                <AddSourceCard
                  hub={hub}
                  projects={projects}
                  scanType={scanType}
                  onScanTypeChange={setScanType}
                />
              </div>
            </div>

            {/* Card 2: Scan Presets */}
            <div className="rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
              <div className="border-b border-slate-200 px-6 py-5 dark:border-slate-800">
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
                  Scan Presets
                </h2>
                <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
                  Use a preset scan configuration or create your own.
                </p>
              </div>
              <div className="px-6 py-5">
                <div>
                  <label className="block text-sm font-medium text-slate-900 dark:text-white mb-4">
                    Default (Recommended)
                  </label>
                  <div className="space-y-2.5">
                    <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-900/30">
                      <CheckCircle2 className="h-5 w-5 text-emerald-500 flex-shrink-0" />
                      <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                        SAST
                      </span>
                    </div>
                    <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-900/30">
                      <CheckCircle2 className="h-5 w-5 text-emerald-500 flex-shrink-0" />
                      <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                        SCA
                      </span>
                    </div>
                    <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-900/30">
                      <CheckCircle2 className="h-5 w-5 text-emerald-500 flex-shrink-0" />
                      <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                        Secrets
                      </span>
                    </div>
                    <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-900/30">
                      <CheckCircle2 className="h-5 w-5 text-emerald-500 flex-shrink-0" />
                      <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                        IaC
                      </span>
                    </div>
                    <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-slate-50 dark:bg-slate-900/30">
                      <CheckCircle2 className="h-5 w-5 text-emerald-500 flex-shrink-0" />
                      <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                        Container
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Card 3: Repository Selection */}
            <div className="rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
              <div className="border-b border-slate-200 px-6 py-5 dark:border-slate-800">
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
                  Select a Repository
                </h2>
              </div>
              <RepositoryInventory
                repos={hub.filteredConnected}
                projects={projects}
                loading={hub.loading}
                providerFilter={hub.providerFilter}
                onProviderFilterChange={hub.setProviderFilter}
                searchQuery={hub.searchQuery}
                onSearchChange={hub.setSearchQuery}
                onRefresh={() => void hub.refreshAll()}
                stats={hub.stats}
                scanType={scanType}
                selectedRepo={selectedRepo}
                onSelectRepo={handleRepoSelect}
              />
            </div>

            {/* Card 4: Recent Scans */}
            <div className="rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
              <div className="border-b border-slate-200 px-6 py-5 dark:border-slate-800 flex items-center justify-between">
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
                  Recent Scans
                </h2>
                <a href="#" className="text-sm font-semibold text-blue-600 dark:text-blue-400 hover:underline">
                  View all scans →
                </a>
              </div>
              <div className="px-6 py-10 text-center">
                <p className="text-sm text-slate-600 dark:text-slate-400">
                  Select a repository to view its scan history
                </p>
              </div>
            </div>
          </div>

          {/* Right Column (25%) - Sticky Sidebar */}
          <div className="lg:col-span-1">
            <div className="sticky top-6 space-y-6">
              {/* Scan Summary Card */}
              <div className="rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
                <div className="border-b border-slate-200 px-6 py-5 dark:border-slate-800 flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
                    Scan Summary
                  </h3>
                  {selectedRepo && (
                    <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300">
                      <span className="inline-block w-2 h-2 rounded-full bg-emerald-500" />
                      <span className="text-xs font-semibold">Ready</span>
                    </span>
                  )}
                </div>

                {selectedRepo ? (
                  <div className="px-6 py-5 space-y-5">
                    {/* Repository */}
                    <div>
                      <p className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400 mb-1">
                        Repository
                      </p>
                      <p className="text-sm font-semibold text-slate-900 dark:text-white">
                        {selectedRepo.name}
                      </p>
                    </div>

                    {/* Provider */}
                    <div>
                      <p className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400 mb-2">
                        Provider
                      </p>
                      <span className="inline-flex items-center gap-2 text-sm font-medium text-slate-700 dark:text-slate-300">
                        <GitBranch className="h-4 w-4" />
                        {selectedRepo.provider === "github"
                          ? "GitHub"
                          : selectedRepo.provider === "gitlab"
                            ? "GitLab"
                            : selectedRepo.provider === "bitbucket"
                              ? "Bitbucket"
                              : selectedRepo.provider === "azure"
                                ? "Azure DevOps"
                                : selectedRepo.provider}
                      </span>
                    </div>

                    {/* Default Branch */}
                    <div>
                      <p className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400 mb-1">
                        Default Branch
                      </p>
                      <p className="text-sm font-mono text-slate-900 dark:text-white">
                        {selectedRepo.branch}
                      </p>
                    </div>

                    {/* Last Updated */}
                    {selectedRepo.lastScanAt && (
                      <div>
                        <p className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400 mb-1">
                          Last Updated
                        </p>
                        <p className="text-sm text-slate-700 dark:text-slate-300">
                          2 hours ago
                        </p>
                      </div>
                    )}

                    {/* Visibility */}
                    <div>
                      <p className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400 mb-2">
                        Visibility
                      </p>
                      <div className="flex items-center gap-2">
                        <Lock className="h-4 w-4 text-slate-500" />
                        <span className="text-sm text-slate-700 dark:text-slate-300">
                          Private
                        </span>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="px-6 py-10 text-center">
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      Select a repository to view summary details
                    </p>
                  </div>
                )}
              </div>

              {/* Scan Configuration Card */}
              {selectedRepo && (
                <div className="rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
                  <div className="border-b border-slate-200 px-6 py-5 dark:border-slate-800 flex items-center justify-between">
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
                      Scan Configuration
                    </h3>
                    <button className="text-xs font-semibold text-blue-600 dark:text-blue-400 hover:underline">
                      Edit
                    </button>
                  </div>

                  <div className="px-6 py-5 space-y-4">
                    {/* Scanner List */}
                    <div className="space-y-2.5">
                      <div className="flex items-start gap-3">
                        <CheckCircle2 className="h-5 w-5 text-emerald-500 flex-shrink-0 mt-0.5" />
                        <div className="flex-1">
                          <p className="text-sm font-medium text-slate-900 dark:text-white">
                            SAST
                          </p>
                          <p className="text-xs text-slate-500 dark:text-slate-400">
                            Semgrep, CodeQL
                          </p>
                        </div>
                      </div>
                      <div className="flex items-start gap-3">
                        <CheckCircle2 className="h-5 w-5 text-emerald-500 flex-shrink-0 mt-0.5" />
                        <div className="flex-1">
                          <p className="text-sm font-medium text-slate-900 dark:text-white">
                            SCA
                          </p>
                          <p className="text-xs text-slate-500 dark:text-slate-400">
                            OWASP Dependency Check
                          </p>
                        </div>
                      </div>
                      <div className="flex items-start gap-3">
                        <CheckCircle2 className="h-5 w-5 text-emerald-500 flex-shrink-0 mt-0.5" />
                        <div className="flex-1">
                          <p className="text-sm font-medium text-slate-900 dark:text-white">
                            Secrets
                          </p>
                          <p className="text-xs text-slate-500 dark:text-slate-400">
                            Gitleaks
                          </p>
                        </div>
                      </div>
                      <div className="flex items-start gap-3">
                        <CheckCircle2 className="h-5 w-5 text-emerald-500 flex-shrink-0 mt-0.5" />
                        <div className="flex-1">
                          <p className="text-sm font-medium text-slate-900 dark:text-white">
                            IaC
                          </p>
                          <p className="text-xs text-slate-500 dark:text-slate-400">
                            Checkov
                          </p>
                        </div>
                      </div>
                      <div className="flex items-start gap-3">
                        <CheckCircle2 className="h-5 w-5 text-emerald-500 flex-shrink-0 mt-0.5" />
                        <div className="flex-1">
                          <p className="text-sm font-medium text-slate-900 dark:text-white">
                            Container
                          </p>
                          <p className="text-xs text-slate-500 dark:text-slate-400">
                            Trivy
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Divider */}
                    <div className="border-t border-slate-200 dark:border-slate-800 pt-4" />

                    {/* Estimated Duration */}
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium text-slate-900 dark:text-white">
                          Estimated Duration
                        </span>
                        <Clock className="h-4 w-4 text-slate-400" />
                      </div>
                      <p className="text-sm text-slate-700 dark:text-slate-300">
                        3–5 minutes
                      </p>
                    </div>

                    {/* Estimated Resources */}
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium text-slate-900 dark:text-white">
                          Estimated Resources
                        </span>
                        <span className="text-sm font-semibold text-slate-700 dark:text-slate-300">
                          Medium
                        </span>
                      </div>
                    </div>

                    {/* Action Buttons */}
                    <div className="space-y-3 pt-2">
                      <Button className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2.5 h-auto rounded-lg">
                        ▶ Start Scan
                      </Button>
                      <Button
                        variant="outline"
                        className="w-full border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 font-semibold py-2.5 h-auto rounded-lg"
                      >
                        Save as Preset
                      </Button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      <ImportRepoDialog
        open={hub.pickOpen}
        onOpenChange={hub.onPickOpenChange}
        title="Import GitHub repositories"
        description="Select repos to connect. An initial full scan is queued for each."
        loading={hub.pickLoading}
        loaded={hub.pickLoaded}
        refreshing={hub.pickRefreshing}
        connecting={hub.connecting}
        items={hub.importable.map((r) => ({
          key: String(r.id),
          fullName: r.fullName,
          defaultBranch: r.defaultBranch,
          branches: r.branches?.length ? r.branches : [r.defaultBranch],
          selectedBranch: hub.selectedBranches[r.id] || r.defaultBranch,
          language: r.language,
          private: r.private,
        }))}
        selectedKeys={new Set(Array.from(hub.selected).map(String))}
        onToggle={(key, checked) => {
          const id = Number(key);
          const next = new Set(hub.selected);
          if (checked) {
            next.add(id);
            void hub.loadBranchesForRepo(id);
          } else {
            next.delete(id);
          }
          hub.setSelected(next);
        }}
        onBranchChange={(key, branch) => {
          const id = Number(key);
          hub.setSelectedBranches({
            ...hub.selectedBranches,
            [id]: branch,
          });
        }}
        onConnect={() => void hub.importSelected()}
        onRefresh={() => void hub.loadAvailable({ quiet: true })}
        emptyMessage={
          hub.connected.length > 0
            ? `All visible GitHub repositories are already connected (${hub.connected.length} in Pepper).`
            : "No repositories found on your GitHub account."
        }
        emptyHint="Use Repository URL in Add Source to connect a repo not listed here."
      />

      <ImportRepoDialog
        open={hub.bitbucketPickOpen}
        onOpenChange={hub.onBitbucketPickOpenChange}
        title="Import Bitbucket repositories"
        description={
          <>
            Repositories in workspace{" "}
            <code className="text-xs">{hub.bitbucketStatus?.workspace}</code>.
            A full scan runs when you click Connect.
          </>
        }
        loading={hub.bitbucketPickLoading}
        loaded={hub.bitbucketPickLoaded}
        refreshing={hub.bitbucketPickRefreshing}
        connecting={hub.bitbucketConnecting}
        items={hub.bitbucketAvailable.map((r) => ({
          key: r.uuid,
          fullName: r.fullName,
          defaultBranch: r.defaultBranch,
          language: r.language,
          private: r.private,
          alreadyConnected: r.alreadyConnected,
        }))}
        selectedKeys={hub.bitbucketSelected}
        onToggle={(key, checked, disabled) => {
          if (disabled) return;
          const next = new Set(hub.bitbucketSelected);
          if (checked) next.add(key);
          else next.delete(key);
          hub.setBitbucketSelected(next);
        }}
        onConnect={() => void hub.importBitbucketSelected()}
        onRefresh={() => void hub.loadBitbucketAvailable({ quiet: true })}
        emptyMessage={
          hub.bitbucketStatus?.workspace
            ? `No repositories found in workspace ${hub.bitbucketStatus.workspace}.`
            : "No repositories available to import."
        }
        emptyHint="Use Repository URL in Add Source for repos outside this workspace."
      />

      <ImportRepoDialog
        open={hub.azurePickOpen}
        onOpenChange={hub.onAzurePickOpenChange}
        title="Import Azure DevOps repositories"
        description={
          <>
            Organization{" "}
            <code className="text-xs">{hub.azureStatus?.azureOrganization}</code>.
            A full scan runs when you click Connect.
          </>
        }
        loading={hub.azurePickLoading}
        loaded={hub.azurePickLoaded}
        refreshing={hub.azurePickRefreshing}
        connecting={hub.azureConnecting}
        items={hub.azureAvailable.map((r) => ({
          key: r.id,
          fullName: r.fullName,
          defaultBranch: r.defaultBranch,
          alreadyConnected: r.alreadyConnected,
        }))}
        selectedKeys={hub.azureSelected}
        onToggle={(key, checked, disabled) => {
          if (disabled) return;
          const next = new Set(hub.azureSelected);
          if (checked) next.add(key);
          else next.delete(key);
          hub.setAzureSelected(next);
        }}
        onConnect={() => void hub.importAzureSelected()}
        onRefresh={() => void hub.loadAzureAvailable({ quiet: true })}
        emptyMessage={
          hub.azureStatus?.azureOrganization
            ? `No repositories in ${hub.azureStatus.azureOrganization}.`
            : "No repositories available to import."
        }
        emptyHint="Use Repository URL in Add Source for other repos your PAT can access."
      />
    </div>
  );
}
