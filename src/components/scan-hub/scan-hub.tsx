"use client";

import { useState } from "react";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";
import { useProjects } from "@/hooks/use-scan-polling";
import type { ScanJobData } from "@/lib/queue";
import {
  CheckCircle2,
  Clock,
  Git,
  HardDrive,
  Zap,
} from "lucide-react";
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
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 pb-10">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="pt-6 pb-6">
          <PageBreadcrumb
            items={[
              { label: "Dashboard", href: "/dashboard" },
              { label: "Scan" },
            ]}
          />
        </div>

        <div className="pb-8">
          <h1 className="text-3xl font-bold text-slate-900 dark:text-slate-50">
            Scan
          </h1>
          <p className="mt-2 text-base text-slate-600 dark:text-slate-400">
            Start a new scan or manage your connected repositories
          </p>
        </div>

        <div className="grid grid-cols-1 gap-8 lg:grid-cols-3">
          {/* Main Content Area */}
          <div className="lg:col-span-2 space-y-6">
            {/* Start a New Scan Section */}
            <AddSourceCard
              hub={hub}
              projects={projects}
              scanType={scanType}
              onScanTypeChange={setScanType}
            />

            {/* Select a Repository Section */}
            <div className="rounded-2xl border border-slate-200/80 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
              <div className="border-b border-slate-200/80 px-6 py-5 dark:border-slate-800">
                <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-50">
                  Select a Repository
                </h2>
                <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
                  Choose from your connected repositories to view details
                </p>
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

            {/* Recent Scans Section */}
            <div className="rounded-2xl border border-slate-200/80 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
              <div className="border-b border-slate-200/80 px-6 py-5 dark:border-slate-800">
                <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-50">
                  Recent Scans
                </h2>
                <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
                  Latest scan activity across your repositories
                </p>
              </div>
              <div className="px-6 py-10 text-center">
                <p className="text-sm text-slate-600 dark:text-slate-400">
                  Select a repository to view its scan history
                </p>
              </div>
            </div>
          </div>

          {/* Sticky Right Panel: Scan Summary */}
          <div className="lg:col-span-1">
            <div className="sticky top-6 rounded-2xl border border-slate-200/80 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
              <div className="border-b border-slate-200/80 px-6 py-5 dark:border-slate-800">
                <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-50">
                  Scan Summary
                </h3>
              </div>

              {selectedRepo ? (
                <div className="px-6 py-5 space-y-6">
                  {/* Repository Info */}
                  <div>
                    <p className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400">
                      Repository
                    </p>
                    <p className="mt-1 text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {selectedRepo.name}
                    </p>
                    <p className="text-xs text-slate-600 dark:text-slate-400">
                      {selectedRepo.fullName}
                    </p>
                  </div>

                  {/* Provider */}
                  <div>
                    <p className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400">
                      Provider
                    </p>
                    <p className="mt-1 inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-medium text-slate-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300">
                      <Git className="h-3 w-3" />
                      {selectedRepo.provider.toUpperCase()}
                    </p>
                  </div>

                  {/* Default Branch */}
                  <div>
                    <p className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400">
                      Default Branch
                    </p>
                    <p className="mt-1 font-mono text-sm text-slate-700 dark:text-slate-300">
                      {selectedRepo.branch}
                    </p>
                  </div>

                  {/* Last Updated */}
                  {selectedRepo.lastScanAt && (
                    <div>
                      <p className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400">
                        Last Scanned
                      </p>
                      <p className="mt-1 text-sm text-slate-700 dark:text-slate-300">
                        {new Date(selectedRepo.lastScanAt).toLocaleDateString()}
                      </p>
                    </div>
                  )}

                  {/* Status */}
                  <div>
                    <p className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400">
                      Scan Status
                    </p>
                    <p className="mt-1 text-sm text-slate-700 dark:text-slate-300">
                      {selectedRepo.scanStatus || "Ready"}
                    </p>
                  </div>

                  {/* Scan Configuration */}
                  <div>
                    <p className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400 mb-3">
                      Enabled Scanners
                    </p>
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 text-sm">
                        <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                        <span className="text-slate-700 dark:text-slate-300">
                          SAST
                        </span>
                      </div>
                      <div className="flex items-center gap-2 text-sm">
                        <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                        <span className="text-slate-700 dark:text-slate-300">
                          Dependency Check
                        </span>
                      </div>
                      <div className="flex items-center gap-2 text-sm">
                        <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                        <span className="text-slate-700 dark:text-slate-300">
                          Secret Scanning
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Estimated Resources */}
                  <div className="rounded-lg bg-slate-50 p-4 dark:bg-slate-900/50">
                    <p className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400 mb-3">
                      Estimated Resources
                    </p>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Clock className="h-4 w-4 text-slate-500" />
                          <span className="text-sm text-slate-700 dark:text-slate-300">
                            Duration
                          </span>
                        </div>
                        <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                          5-10 min
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <HardDrive className="h-4 w-4 text-slate-500" />
                          <span className="text-sm text-slate-700 dark:text-slate-300">
                            Storage
                          </span>
                        </div>
                        <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                          ~100 MB
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Zap className="h-4 w-4 text-slate-500" />
                          <span className="text-sm text-slate-700 dark:text-slate-300">
                            CPU Usage
                          </span>
                        </div>
                        <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                          Moderate
                        </span>
                      </div>
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
