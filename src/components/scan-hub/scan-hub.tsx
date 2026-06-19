"use client";

import { useState } from "react";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";
import { useProjects } from "@/hooks/use-scan-polling";
import type { ScanJobData } from "@/lib/queue";
import { AddSourceCard } from "./add-source-card";
import { ImportRepoDialog } from "./import-repo-dialog";
import { RepositoryInventory } from "./repository-inventory";
import { useScanHubIntegrations } from "./use-scan-hub-integrations";

export function ScanHub() {
  const hub = useScanHubIntegrations();
  const { projects } = useProjects();
  const [scanType, setScanType] = useState<ScanJobData["scanType"]>("FULL");

  return (
    <div className="space-y-6 pb-10">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Scan" },
        ]}
      />

      <AddSourceCard
        hub={hub}
        projects={projects}
        scanType={scanType}
        onScanTypeChange={setScanType}
      />

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
      />

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
          language: r.language,
          private: r.private,
        }))}
        selectedKeys={new Set(Array.from(hub.selected).map(String))}
        onToggle={(key, checked) => {
          const id = Number(key);
          const next = new Set(hub.selected);
          if (checked) next.add(id);
          else next.delete(id);
          hub.setSelected(next);
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
