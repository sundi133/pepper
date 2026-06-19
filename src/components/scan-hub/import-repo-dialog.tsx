"use client";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Loader2, RefreshCw, Shield, X, Search } from "lucide-react";
import { cn } from "@/lib/utils";
import { useState, useMemo } from "react";

type ImportItem = {
  key: string;
  fullName: string;
  defaultBranch: string;
  branches?: string[];
  selectedBranch?: string;
  language?: string | null;
  private?: boolean;
  alreadyConnected?: boolean;
  subtitle?: string;
};

type ImportRepoDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: React.ReactNode;
  loading: boolean;
  loaded: boolean;
  refreshing: boolean;
  connecting: boolean;
  items: ImportItem[];
  selectedKeys: Set<string>;
  onToggle: (key: string, checked: boolean, disabled?: boolean) => void;
  onBranchChange?: (key: string, branch: string) => void;
  onConnect: () => void;
  onRefresh: () => void;
  emptyMessage: string;
  emptyHint?: string;
  useNumericKeys?: boolean;
};

export function ImportRepoDialog({
  open,
  onOpenChange,
  title,
  description,
  loading,
  loaded,
  refreshing,
  connecting,
  items,
  selectedKeys,
  onToggle,
  onBranchChange,
  onConnect,
  onRefresh,
  emptyMessage,
  emptyHint,
}: ImportRepoDialogProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedRepoForBranch, setSelectedRepoForBranch] = useState<string | null>(null);

  const importable = items.filter((i) => !i.alreadyConnected);
  const selectedCount = importable.filter((i) => selectedKeys.has(i.key)).length;

  const filteredItems = useMemo(() => {
    if (!searchQuery.trim()) return items;
    const query = searchQuery.toLowerCase();
    return items.filter(
      (item) =>
        item.fullName.toLowerCase().includes(query) ||
        item.language?.toLowerCase().includes(query) ||
        item.subtitle?.toLowerCase().includes(query)
    );
  }, [items, searchQuery]);

  const selectedRepoData = selectedRepoForBranch
    ? items.find((r) => r.key === selectedRepoForBranch)
    : null;

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 bg-gradient-to-br from-slate-50 via-white to-blue-50/30 dark:from-slate-950 dark:via-slate-900 dark:to-slate-900 flex flex-col">
      {/* Header */}
      <div className="border-b border-slate-200/80 dark:border-slate-800 bg-gradient-to-r from-white via-blue-50/40 to-teal-50/40 dark:from-slate-950 dark:via-slate-900/80 dark:to-slate-900 px-8 py-6 flex items-center justify-between sticky top-0 shadow-sm">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-4">
            <h1 className="text-3xl font-bold bg-gradient-to-r from-slate-900 to-teal-600 bg-clip-text text-transparent dark:from-white dark:to-teal-400">
              {title}
            </h1>
            <span className="inline-block px-3 py-1 rounded-full bg-teal-100 text-teal-700 dark:bg-teal-900/40 dark:text-teal-300 text-sm font-semibold">
              {importable.length} available
            </span>
          </div>
          <p className="mt-3 text-base text-slate-600 dark:text-slate-300 leading-relaxed">
            {description}
          </p>
        </div>
        <button
          onClick={() => onOpenChange(false)}
          className="ml-4 p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 rounded-lg hover:bg-slate-200/50 dark:hover:bg-slate-800 transition-all duration-200 flex-shrink-0"
        >
          <X className="h-6 w-6" />
        </button>
      </div>

      {/* Search and Filter Bar */}
      <div className="border-b border-slate-200/60 dark:border-slate-800 bg-white/80 dark:bg-slate-900/40 px-8 py-4 sticky top-[88px] flex items-center gap-3 backdrop-blur-sm">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-400" />
          <Input
            placeholder="Search repositories by name, language…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10 pr-4 py-2.5 border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-50 placeholder-slate-500 dark:placeholder-slate-400 focus:ring-2 focus:ring-teal-500 focus:border-transparent rounded-lg font-medium"
          />
        </div>
        <Button
          variant="outline"
          size="sm"
          disabled={refreshing}
          onClick={onRefresh}
          className="gap-2 flex-shrink-0 border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 font-semibold"
        >
          {refreshing ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <RefreshCw className="h-4 w-4" />
          )}
          Refresh
        </Button>
      </div>

      {/* Main Content - Two Column Layout */}
      <div className="flex-1 overflow-hidden flex">
        {/* Left: Repository List */}
        <div className="flex-1 overflow-auto border-r border-slate-200/60 dark:border-slate-800 bg-gradient-to-b from-white/50 to-slate-50/30 dark:from-slate-900/20 dark:to-slate-950/50">
          {loading || !loaded ? (
            <div className="flex items-center justify-center gap-3 h-full text-slate-500 dark:text-slate-400">
              <Loader2 className="h-6 w-6 animate-spin" />
              <span className="text-lg font-medium">Loading repositories…</span>
            </div>
          ) : importable.length === 0 && items.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full gap-3 text-center px-6">
              <p className="text-base font-semibold text-slate-700 dark:text-slate-300">{emptyMessage}</p>
              {emptyHint && (
                <p className="text-sm text-slate-500 dark:text-slate-400">{emptyHint}</p>
              )}
            </div>
          ) : filteredItems.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full gap-3 text-center px-6">
              <p className="text-base font-semibold text-slate-700 dark:text-slate-300">
                No repositories found matching "{searchQuery}"
              </p>
            </div>
          ) : (
            <div className="divide-y divide-slate-200/50 dark:divide-slate-800/50">
              {filteredItems.map((repo) => (
                <div
                  key={repo.key}
                  onClick={() => {
                    if (
                      repo.branches &&
                      repo.branches.length > 0 &&
                      !repo.alreadyConnected
                    ) {
                      setSelectedRepoForBranch(repo.key);
                    }
                  }}
                  className={cn(
                    "px-8 py-4 flex items-center gap-4 transition-all duration-200 cursor-pointer border-l-4 border-l-transparent",
                    repo.alreadyConnected
                      ? "bg-slate-50/40 dark:bg-slate-900/20 opacity-60 cursor-not-allowed"
                      : selectedKeys.has(repo.key)
                      ? "bg-teal-50/80 dark:bg-teal-950/30 border-l-teal-500"
                      : selectedRepoForBranch === repo.key
                      ? "bg-blue-50/60 dark:bg-blue-950/20 border-l-blue-500"
                      : "hover:bg-gradient-to-r hover:from-slate-50 hover:to-blue-50/30 dark:hover:from-slate-900/40 dark:hover:to-slate-900/20",
                  )}
                >
                  <Checkbox
                    checked={selectedKeys.has(repo.key)}
                    disabled={repo.alreadyConnected}
                    onCheckedChange={(checked) => {
                      onToggle(repo.key, checked === true, repo.alreadyConnected);
                    }}
                    className="shrink-0"
                    onClick={(e) => e.stopPropagation()}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 flex-wrap">
                      <p className="text-base font-bold text-slate-900 dark:text-white tracking-tight">
                        {repo.fullName}
                      </p>
                      {repo.alreadyConnected && (
                        <Badge className="bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300 text-xs font-semibold">
                          ✓ Connected
                        </Badge>
                      )}
                    </div>
                    <div className="mt-2 flex items-center gap-4 text-sm text-slate-600 dark:text-slate-400 font-medium">
                      <span className="inline-flex items-center px-2.5 py-1 rounded-md bg-slate-200/60 dark:bg-slate-800/60 text-slate-700 dark:text-slate-300">
                        📌 {repo.defaultBranch}
                      </span>
                      {repo.language && (
                        <span className="inline-flex items-center gap-1.5">
                          💻 {repo.language}
                        </span>
                      )}
                      {repo.private && (
                        <span className="inline-flex items-center gap-1.5 text-amber-600 dark:text-amber-400">
                          🔒 Private
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: Branch Selector Sidebar */}
        <div className="w-96 bg-gradient-to-b from-blue-50/60 via-white/40 to-teal-50/40 dark:from-slate-800/80 dark:via-slate-900/60 dark:to-slate-900/80 border-l border-slate-200/60 dark:border-slate-800 flex flex-col">
          {selectedRepoData && selectedRepoData.branches && selectedRepoData.branches.length > 0 && !selectedRepoData.alreadyConnected ? (
            <>
              <div className="border-b border-slate-200/60 dark:border-slate-800 px-8 py-5 sticky top-0 bg-gradient-to-r from-blue-100/40 to-teal-100/30 dark:from-slate-800/60 dark:to-slate-800/40">
                <p className="text-lg font-bold text-slate-900 dark:text-white">
                  Select Branch
                </p>
                <p className="text-sm text-slate-600 dark:text-slate-300 mt-2 font-medium truncate">
                  📁 {selectedRepoData.fullName}
                </p>
              </div>
              <div className="flex-1 overflow-auto p-5 space-y-2.5">
                {selectedRepoData.branches.map((branch) => (
                  <button
                    key={branch}
                    onClick={() => onBranchChange?.(selectedRepoData.key, branch)}
                    className={cn(
                      "w-full px-4 py-3.5 rounded-xl text-base font-semibold text-left transition-all duration-200 border-2 shadow-sm hover:shadow-md",
                      (selectedRepoData.selectedBranch || selectedRepoData.defaultBranch) === branch
                        ? "bg-gradient-to-r from-teal-500 to-teal-600 text-white border-teal-700 dark:border-teal-500"
                        : "bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-200 border-slate-300 dark:border-slate-700 hover:border-teal-400 dark:hover:border-teal-500 hover:bg-blue-50/50 dark:hover:bg-slate-700/50",
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <span className="flex items-center gap-2">
                        <span>🌿</span>
                        {branch}
                      </span>
                      {branch === selectedRepoData.defaultBranch && (
                        <span className="text-xs font-bold opacity-80 bg-white/30 px-2 py-1 rounded-lg">
                          DEFAULT
                        </span>
                      )}
                    </div>
                  </button>
                ))}
              </div>
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center text-center px-6 py-8">
              <p className="text-base font-semibold text-slate-500 dark:text-slate-400">
                {selectedRepoData && selectedRepoData.alreadyConnected
                  ? "✓ This repository is already connected"
                  : "👈 Select a repository to choose a branch"}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Footer */}
      <div className="border-t border-slate-200/80 dark:border-slate-800 bg-gradient-to-r from-white via-blue-50/40 to-teal-50/40 dark:from-slate-950 dark:via-slate-900/80 dark:to-slate-900 px-8 py-5 flex items-center justify-between gap-3 sticky bottom-0 shadow-lg">
        <div className="text-base font-semibold">
          {selectedCount > 0 && (
            <span className="text-slate-900 dark:text-white">
              ✨ {selectedCount} of {importable.length} selected
            </span>
          )}
        </div>
        <div className="flex gap-3">
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            className="border-slate-300 dark:border-slate-700 font-semibold hover:bg-slate-100 dark:hover:bg-slate-800 text-base py-2.5 h-auto"
          >
            Close
          </Button>
          <Button
            onClick={onConnect}
            disabled={
              connecting ||
              selectedCount === 0 ||
              loading ||
              !loaded
            }
            className="gap-2 bg-gradient-to-r from-teal-500 to-teal-600 hover:from-teal-600 hover:to-teal-700 text-white px-8 font-semibold text-base py-2.5 h-auto shadow-lg hover:shadow-xl transition-all duration-200 disabled:opacity-50"
          >
            {connecting ? (
              <>
                <Loader2 className="h-5 w-5 animate-spin" />
                Connecting…
              </>
            ) : (
              <>
                <Shield className="h-5 w-5" />
                Connect ({selectedCount})
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}
