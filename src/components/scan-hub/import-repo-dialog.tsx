"use client";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
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

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 bg-white dark:bg-slate-950 flex flex-col">
      {/* Header */}
      <div className="border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 px-6 py-5 flex items-center justify-between sticky top-0">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-50">
              {title}
            </h1>
            <span className="text-sm font-medium text-teal-600 dark:text-teal-400">
              {importable.length} available
            </span>
          </div>
          <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
            {description}
          </p>
        </div>
        <button
          onClick={() => onOpenChange(false)}
          className="ml-4 p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors flex-shrink-0"
        >
          <X className="h-6 w-6" />
        </button>
      </div>

      {/* Search and Filter Bar */}
      <div className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 px-6 py-4 sticky top-[88px] flex items-center gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <Input
            placeholder="Search repositories…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9 border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900"
          />
        </div>
        <Button
          variant="outline"
          size="sm"
          disabled={refreshing}
          onClick={onRefresh}
          className="gap-2 flex-shrink-0 border-slate-300 dark:border-slate-700"
        >
          {refreshing ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <RefreshCw className="h-4 w-4" />
          )}
          Refresh
        </Button>
      </div>

      {/* Content Grid */}
      <div className="flex-1 overflow-auto">
        {loading || !loaded ? (
          <div className="flex items-center justify-center gap-2 h-full text-slate-500 dark:text-slate-400">
            <Loader2 className="h-5 w-5 animate-spin" />
            Loading repositories…
          </div>
        ) : importable.length === 0 && items.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 text-center px-6">
            <p className="text-sm text-slate-600 dark:text-slate-400">{emptyMessage}</p>
            {emptyHint && (
              <p className="text-xs text-slate-500 dark:text-slate-500">{emptyHint}</p>
            )}
          </div>
        ) : filteredItems.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 text-center px-6">
            <p className="text-sm text-slate-600 dark:text-slate-400">
              No repositories found matching "{searchQuery}"
            </p>
          </div>
        ) : (
          <div className="p-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredItems.map((repo) => (
              <div
                key={repo.key}
                className={cn(
                  "rounded-lg border p-4 transition-all cursor-pointer",
                  repo.alreadyConnected
                    ? "border-slate-200 bg-slate-50 dark:border-slate-800 dark:bg-slate-900/30 opacity-60 cursor-not-allowed"
                    : selectedKeys.has(repo.key)
                    ? "border-teal-400 bg-teal-50 dark:border-teal-600/50 dark:bg-teal-950/30 ring-2 ring-teal-500/20"
                    : "border-slate-200 bg-white hover:border-slate-300 hover:shadow-md dark:border-slate-800 dark:bg-slate-900/50 dark:hover:border-slate-700",
                )}
                onClick={() => {
                  if (!repo.alreadyConnected) {
                    onToggle(repo.key, !selectedKeys.has(repo.key), false);
                  }
                }}
              >
                <div className="flex items-start gap-3">
                  <Checkbox
                    checked={selectedKeys.has(repo.key)}
                    disabled={repo.alreadyConnected}
                    onCheckedChange={(checked) =>
                      onToggle(repo.key, checked === true, repo.alreadyConnected)
                    }
                    className="mt-1 shrink-0"
                    onClick={(e) => e.stopPropagation()}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="text-sm font-semibold text-slate-900 dark:text-slate-50 truncate">
                        {repo.fullName}
                      </p>
                      {repo.alreadyConnected && (
                        <Badge variant="secondary" className="text-[10px] flex-shrink-0">
                          Connected
                        </Badge>
                      )}
                    </div>
                    <div className="mt-2 space-y-1">
                      <p className="text-xs text-slate-500 dark:text-slate-400">
                        <span className="font-medium">Branch:</span> {repo.defaultBranch}
                      </p>
                      {(repo.language || repo.private) && (
                        <p className="text-xs text-slate-500 dark:text-slate-400">
                          {repo.language && <span>{repo.language}</span>}
                          {repo.language && repo.private && <span> · </span>}
                          {repo.private && <span>Private</span>}
                        </p>
                      )}
                      {repo.subtitle && (
                        <p className="text-xs text-slate-500 dark:text-slate-400">
                          {repo.subtitle}
                        </p>
                      )}
                    </div>
                    {repo.branches && repo.branches.length > 0 && !repo.alreadyConnected && (
                      <div className="mt-3 flex items-center gap-2">
                        <span className="text-xs text-slate-600 dark:text-slate-400 whitespace-nowrap">
                          Branch:
                        </span>
                        <Select
                          value={repo.selectedBranch || repo.defaultBranch}
                          onValueChange={(branch) => {
                            onBranchChange?.(repo.key, branch);
                          }}
                        >
                          <SelectTrigger className="h-8 w-full text-xs border-slate-300 dark:border-slate-700">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {repo.branches.map((branch) => (
                              <SelectItem key={branch} value={branch}>
                                {branch}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 px-6 py-4 flex items-center justify-between gap-3 sticky bottom-0">
        <div className="text-sm text-slate-600 dark:text-slate-400">
          {selectedCount > 0 && (
            <span className="font-semibold text-slate-900 dark:text-slate-50">
              {selectedCount} of {importable.length} selected
            </span>
          )}
        </div>
        <div className="flex gap-3">
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            className="border-slate-300 dark:border-slate-700"
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
            className="gap-2 bg-teal-600 hover:bg-teal-700 text-white px-6"
          >
            {connecting ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Connecting…
              </>
            ) : (
              <>
                <Shield className="h-4 w-4" />
                Connect ({selectedCount})
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}
