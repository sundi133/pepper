"use client";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Loader2, RefreshCw, Shield, X } from "lucide-react";
import { cn } from "@/lib/utils";

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
  const importable = items.filter((i) => !i.alreadyConnected);
  const selectedCount = importable.filter((i) => selectedKeys.has(i.key)).length;

  if (!open) return null;

  return (
    <>
      {/* Overlay */}
      <div
        className="fixed inset-0 z-40 bg-black/20 transition-opacity duration-300"
        onClick={() => onOpenChange(false)}
      />

      {/* Sidebar Panel */}
      <div className="fixed right-0 top-0 z-50 h-screen w-full max-w-2xl bg-white shadow-2xl dark:bg-slate-950 flex flex-col animate-in slide-in-from-right">
        {/* Header */}
        <div className="border-b border-slate-200 px-6 py-5 dark:border-slate-800 flex items-center justify-between">
          <div className="flex-1 min-w-0">
            <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-50">
              {title}
            </h2>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
              {description}
            </p>
          </div>
          <button
            onClick={() => onOpenChange(false)}
            className="ml-4 p-1.5 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <ScrollArea className="flex-1">
          <div className="p-6">
            {loading || !loaded ? (
              <div className="flex items-center justify-center gap-2 py-12 text-slate-500 dark:text-slate-400">
                <Loader2 className="h-5 w-5 animate-spin" />
                Loading repositories…
              </div>
            ) : importable.length === 0 && items.length === 0 ? (
              <div className="space-y-4 py-12 text-center">
                <p className="text-sm text-slate-600 dark:text-slate-400">{emptyMessage}</p>
                {emptyHint && (
                  <p className="text-xs text-slate-500 dark:text-slate-500">{emptyHint}</p>
                )}
                <Button
                  variant="outline"
                  disabled={refreshing}
                  onClick={onRefresh}
                  className="mx-auto"
                >
                  {refreshing ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <RefreshCw className="mr-2 h-4 w-4" />
                  )}
                  Check again
                </Button>
              </div>
            ) : (
              <div className="space-y-3">
                {items.map((repo) => (
                  <div
                    key={repo.key}
                    className={cn(
                      "flex items-start gap-4 rounded-lg border p-4 transition-colors",
                      repo.alreadyConnected
                        ? "border-slate-200 bg-slate-50/50 dark:border-slate-800 dark:bg-slate-900/30 opacity-60"
                        : selectedKeys.has(repo.key)
                        ? "border-teal-300 bg-teal-50/50 dark:border-teal-900/50 dark:bg-teal-950/20"
                        : "border-slate-200 bg-white hover:border-slate-300 dark:border-slate-800 dark:bg-slate-900/50 dark:hover:border-slate-700",
                    )}
                  >
                    <Checkbox
                      checked={selectedKeys.has(repo.key)}
                      disabled={repo.alreadyConnected}
                      onCheckedChange={(checked) =>
                        onToggle(repo.key, checked === true, repo.alreadyConnected)
                      }
                      className="mt-1 shrink-0"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="text-sm font-medium text-slate-900 dark:text-slate-50">
                          {repo.fullName}
                        </p>
                        {repo.alreadyConnected && (
                          <Badge variant="secondary" className="text-[10px]">
                            Connected
                          </Badge>
                        )}
                      </div>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                        {repo.defaultBranch}
                        {repo.language ? ` · ${repo.language}` : ""}
                        {repo.private ? " · private" : ""}
                        {repo.subtitle ? ` · ${repo.subtitle}` : ""}
                      </p>
                      {repo.branches && repo.branches.length > 0 && !repo.alreadyConnected && (
                        <div className="mt-3 flex items-center gap-3">
                          <span className="text-xs text-slate-600 dark:text-slate-400 whitespace-nowrap">
                            Branch:
                          </span>
                          <Select
                            value={repo.selectedBranch || repo.defaultBranch}
                            onValueChange={(branch) =>
                              onBranchChange?.(repo.key, branch)
                            }
                          >
                            <SelectTrigger className="h-8 flex-1 max-w-xs border-slate-300 dark:border-slate-700">
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
                ))}
              </div>
            )}
          </div>
        </ScrollArea>

        {/* Footer */}
        <div className="border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 px-6 py-4 flex items-center justify-between gap-3">
          <div className="text-sm text-slate-600 dark:text-slate-400">
            {selectedCount > 0 && (
              <span className="font-medium">{selectedCount} selected</span>
            )}
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              onClick={() => onOpenChange(false)}
              className="border-slate-300 dark:border-slate-700"
            >
              Cancel
            </Button>
            <Button
              onClick={onConnect}
              disabled={
                connecting ||
                selectedCount === 0 ||
                loading ||
                !loaded
              }
              className="gap-2 bg-teal-600 hover:bg-teal-700 text-white"
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
    </>
  );
}
