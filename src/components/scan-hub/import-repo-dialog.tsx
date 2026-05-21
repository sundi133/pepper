"use client";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Loader2, RefreshCw, Shield } from "lucide-react";
import { cn } from "@/lib/utils";
type ImportItem = {
  key: string;
  fullName: string;
  defaultBranch: string;
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
  onConnect,
  onRefresh,
  emptyMessage,
  emptyHint,
}: ImportRepoDialogProps) {
  const importable = items.filter((i) => !i.alreadyConnected);
  const selectedCount = importable.filter((i) => selectedKeys.has(i.key)).length;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        {loading || !loaded ? (
          <div className="flex items-center justify-center gap-2 py-12 text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin" />
            Loading repositories…
          </div>
        ) : importable.length === 0 && items.length === 0 ? (
          <div className="space-y-4 py-6 text-center text-sm text-muted-foreground">
            <p>{emptyMessage}</p>
            {emptyHint ? <p className="text-xs">{emptyHint}</p> : null}
            <Button
              variant="outline"
              disabled={refreshing}
              onClick={onRefresh}
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
          <ScrollArea className="max-h-[min(50vh,360px)] pr-3">
            <ul className="space-y-2">
              {items.map((repo) => (
                <li
                  key={repo.key}
                  className={cn(
                    "flex items-start gap-3 rounded-lg border border-border p-3",
                    repo.alreadyConnected
                      ? "bg-muted/20 opacity-80"
                      : "bg-muted/30",
                  )}
                >
                  <Checkbox
                    checked={selectedKeys.has(repo.key)}
                    disabled={repo.alreadyConnected}
                    onCheckedChange={(checked) =>
                      onToggle(repo.key, checked === true, repo.alreadyConnected)
                    }
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium text-foreground">
                        {repo.fullName}
                      </p>
                      {repo.alreadyConnected && (
                        <Badge variant="secondary" className="text-[10px]">
                          Connected
                        </Badge>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {repo.defaultBranch}
                      {repo.language ? ` · ${repo.language}` : ""}
                      {repo.private ? " · private" : ""}
                      {repo.subtitle ? ` · ${repo.subtitle}` : ""}
                    </p>
                  </div>
                </li>
              ))}
            </ul>
          </ScrollArea>
        )}
        <DialogFooter className="gap-2 sm:gap-0">
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
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
          >
            {connecting ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Connecting…
              </>
            ) : (
              <>
                <Shield className="mr-2 h-4 w-4" />
                Connect {selectedCount > 0 ? `(${selectedCount})` : ""}
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
