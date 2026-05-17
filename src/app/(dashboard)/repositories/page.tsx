"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Github,
  GitBranch,
  Link2,
  Loader2,
  RefreshCw,
  Shield,
  Unplug,
  AlertCircle,
  CheckCircle2,
  Import,
} from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

type GithubStatus = {
  connected: boolean;
  githubLogin: string | null;
  oauthConfigured: boolean;
};

type ConnectedRepo = {
  projectId: string;
  name: string;
  owner: string;
  fullName: string;
  defaultBranch: string;
  branch: string;
  language: string;
  coverage: string;
  scanStatus: string;
  lastScanAt: string | null;
  findingsCount: number;
  scanId: string | null;
};

type AvailableRepo = {
  id: number;
  fullName: string;
  defaultBranch: string;
  language: string | null;
  private: boolean;
  alreadyConnected: boolean;
};

const SCAN_STATUS_LABEL: Record<
  string,
  { label: string; variant: "default" | "secondary" | "destructive" | "outline" }
> = {
  PENDING: { label: "Pending", variant: "secondary" },
  SCANNING: { label: "Scanning", variant: "default" },
  ISSUES: { label: "Issues", variant: "destructive" },
  PASSED: { label: "Passed", variant: "outline" },
  FAILED: { label: "Failed", variant: "destructive" },
};

function formatLastScan(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

function ConnectedRepoCard({ repo }: { repo: ConnectedRepo }) {
  const st = SCAN_STATUS_LABEL[repo.scanStatus] ?? SCAN_STATUS_LABEL.PENDING;
  const href = repo.scanId
    ? `/scans/${repo.scanId}`
    : `/projects/${repo.projectId}`;

  return (
    <Link
      href={href}
      className="surface-card block p-4 transition-colors hover:border-primary/40 hover:bg-accent/30 lg:hidden"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="font-semibold text-foreground truncate">{repo.name}</p>
          <p className="text-help text-xs">{repo.fullName}</p>
        </div>
        <Badge variant={st.variant}>{st.label}</Badge>
      </div>
      <dl className="mt-3 grid grid-cols-2 gap-2 text-xs">
        <div>
          <dt className="text-muted-foreground">Branch</dt>
          <dd className="font-mono text-foreground">{repo.branch}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Findings</dt>
          <dd className="font-medium text-foreground">{repo.findingsCount}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Language</dt>
          <dd className="text-foreground">{repo.language || "—"}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Last scan</dt>
          <dd className="text-foreground">{formatLastScan(repo.lastScanAt)}</dd>
        </div>
      </dl>
    </Link>
  );
}

export default function RepositoriesPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [status, setStatus] = useState<GithubStatus | null>(null);
  const [connected, setConnected] = useState<ConnectedRepo[]>([]);
  const [available, setAvailable] = useState<AvailableRepo[]>([]);
  const [loading, setLoading] = useState(true);
  const [pickOpen, setPickOpen] = useState(false);
  const [pickLoading, setPickLoading] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [manualRepoUrl, setManualRepoUrl] = useState("");
  const [manualBranch, setManualBranch] = useState("");
  const [manualConnecting, setManualConnecting] = useState(false);

  const githubQuery = searchParams.get("github");
  const pickQuery = searchParams.get("pick");
  const errorMessage = searchParams.get("message");

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    try {
      const [statusRes, connectedRes] = await Promise.all([
        fetch("/api/integrations/github"),
        fetch("/api/integrations/github/repositories/connected"),
      ]);
      const statusJson = (await statusRes.json()) as GithubStatus & {
        error?: string;
      };
      const connectedJson = (await connectedRes.json()) as {
        repositories?: ConnectedRepo[];
        error?: string;
      };
      if (!statusRes.ok) throw new Error(statusJson.error || "Failed to load GitHub status");
      if (!connectedRes.ok) {
        throw new Error(connectedJson.error || "Failed to load repositories");
      }
      setStatus(statusJson);
      setConnected(connectedJson.repositories ?? []);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to load repositories");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadAvailable = useCallback(async () => {
    setPickLoading(true);
    try {
      const res = await fetch("/api/integrations/github/repositories");
      const json = (await res.json()) as {
        repositories?: AvailableRepo[];
        error?: string;
        code?: string;
      };
      if (!res.ok) {
        if (json.code === "GITHUB_TOKEN_INVALID") {
          setStatus((s) => (s ? { ...s, connected: false } : s));
        }
        throw new Error(json.error || "Failed to list GitHub repositories");
      }
      setAvailable(json.repositories ?? []);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to list repositories");
      setAvailable([]);
    } finally {
      setPickLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);

  const hasActiveScan = connected.some(
    (r) => r.scanStatus === "SCANNING" || r.scanStatus === "PENDING",
  );

  useEffect(() => {
    if (!hasActiveScan) return;
    const t = window.setInterval(() => void loadDashboard(), 5000);
    return () => window.clearInterval(t);
  }, [hasActiveScan, loadDashboard]);

  useEffect(() => {
    if (githubQuery === "connected") {
      toast.success("GitHub connected successfully");
      router.replace("/repositories", { scroll: false });
    } else if (githubQuery === "error") {
      toast.error(
        errorMessage
          ? decodeURIComponent(errorMessage)
          : "GitHub authorization failed",
      );
      router.replace("/repositories", { scroll: false });
    }
  }, [githubQuery, errorMessage, router]);

  useEffect(() => {
    if (pickQuery === "1" && status?.connected) {
      setPickOpen(true);
      void loadAvailable();
      router.replace("/repositories", { scroll: false });
    }
  }, [pickQuery, status?.connected, loadAvailable, router]);

  const importable = useMemo(
    () => available.filter((r) => !r.alreadyConnected),
    [available],
  );

  function connectGithub() {
    window.location.href = "/api/integrations/github/connect?returnTo=%2Frepositories";
  }

  async function disconnectGithub() {
    if (
      !window.confirm(
        "Disconnect GitHub? Import and private clone stop until you connect again.",
      )
    ) {
      return;
    }
    setDisconnecting(true);
    try {
      const res = await fetch("/api/integrations/github", { method: "DELETE" });
      const json = (await res.json()) as { error?: string };
      if (!res.ok) throw new Error(json.error || "Failed to disconnect");
      toast.success("GitHub disconnected");
      setStatus((s) =>
        s ? { ...s, connected: false, githubLogin: null } : s,
      );
      setPickOpen(false);
      setAvailable([]);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to disconnect");
    } finally {
      setDisconnecting(false);
    }
  }

  async function importSelected() {
    if (selected.size === 0) return;
    setConnecting(true);
    try {
      const res = await fetch("/api/integrations/github/repositories/connect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoIds: Array.from(selected) }),
      });
      const json = (await res.json()) as {
        connected?: { fullName: string }[];
        error?: string;
      };
      if (!res.ok) {
        throw new Error(json.error || "Failed to connect repositories");
      }
      const n = json.connected?.length ?? 0;
      toast.success(
        n > 0
          ? `Connected ${n} repositor${n === 1 ? "y" : "ies"} and queued scan${n === 1 ? "" : "s"}`
          : "No new repositories were connected",
      );
      setSelected(new Set());
      setPickOpen(false);
      await loadDashboard();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to connect repositories");
    } finally {
      setConnecting(false);
    }
  }

  function openPicker() {
    setPickOpen(true);
    setSelected(new Set());
    void loadAvailable();
  }

  async function connectManualRepo() {
    const url = manualRepoUrl.trim();
    if (!url) {
      toast.error("Enter a GitHub repository URL or owner/repo");
      return;
    }
    if (!status?.connected) {
      window.location.href = `/api/integrations/github/connect?returnTo=${encodeURIComponent("/repositories")}`;
      return;
    }
    setManualConnecting(true);
    try {
      const res = await fetch("/api/integrations/github/repositories/connect-manual", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repoUrl: url,
          branch: manualBranch.trim() || undefined,
        }),
      });
      const json = (await res.json()) as {
        error?: string;
        code?: string;
        fullName?: string;
        created?: boolean;
      };
      if (!res.ok) {
        if (json.code === "GITHUB_OAUTH_REQUIRED") {
          window.location.href = `/api/integrations/github/connect?returnTo=${encodeURIComponent("/repositories")}`;
          return;
        }
        throw new Error(json.error || "Failed to connect repository");
      }
      toast.success(
        json.created
          ? `Connected ${json.fullName} and queued scan`
          : `Rescanned ${json.fullName}`,
      );
      setManualRepoUrl("");
      setManualBranch("");
      await loadDashboard();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to connect repository");
    } finally {
      setManualConnecting(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Repositories" },
        ]}
      />

      <div>
        <h1 className="text-2xl font-bold tracking-tight text-foreground sm:text-3xl">
          Repositories
        </h1>
        <p className="text-help mt-2 max-w-2xl">
          Connect GitHub once, import projects, or add any repo by URL. Use the same
          login for scans and AI fix pull requests.
        </p>
      </div>

      {!loading && status?.oauthConfigured === false && (
        <Card className="border-amber-500/50 bg-amber-50 dark:bg-amber-500/10">
          <CardContent className="flex gap-3 py-4 text-sm text-foreground">
            <AlertCircle className="h-5 w-5 shrink-0 text-amber-600 dark:text-amber-400" />
            <p>
              GitHub OAuth is not configured. Set{" "}
              <code className="rounded bg-muted px-1">GITHUB_OAUTH_CLIENT_ID</code> and{" "}
              <code className="rounded bg-muted px-1">GITHUB_OAUTH_CLIENT_SECRET</code>{" "}
              in your server environment.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Connection status strip */}
      <Card
        className={cn(
          "overflow-hidden",
          status?.connected
            ? "border-primary/30 bg-primary/5"
            : "border-border",
        )}
      >
        <CardContent className="flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-3">
            <div
              className={cn(
                "flex h-11 w-11 shrink-0 items-center justify-center rounded-xl",
                status?.connected
                  ? "bg-primary/15 text-primary"
                  : "bg-muted text-muted-foreground",
              )}
            >
              <Github className="h-6 w-6" aria-hidden />
            </div>
            <div>
              <p className="text-label">
                {status?.connected ? "GitHub connected" : "GitHub not connected"}
              </p>
              {status?.connected ? (
                <p className="text-help mt-0.5 flex items-center gap-1.5">
                  <CheckCircle2 className="h-4 w-4 text-primary" />
                  Signed in as <strong className="text-foreground">{status.githubLogin}</strong>
                </p>
              ) : (
                <p className="text-help mt-0.5">
                  Authorize to import repos, clone private code, and open fix PRs.
                </p>
              )}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {status?.connected ? (
              <>
                <Button onClick={openPicker} className="gap-2">
                  <Import className="h-4 w-4" />
                  Import from GitHub
                </Button>
                <Button
                  variant="outline"
                  onClick={() => void loadDashboard()}
                  disabled={loading}
                >
                  <RefreshCw className="h-4 w-4 sm:mr-2" />
                  <span className="hidden sm:inline">Refresh</span>
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => void disconnectGithub()}
                  disabled={disconnecting}
                  className="text-muted-foreground"
                >
                  <Unplug className="h-4 w-4 sm:mr-2" />
                  <span className="hidden sm:inline">
                    {disconnecting ? "Disconnecting…" : "Disconnect"}
                  </span>
                </Button>
              </>
            ) : (
              <Button
                onClick={connectGithub}
                disabled={status?.oauthConfigured === false}
                className="gap-2"
              >
                <Github className="h-4 w-4" />
                Connect GitHub
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Two ways to add repos */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Import className="h-4 w-4 text-primary" />
              Import from your account
            </CardTitle>
            <CardDescription>
              Pick repositories from GitHub. Each import queues an initial full scan.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button
              variant="outline"
              className="w-full sm:w-auto"
              onClick={openPicker}
              disabled={!status?.connected}
            >
              Browse GitHub repositories
            </Button>
            {!status?.connected && (
              <p className="text-help mt-3">Connect GitHub above to enable import.</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Link2 className="h-4 w-4 text-primary" />
              Add by URL
            </CardTitle>
            <CardDescription>
              Any repo your GitHub user can access — <code className="text-xs">owner/repo</code> or full URL.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="manual-repo-url" className="text-label">
                Repository
              </Label>
              <Input
                id="manual-repo-url"
                placeholder="owner/repo or https://github.com/owner/repo"
                value={manualRepoUrl}
                onChange={(e) => setManualRepoUrl(e.target.value)}
                spellCheck={false}
                disabled={!status?.connected}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="manual-repo-branch" className="text-label">
                Branch <span className="font-normal text-muted-foreground">(optional)</span>
              </Label>
              <Input
                id="manual-repo-branch"
                placeholder="main"
                value={manualBranch}
                onChange={(e) => setManualBranch(e.target.value)}
                disabled={!status?.connected}
              />
            </div>
            <Button
              className="w-full sm:w-auto"
              onClick={() => void connectManualRepo()}
              disabled={
                manualConnecting || !manualRepoUrl.trim() || !status?.connected
              }
            >
              {manualConnecting ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Connecting…
                </>
              ) : (
                "Connect & scan"
              )}
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Connected list */}
      <Card>
        <CardHeader>
          <CardTitle>Connected repositories</CardTitle>
          <CardDescription>
            {connected.length > 0
              ? `${connected.length} repositor${connected.length === 1 ? "y" : "ies"} linked to Pepper`
              : "Import or add a repository to get started"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center gap-2 py-16 text-muted-foreground">
              <Loader2 className="h-5 w-5 animate-spin" />
              Loading…
            </div>
          ) : connected.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 py-14 text-center">
              <Github className="h-12 w-12 text-muted-foreground/50" />
              <p className="font-medium text-foreground">No repositories yet</p>
              <p className="text-help max-w-sm">
                {status?.connected
                  ? "Use Import or Add by URL above."
                  : "Connect GitHub to begin."}
              </p>
            </div>
          ) : (
            <>
              <div className="space-y-3 lg:hidden">
                {connected.map((repo) => (
                  <ConnectedRepoCard key={repo.projectId} repo={repo} />
                ))}
              </div>
              <div className="hidden overflow-x-auto lg:block">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Repository</TableHead>
                      <TableHead>Owner</TableHead>
                      <TableHead>Branch</TableHead>
                      <TableHead>Language</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Findings</TableHead>
                      <TableHead>Last scan</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {connected.map((repo) => {
                      const st =
                        SCAN_STATUS_LABEL[repo.scanStatus] ??
                        SCAN_STATUS_LABEL.PENDING;
                      return (
                        <TableRow key={repo.projectId}>
                          <TableCell className="font-medium text-foreground">
                            <Link
                              href={
                                repo.scanId
                                  ? `/scans/${repo.scanId}`
                                  : `/projects/${repo.projectId}`
                              }
                              className="hover:text-primary hover:underline"
                            >
                              {repo.name}
                            </Link>
                          </TableCell>
                          <TableCell>{repo.owner}</TableCell>
                          <TableCell>
                            <span className="inline-flex items-center gap-1 font-mono text-xs">
                              <GitBranch className="h-3 w-3" />
                              {repo.branch}
                            </span>
                          </TableCell>
                          <TableCell>{repo.language}</TableCell>
                          <TableCell>
                            <Badge variant={st.variant}>{st.label}</Badge>
                          </TableCell>
                          <TableCell className="text-right font-medium">
                            {repo.findingsCount}
                          </TableCell>
                          <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                            {formatLastScan(repo.lastScanAt)}
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <Dialog open={pickOpen} onOpenChange={setPickOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Import repositories</DialogTitle>
            <DialogDescription>
              Select repos to connect. An initial full scan is queued for each.
            </DialogDescription>
          </DialogHeader>
          {pickLoading ? (
            <div className="flex items-center justify-center gap-2 py-12 text-muted-foreground">
              <Loader2 className="h-5 w-5 animate-spin" />
              Loading from GitHub…
            </div>
          ) : importable.length === 0 ? (
            <div className="space-y-4 py-6 text-center text-sm text-muted-foreground">
              <p>Nothing new to import.</p>
              <Button variant="outline" onClick={() => void loadAvailable()}>
                <RefreshCw className="mr-2 h-4 w-4" />
                Retry
              </Button>
            </div>
          ) : (
            <ScrollArea className="max-h-[min(50vh,360px)] pr-3">
              <ul className="space-y-2">
                {importable.map((repo) => (
                  <li
                    key={repo.id}
                    className="flex items-start gap-3 rounded-lg border border-border bg-muted/30 p-3"
                  >
                    <Checkbox
                      checked={selected.has(repo.id)}
                      onCheckedChange={(checked) => {
                        const next = new Set(selected);
                        if (checked) next.add(repo.id);
                        else next.delete(repo.id);
                        setSelected(next);
                      }}
                    />
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-foreground">
                        {repo.fullName}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {repo.defaultBranch}
                        {repo.language ? ` · ${repo.language}` : ""}
                        {repo.private ? " · private" : ""}
                      </p>
                    </div>
                  </li>
                ))}
              </ul>
            </ScrollArea>
          )}
          <DialogFooter className="gap-2 sm:gap-0">
            <Button variant="ghost" onClick={() => setPickOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => void importSelected()}
              disabled={connecting || selected.size === 0 || pickLoading}
            >
              {connecting ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Connecting…
                </>
              ) : (
                <>
                  <Shield className="mr-2 h-4 w-4" />
                  Connect {selected.size > 0 ? `(${selected.size})` : ""}
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
