"use client";

import { useState, useEffect } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { GitBranch } from "lucide-react";
import { toast } from "sonner";

interface GitLabStatus {
  connected: boolean;
  username: string | null;
  hostUrl: string;
  connectedAt: string | null;
  tokenKind?: string | null;
  tokenScopes?: string[];
  tokenExpiresAt?: string | null;
  commitStatuses?: boolean;
}

const DAY = 24 * 60 * 60 * 1000;

/** Warnings about the connected token: a person's token, or one about to expire. */
function tokenWarnings(s: GitLabStatus, now = Date.now()): string[] {
  const out: string[] = [];
  if (s.tokenKind === "personal") {
    out.push("This is a personal access token: it stops working if its owner leaves. A group or project access token is a bot identity that doesn't.");
  }
  if (s.tokenExpiresAt) {
    const left = new Date(s.tokenExpiresAt).getTime() - now;
    if (left <= 0) out.push("The token has expired. Create a new one and reconnect.");
    else if (left < 30 * DAY) out.push(`The token expires in ${Math.ceil(left / DAY)} day(s). Rotate it and reconnect before then.`);
  }
  return out;
}

export function GitLabConnectionCard() {
  const [status, setStatus] = useState<GitLabStatus | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [form, setForm] = useState({ accessToken: "", hostUrl: "https://gitlab.com", commitStatuses: true });
  const [savingStatuses, setSavingStatuses] = useState(false);

  async function refresh() {
    try {
      const res = await fetch("/api/integrations/gitlab/connect");
      if (!res.ok) return;
      const data = (await res.json()) as GitLabStatus;
      setStatus(data);
    } catch {
      /* ignore */
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function connect(e: React.FormEvent) {
    e.preventDefault();
    const accessToken = form.accessToken.trim();
    const hostUrl = form.hostUrl.trim() || "https://gitlab.com";
    if (!accessToken) {
      toast.error("Access token is required");
      return;
    }
    setSubmitting(true);
    try {
      const res = await fetch("/api/integrations/gitlab/connect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ accessToken, hostUrl, commitStatuses: form.commitStatuses }),
      });
      const data = (await res.json()) as { error?: string; username?: string };
      if (!res.ok) throw new Error(data.error || "Failed to connect GitLab");
      toast.success(`GitLab connected as ${data.username ?? "user"}`);
      setForm({ accessToken: "", hostUrl: "https://gitlab.com", commitStatuses: true });
      setFormOpen(false);
      await refresh();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to connect GitLab");
    } finally {
      setSubmitting(false);
    }
  }

  async function toggleStatuses(on: boolean) {
    setSavingStatuses(true);
    try {
      const res = await fetch("/api/integrations/gitlab/connect", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ commitStatuses: on }),
      });
      const data = (await res.json()) as GitLabStatus & { error?: string };
      if (!res.ok) throw new Error(data.error || "Failed to save");
      setStatus(data);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to save");
    } finally {
      setSavingStatuses(false);
    }
  }

  async function disconnect() {
    if (!window.confirm("Disconnect GitLab? Pepper will stop posting inline MR comments until you reconnect.")) return;
    setDisconnecting(true);
    try {
      const res = await fetch("/api/integrations/gitlab/connect", { method: "DELETE" });
      if (!res.ok) throw new Error("Failed to disconnect");
      toast.success("GitLab disconnected");
      setStatus((prev) => prev ? { ...prev, connected: false, username: null } : null);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to disconnect GitLab");
    } finally {
      setDisconnecting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <GitBranch className="h-5 w-5" />
          <CardTitle>GitLab</CardTitle>
          <Badge variant="outline">Access token</Badge>
        </div>
        <CardDescription>
          Connect a GitLab access token so Pepper can clone private projects, review merge
          requests, post inline comments and statuses, answer <code>@pepper</code> commands and
          open fix merge requests. Use a <strong>group access token</strong> (or project access
          token): a bot identity that keeps working when people leave. Role: Developer; scopes:{" "}
          <code>api</code>, <code>read_repository</code>, and <code>write_repository</code> for AI fixes.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {status?.connected ? (
          <>
            <p className="text-sm">
              Connected as <strong>{status.username ?? "GitLab user"}</strong>
              {status.hostUrl && status.hostUrl !== "https://gitlab.com" && (
                <>
                  {" "}on <code className="rounded bg-muted px-1">{status.hostUrl}</code>
                </>
              )}
              {status.tokenKind && (
                <span className="text-muted-foreground">
                  {" "}({status.tokenKind === "bot" ? "group or project access token" : "personal access token"}
                  {status.tokenExpiresAt ? `, expires ${new Date(status.tokenExpiresAt).toLocaleDateString()}` : ""})
                </span>
              )}
            </p>
            {tokenWarnings(status).map((w) => (
              <p key={w} className="text-sm text-amber-600 dark:text-amber-400">{w}</p>
            ))}
            <div className="flex items-start gap-3">
              <Switch
                id="gl-statuses"
                checked={Boolean(status.commitStatuses)}
                disabled={savingStatuses}
                onCheckedChange={(on) => void toggleStatuses(on)}
              />
              <div className="space-y-0.5">
                <Label htmlFor="gl-statuses">Post commit statuses on merge requests</Label>
                <p className="text-xs text-muted-foreground">
                  <code>pepper/security</code>: pending while a review runs, then passed or failed with the
                  build gate. With &quot;Pipelines must succeed&quot;, a failed status blocks the merge.
                </p>
              </div>
            </div>
            <Button
              variant="ghost"
              onClick={() => void disconnect()}
              disabled={disconnecting}
            >
              {disconnecting ? "Disconnecting…" : "Disconnect GitLab"}
            </Button>
          </>
        ) : formOpen ? (
          <form onSubmit={(e) => void connect(e)} className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="gl-token">Access token</Label>
              <Input
                id="gl-token"
                type="password"
                value={form.accessToken}
                onChange={(e) => setForm((f) => ({ ...f, accessToken: e.target.value }))}
                placeholder="glpat-••••••••••••••••••••"
                autoComplete="new-password"
                required
              />
              <p className="text-xs text-muted-foreground">
                Recommended: the group&apos;s Settings → Access tokens (role Developer). A personal
                token from User Settings → Access tokens also works. Scopes: <code>api</code>,{" "}
                <code>read_repository</code>, <code>write_repository</code>.
              </p>
            </div>
            <div className="space-y-1">
              <Label htmlFor="gl-host">GitLab host (self-hosted only)</Label>
              <Input
                id="gl-host"
                value={form.hostUrl}
                onChange={(e) => setForm((f) => ({ ...f, hostUrl: e.target.value }))}
                placeholder="https://gitlab.com"
              />
              <p className="text-xs text-muted-foreground">
                Leave as <code>https://gitlab.com</code> unless you use a self-hosted instance.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Switch
                id="gl-statuses-new"
                checked={form.commitStatuses}
                onCheckedChange={(on) => setForm((f) => ({ ...f, commitStatuses: on }))}
              />
              <Label htmlFor="gl-statuses-new">Post commit statuses on merge requests</Label>
            </div>
            <div className="flex gap-2">
              <Button type="submit" disabled={submitting}>
                {submitting ? "Connecting…" : "Connect"}
              </Button>
              <Button
                type="button"
                variant="ghost"
                onClick={() => { setFormOpen(false); setForm({ accessToken: "", hostUrl: "https://gitlab.com", commitStatuses: true }); }}
                disabled={submitting}
              >
                Cancel
              </Button>
            </div>
          </form>
        ) : (
          <>
            <p className="text-sm text-muted-foreground">
              Not connected. Pepper will skip GitLab MR inline comments until you connect.
            </p>
            <Button onClick={() => setFormOpen(true)}>Connect GitLab</Button>
          </>
        )}
      </CardContent>
    </Card>
  );
}
