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
import { GitBranch } from "lucide-react";
import { toast } from "sonner";

interface GitLabStatus {
  connected: boolean;
  username: string | null;
  hostUrl: string;
  connectedAt: string | null;
}

export function GitLabConnectionCard() {
  const [status, setStatus] = useState<GitLabStatus | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [form, setForm] = useState({ accessToken: "", hostUrl: "https://gitlab.com" });

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
        body: JSON.stringify({ accessToken, hostUrl }),
      });
      const data = (await res.json()) as { error?: string; username?: string };
      if (!res.ok) throw new Error(data.error || "Failed to connect GitLab");
      toast.success(`GitLab connected as ${data.username ?? "user"}`);
      setForm({ accessToken: "", hostUrl: "https://gitlab.com" });
      setFormOpen(false);
      await refresh();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to connect GitLab");
    } finally {
      setSubmitting(false);
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
          <Badge variant="outline">PAT</Badge>
        </div>
        <CardDescription>
          Connect a GitLab Personal Access Token so Pepper can post inline security
          comments on merge requests — just like GitHub and Bitbucket.
          Requires scopes: <code>api</code> (or at minimum <code>read_user</code> +{" "}
          <code>read_api</code> + <code>write_note</code>).
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
            </p>
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
              <Label htmlFor="gl-token">Personal Access Token</Label>
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
                Create at GitLab → User Settings → Access Tokens.
                Required scopes: <code>api</code>.
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
            <div className="flex gap-2">
              <Button type="submit" disabled={submitting}>
                {submitting ? "Connecting…" : "Connect"}
              </Button>
              <Button
                type="button"
                variant="ghost"
                onClick={() => { setFormOpen(false); setForm({ accessToken: "", hostUrl: "https://gitlab.com" }); }}
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
