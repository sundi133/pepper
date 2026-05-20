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
import { Badge } from "@/components/ui/badge";
import { Copy, Github, ExternalLink, GitBranch } from "lucide-react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

export default function IntegrationsPage() {
  const webhookUrl =
    typeof window !== "undefined"
      ? `${window.location.origin}/api/webhooks`
      : "";

  const [githubConn, setGithubConn] = useState<{
    connected: boolean;
    githubLogin: string | null;
  } | null>(null);
  const [githubDisconnecting, setGithubDisconnecting] = useState(false);

  // ─── Bitbucket Cloud ────────────────────────────────────────────────
  const [bitbucketConn, setBitbucketConn] = useState<{
    connected: boolean;
    username: string | null;
    workspace: string | null;
  } | null>(null);
  const [bitbucketFormOpen, setBitbucketFormOpen] = useState(false);
  const [bitbucketSubmitting, setBitbucketSubmitting] = useState(false);
  const [bitbucketDisconnecting, setBitbucketDisconnecting] = useState(false);
  const [bitbucketForm, setBitbucketForm] = useState({
    username: "",
    appPassword: "",
    workspace: "",
  });

  async function refreshBitbucket() {
    try {
      const res = await fetch("/api/integrations/bitbucket/connect");
      if (!res.ok) return;
      const data = (await res.json()) as {
        connected?: boolean;
        username?: string | null;
        workspace?: string | null;
      };
      setBitbucketConn({
        connected: Boolean(data.connected),
        username: data.username ?? null,
        workspace: data.workspace ?? null,
      });
    } catch {
      /* ignore */
    }
  }

  useEffect(() => {
    void (async () => {
      try {
        const res = await fetch("/api/integrations/github");
        if (!res.ok) return;
        const data = (await res.json()) as {
          connected?: boolean;
          githubLogin?: string | null;
        };
        setGithubConn({
          connected: Boolean(data.connected),
          githubLogin: data.githubLogin ?? null,
        });
      } catch {
        /* ignore */
      }
    })();
    void refreshBitbucket();
  }, []);

  async function connectBitbucket(e: React.FormEvent) {
    e.preventDefault();
    const username = bitbucketForm.username.trim();
    const appPassword = bitbucketForm.appPassword.trim();
    const workspace = bitbucketForm.workspace.trim();
    if (!username || !appPassword) {
      toast.error("Username and app password are required");
      return;
    }
    setBitbucketSubmitting(true);
    try {
      const res = await fetch("/api/integrations/bitbucket/connect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          appPassword,
          workspace: workspace || undefined,
        }),
      });
      const data = (await res.json()) as { error?: string };
      if (!res.ok) {
        throw new Error(data.error || "Failed to connect Bitbucket");
      }
      toast.success("Bitbucket connected");
      setBitbucketForm({ username: "", appPassword: "", workspace: "" });
      setBitbucketFormOpen(false);
      await refreshBitbucket();
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Failed to connect Bitbucket",
      );
    } finally {
      setBitbucketSubmitting(false);
    }
  }

  async function disconnectBitbucket() {
    if (
      !window.confirm(
        "Disconnect Bitbucket? Pepper will stop posting PR review comments and build statuses to your Bitbucket repositories.",
      )
    ) {
      return;
    }
    setBitbucketDisconnecting(true);
    try {
      const res = await fetch("/api/integrations/bitbucket/connect", {
        method: "DELETE",
      });
      if (!res.ok) throw new Error("Failed to disconnect");
      toast.success("Bitbucket disconnected");
      setBitbucketConn({ connected: false, username: null, workspace: null });
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Failed to disconnect Bitbucket",
      );
    } finally {
      setBitbucketDisconnecting(false);
    }
  }

  async function disconnectGithubOAuth() {
    if (
      !window.confirm(
        "Disconnect GitHub? You will need to authorize again to import repositories or open fix pull requests.",
      )
    ) {
      return;
    }
    setGithubDisconnecting(true);
    try {
      const res = await fetch("/api/integrations/github", { method: "DELETE" });
      const j = (await res.json()) as { error?: string };
      if (!res.ok) throw new Error(j.error || "Failed to disconnect");
      toast.success("GitHub disconnected");
      setGithubConn({ connected: false, githubLogin: null });
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to disconnect GitHub");
    } finally {
      setGithubDisconnecting(false);
    }
  }

  function copyUrl(url: string) {
    navigator.clipboard.writeText(url);
    toast.success("Copied to clipboard");
  }

  return (
    <div className="max-w-2xl space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Integrations" },
        ]}
      />
      <div>
        <h1 className="text-2xl font-bold">Integrations</h1>
        <p className="text-muted-foreground">
          Connect external services to Pepper
        </p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Github className="h-5 w-5" />
            <CardTitle>GitHub</CardTitle>
            <Badge variant="outline">OAuth</Badge>
          </div>
          <CardDescription>
            One GitHub authorization for importing repositories, cloning private
            repos for scans, and opening AI fix pull requests from findings. No
            personal access tokens to paste.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {githubConn?.connected ? (
            <p className="text-sm">
              Connected as{" "}
              <strong>{githubConn.githubLogin ?? "GitHub user"}</strong>
            </p>
          ) : (
            <p className="text-sm text-muted-foreground">
              Not connected. Use Repositories or click Open fix PR on a finding
              to authorize GitHub.
            </p>
          )}
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" asChild>
              <Link href="/repositories">
                <ExternalLink className="mr-2 h-4 w-4" />
                Manage repositories
              </Link>
            </Button>
            {githubConn?.connected ? (
              <Button
                variant="ghost"
                onClick={() => void disconnectGithubOAuth()}
                disabled={githubDisconnecting}
              >
                {githubDisconnecting ? "Disconnecting…" : "Disconnect GitHub"}
              </Button>
            ) : (
              <Button asChild>
                <a href="/api/integrations/github/connect?returnTo=%2Frepositories">
                  Connect GitHub
                </a>
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Github className="h-5 w-5" />
            <CardTitle>GitHub webhooks</CardTitle>
            <Badge variant="outline">Webhook</Badge>
          </div>
          <CardDescription>
            Scan pull requests on every update and re-run SAST when code is merged
            or pushed to your default branch (e.g. main).
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Webhook URL</Label>
            <div className="flex gap-2">
              <Input value={`${webhookUrl}/github`} readOnly />
              <Button
                variant="outline"
                size="icon"
                onClick={() => copyUrl(`${webhookUrl}/github`)}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>
          <div className="text-sm text-muted-foreground space-y-1">
            <p>
              1. In your GitHub repo: Settings → Webhooks → Add webhook
            </p>
            <p>2. Paste the URL above and set Content type to JSON</p>
            <p>
              3. Enable <strong>Pull request</strong> and <strong>Push</strong>{" "}
              events
            </p>
            <p>
              4. Set the secret to match{" "}
              <code>GITHUB_WEBHOOK_SECRET</code> on your Pepper instance
            </p>
            <p>
              5. Link the repo in Pepper (Repositories or a GitHub URL project)
              so <code>repoUrl</code> matches <code>owner/repo</code>
            </p>
            <p>
              Merges and pushes to the project default branch queue a{" "}
              <code>SAST_ONLY</code> scan (override with{" "}
              <code>GITHUB_WEBHOOK_MAIN_SCAN_TYPE=FULL</code> if needed).
            </p>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <GitBranch className="h-5 w-5" />
            <CardTitle>Bitbucket Cloud</CardTitle>
            <Badge variant="outline">App password</Badge>
          </div>
          <CardDescription>
            Post PR security review summaries, inline comments and build
            statuses on Bitbucket Cloud pull requests. Uses an app password
            scoped per org — not your account password.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {bitbucketConn?.connected ? (
            <>
              <p className="text-sm">
                Connected as <strong>{bitbucketConn.username}</strong>
                {bitbucketConn.workspace ? (
                  <>
                    {" "}
                    on workspace{" "}
                    <code className="rounded bg-muted px-1">
                      {bitbucketConn.workspace}
                    </code>
                  </>
                ) : null}
              </p>
              <Button
                variant="ghost"
                onClick={() => void disconnectBitbucket()}
                disabled={bitbucketDisconnecting}
              >
                {bitbucketDisconnecting
                  ? "Disconnecting…"
                  : "Disconnect Bitbucket"}
              </Button>
            </>
          ) : bitbucketFormOpen ? (
            <form
              onSubmit={(e) => void connectBitbucket(e)}
              className="space-y-3"
            >
              <div className="space-y-1">
                <Label htmlFor="bb-username">Bitbucket username</Label>
                <Input
                  id="bb-username"
                  value={bitbucketForm.username}
                  onChange={(e) =>
                    setBitbucketForm((f) => ({
                      ...f,
                      username: e.target.value,
                    }))
                  }
                  placeholder="your-bitbucket-username"
                  autoComplete="off"
                  required
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="bb-apppassword">App password</Label>
                <Input
                  id="bb-apppassword"
                  type="password"
                  value={bitbucketForm.appPassword}
                  onChange={(e) =>
                    setBitbucketForm((f) => ({
                      ...f,
                      appPassword: e.target.value,
                    }))
                  }
                  placeholder="ATBB••••••••"
                  autoComplete="new-password"
                  required
                />
                <p className="text-xs text-muted-foreground">
                  Create one at Bitbucket → Personal settings → App passwords.
                  Required scopes: <code>account:read</code>,{" "}
                  <code>repository:read</code>, <code>repository:write</code>,{" "}
                  <code>pullrequest:write</code>.
                </p>
              </div>
              <div className="space-y-1">
                <Label htmlFor="bb-workspace">Workspace (optional)</Label>
                <Input
                  id="bb-workspace"
                  value={bitbucketForm.workspace}
                  onChange={(e) =>
                    setBitbucketForm((f) => ({
                      ...f,
                      workspace: e.target.value,
                    }))
                  }
                  placeholder="my-workspace-slug"
                  autoComplete="off"
                />
              </div>
              <div className="flex gap-2">
                <Button type="submit" disabled={bitbucketSubmitting}>
                  {bitbucketSubmitting ? "Connecting…" : "Connect"}
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => {
                    setBitbucketFormOpen(false);
                    setBitbucketForm({
                      username: "",
                      appPassword: "",
                      workspace: "",
                    });
                  }}
                  disabled={bitbucketSubmitting}
                >
                  Cancel
                </Button>
              </div>
            </form>
          ) : (
            <>
              <p className="text-sm text-muted-foreground">
                Not connected. Pepper will skip Bitbucket PR comments and build
                statuses until you connect.
              </p>
              <Button onClick={() => setBitbucketFormOpen(true)}>
                Connect Bitbucket
              </Button>
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <GitBranch className="h-5 w-5" />
            <CardTitle>Bitbucket webhooks</CardTitle>
            <Badge variant="outline">Webhook</Badge>
          </div>
          <CardDescription>
            Scan pull requests on every update. Pair with the Bitbucket Cloud
            connection above so Pepper can post the review back.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Webhook URL</Label>
            <div className="flex gap-2">
              <Input value={`${webhookUrl}/bitbucket`} readOnly />
              <Button
                variant="outline"
                size="icon"
                onClick={() => copyUrl(`${webhookUrl}/bitbucket`)}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>
          <div className="text-sm text-muted-foreground space-y-1">
            <p>1. In your Bitbucket repo: Settings → Webhooks → Add webhook</p>
            <p>2. Paste the URL above</p>
            <p>
              3. Enable <strong>Pull request → Created</strong> and{" "}
              <strong>Pull request → Updated</strong>
            </p>
            <p>
              4. Set the secret to match{" "}
              <code>BITBUCKET_WEBHOOK_SECRET</code> on your Pepper instance
              (optional — signature is only verified when the env var is set)
            </p>
            <p>
              5. Link the repo in Pepper by setting{" "}
              <code>bitbucketWorkspace</code> + <code>bitbucketRepoSlug</code>{" "}
              on the project, or include <code>workspace/repo-slug</code> in{" "}
              <code>repoUrl</code>.
            </p>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <CardTitle>GitLab</CardTitle>
            <Badge variant="outline">Webhook</Badge>
          </div>
          <CardDescription>Automatically scan merge requests</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Webhook URL</Label>
            <div className="flex gap-2">
              <Input value={`${webhookUrl}/gitlab`} readOnly />
              <Button
                variant="outline"
                size="icon"
                onClick={() => copyUrl(`${webhookUrl}/gitlab`)}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>
          <div className="text-sm text-muted-foreground space-y-1">
            <p>1. Go to your GitLab project Settings &gt; Webhooks</p>
            <p>2. Add webhook with the URL above</p>
            <p>3. Select &quot;Merge request events&quot;</p>
            <p>
              4. Set the GITLAB_WEBHOOK_SECRET env var on your Pepper instance
            </p>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <CardTitle>CI/CD</CardTitle>
            <Badge variant="outline">API</Badge>
          </div>
          <CardDescription>
            Drop-in pipeline templates with fail-build gates, SBOM upload and
            optional cosign signing.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-sm">
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" asChild>
              <a href="/api/cicd-templates/github" download>
                GitHub Actions
              </a>
            </Button>
            <Button variant="outline" asChild>
              <a href="/api/cicd-templates/gitlab" download>
                GitLab CI
              </a>
            </Button>
            <Button variant="outline" asChild>
              <a href="/api/cicd-templates/jenkins" download>
                Jenkinsfile
              </a>
            </Button>
            <Button variant="outline" asChild>
              <Link href="/settings/apikeys">Manage API keys</Link>
            </Button>
          </div>
          <p className="text-muted-foreground">
            Each template uses <code>PEPPER_API_URL</code> +{" "}
            <code>PEPPER_API_KEY</code>, downloads CycloneDX + SPDX SBOMs, and
            fails the build when the project&apos;s build gate is breached.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Outbound integrations</CardTitle>
          <CardDescription>
            Send findings and scan summaries to ticketing, chat and SIEM tools.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" asChild>
              <Link href="/settings/integrations/outbound">Slack, Jira, SIEM, Dapper</Link>
            </Button>
            <Button variant="outline" asChild>
              <Link href="/settings/integrations/precommit">Pre-commit hook</Link>
            </Button>
            <Button variant="outline" asChild>
              <Link href="/settings/integrations/ide">IDE plugins</Link>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
