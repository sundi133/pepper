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
import { Copy, Github, ExternalLink } from "lucide-react";
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
  }, []);

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
            Integrate scans into any CI pipeline using the API
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="text-sm space-y-2">
            <p className="font-medium">Example: GitHub Actions</p>
            <pre className="rounded-md bg-muted p-4 text-xs overflow-x-auto">
              {`- name: Run Pepper Scan
  run: |
    curl -X POST \\
      \${PEPPER_URL}/api/scans \\
      -H "Authorization: Bearer \${PEPPER_API_KEY}" \\
      -F "data={\\\"projectId\\\":\\\"...\\\",\\\"scanType\\\":\\\"FULL\\\"}" \\
      -F "file=@source.zip"`}
            </pre>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
