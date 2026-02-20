"use client";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

export default function IntegrationsPage() {
  const webhookUrl = typeof window !== "undefined" ? `${window.location.origin}/api/webhooks` : "";

  function copyUrl(url: string) {
    navigator.clipboard.writeText(url);
    toast.success("Copied to clipboard");
  }

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Integrations</h1>
        <p className="text-muted-foreground">
          Connect Pepper with your CI/CD and SCM platforms
        </p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <CardTitle>GitHub</CardTitle>
            <Badge variant="outline">Webhook</Badge>
          </div>
          <CardDescription>
            Automatically scan pull requests when they are opened or updated
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Webhook URL</Label>
            <div className="flex gap-2">
              <Input value={`${webhookUrl}/github`} readOnly />
              <Button variant="outline" size="icon" onClick={() => copyUrl(`${webhookUrl}/github`)}>
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>
          <div className="space-y-2">
            <Label>Events to subscribe</Label>
            <p className="text-sm text-muted-foreground">Pull requests</p>
          </div>
          <div className="text-sm text-muted-foreground space-y-1">
            <p>1. Go to your GitHub repository Settings &gt; Webhooks</p>
            <p>2. Add webhook with the URL above</p>
            <p>3. Set content type to application/json</p>
            <p>4. Select &quot;Pull requests&quot; events</p>
            <p>5. Set the GITHUB_WEBHOOK_SECRET env var on your Pepper instance</p>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <CardTitle>GitLab</CardTitle>
            <Badge variant="outline">Webhook</Badge>
          </div>
          <CardDescription>
            Automatically scan merge requests
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Webhook URL</Label>
            <div className="flex gap-2">
              <Input value={`${webhookUrl}/gitlab`} readOnly />
              <Button variant="outline" size="icon" onClick={() => copyUrl(`${webhookUrl}/gitlab`)}>
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>
          <div className="text-sm text-muted-foreground space-y-1">
            <p>1. Go to your GitLab project Settings &gt; Webhooks</p>
            <p>2. Add webhook with the URL above</p>
            <p>3. Select &quot;Merge request events&quot;</p>
            <p>4. Set the GITLAB_WEBHOOK_SECRET env var on your Pepper instance</p>
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
