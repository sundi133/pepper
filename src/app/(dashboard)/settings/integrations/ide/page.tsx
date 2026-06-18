"use client";

import { useState, useEffect } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Copy, Check } from "lucide-react";
import Link from "next/link";
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

export default function IdeIntegrationPage() {
  const [baseUrl] = useState(() =>
    typeof window !== "undefined" ? window.location.origin : "",
  );
  const [projects, setProjects] = useState<Array<{ id: string; name: string }>>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>("");
  const [apiKeys, setApiKeys] = useState<Array<{ id: string; prefix: string; name: string }>>([]);
  const [selectedKeyId, setSelectedKeyId] = useState<string>("");
  const [showConfig, setShowConfig] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [projRes, keyRes] = await Promise.all([
          fetch("/api/projects"),
          fetch("/api/apikeys"),
        ]);

        if (projRes.ok) {
          const data = await projRes.json() as { projects?: Array<{ id: string; name: string }> };
          if (data.projects && data.projects.length > 0) {
            const simpleProjects = data.projects.map((p) => ({ id: p.id, name: p.name }));
            setProjects(simpleProjects);
            setSelectedProjectId(simpleProjects[0].id);
          }
        }

        if (keyRes.ok) {
          const data = await keyRes.json() as { keys?: Array<{ id: string; prefix: string; name: string }> };
          if (data.keys && data.keys.length > 0) {
            setApiKeys(data.keys);
            setSelectedKeyId(data.keys[0].id);
          }
        }
      } catch {
        // ignore
      }
    };

    void fetchData();
  }, []);

  const selectedKey = apiKeys.find((k) => k.id === selectedKeyId);
  const curlCommand = selectedProjectId && selectedKey
    ? `curl "${baseUrl}/api/ide/findings?projectId=${selectedProjectId}" \\
  -H "Authorization: Bearer ${selectedKey.prefix}..."`
    : "";

  const vsCodeSettings = selectedProjectId && selectedKey
    ? JSON.stringify({
        "pepper.apiUrl": `${baseUrl}/api/ide/findings`,
        "pepper.apiKey": selectedKey.prefix,
        "pepper.projectId": selectedProjectId,
      }, null, 2)
    : "{}";

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success("Copied to clipboard");
  };

  const hasRequirements = selectedProjectId && selectedKey;

  return (
    <div className="max-w-3xl space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Settings", href: "/settings/integrations" },
          { label: "IDE plugins" },
        ]}
      />

      <div>
        <h1 className="text-2xl font-bold">IDE Integration</h1>
        <p className="text-muted-foreground">
          One-click setup for VS Code, Neovim, or any editor. Use Pepper's findings API directly.
        </p>
      </div>

      <Card className="border-primary/20 bg-primary/5">
        <CardHeader>
          <CardTitle className="text-lg">One-Click Setup</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-3">
            {projects.length === 0 ? (
              <div className="rounded bg-muted p-3 text-sm text-muted-foreground">
                No projects yet. <Link href="/scans/new" className="text-primary hover:underline">Create a project</Link> first.
              </div>
            ) : apiKeys.length === 0 ? (
              <div className="rounded bg-muted p-3 text-sm text-muted-foreground">
                No API keys yet. <Link href="/settings/apikeys" className="text-primary hover:underline">Create an API key</Link> first.
              </div>
            ) : (
              <>
                <div>
                  <label className="block text-sm font-medium mb-2">Select Project</label>
                  <select
                    value={selectedProjectId}
                    onChange={(e) => setSelectedProjectId(e.target.value)}
                    className="w-full rounded border border-input bg-background px-3 py-2 text-sm"
                  >
                    {projects.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2">Select API Key</label>
                  <select
                    value={selectedKeyId}
                    onChange={(e) => setSelectedKeyId(e.target.value)}
                    className="w-full rounded border border-input bg-background px-3 py-2 text-sm"
                  >
                    {apiKeys.map((k) => (
                      <option key={k.id} value={k.id}>
                        {k.name} ({k.prefix}...)
                      </option>
                    ))}
                  </select>
                </div>

                {hasRequirements && (
                  <Button
                    onClick={() => setShowConfig(!showConfig)}
                    className="w-full"
                    variant={showConfig ? "default" : "outline"}
                  >
                    {showConfig ? "Hide" : "Show"} Configuration
                  </Button>
                )}
              </>
            )}
          </div>
        </CardContent>
      </Card>

      {showConfig && hasRequirements && (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">VS Code Setup</CardTitle>
              <CardDescription>Copy and paste into your VS Code settings.json</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="rounded bg-amber-50 border border-amber-200 p-3 text-xs text-amber-900">
                <p className="font-medium mb-1">⚠️ Important:</p>
                <p>
                  Replace <code className="bg-amber-100 px-1 rounded">ppr_eS7maG</code> with your <strong>full API key</strong>.
                  Go to <Link href="/settings/apikeys" className="text-amber-900 underline">API Keys</Link> to copy your complete key.
                </p>
              </div>
              <pre className="overflow-x-auto rounded bg-muted p-3 text-xs">
                {vsCodeSettings}
              </pre>
              <Button
                variant="outline"
                onClick={() => copyToClipboard(vsCodeSettings)}
                className="w-full"
              >
                <Copy className="mr-2 h-4 w-4" />
                Copy VS Code Config
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Test with cURL</CardTitle>
              <CardDescription>Test the API directly from your terminal</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="rounded bg-amber-50 border border-amber-200 p-3 text-xs text-amber-900">
                <p className="font-medium mb-1">⚠️ Remember:</p>
                <p>
                  Replace <code className="bg-amber-100 px-1 rounded">ppr_eS7maG...</code> with your <strong>full API key</strong> from the
                  <Link href="/settings/apikeys" className="text-amber-900 underline ml-1">API Keys page</Link>.
                </p>
              </div>
              <pre className="overflow-x-auto rounded bg-muted p-3 text-xs">
                {curlCommand}
              </pre>
              <Button
                variant="outline"
                onClick={() => copyToClipboard(curlCommand)}
                className="w-full"
              >
                <Copy className="mr-2 h-4 w-4" />
                Copy cURL Command
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg">API Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 text-sm">
              <div>
                <label className="font-medium text-muted-foreground">Endpoint</label>
                <code className="block mt-1 rounded bg-muted p-2 overflow-x-auto text-xs">
                  GET {baseUrl}/api/ide/findings
                </code>
              </div>

              <div>
                <label className="font-medium text-muted-foreground">Parameters</label>
                <ul className="mt-1 space-y-2 text-xs">
                  <li><code className="bg-muted px-1 rounded">projectId</code> - Required</li>
                  <li><code className="bg-muted px-1 rounded">filePath</code> - Optional (filter to file)</li>
                  <li><code className="bg-muted px-1 rounded">minSeverity</code> - Optional (INFO, LOW, MEDIUM, HIGH, CRITICAL)</li>
                </ul>
              </div>

              <div>
                <label className="font-medium text-muted-foreground">Response</label>
                <pre className="mt-1 rounded bg-muted p-2 text-xs overflow-x-auto">
                  {`{
  "project": {...},
  "scan": {...},
  "findings": [
    {
      "id": "...",
      "severity": "HIGH",
      "title": "...",
      "filePath": "src/...",
      "startLine": 42
    }
  ]
}`}
                </pre>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Integration Examples</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 text-sm">
              <div className="rounded bg-blue-50 border border-blue-200 p-3 text-xs text-blue-900">
                <p className="font-medium mb-1">💡 Tip:</p>
                <p>
                  Use your <strong>full API key</strong> from the <Link href="/settings/apikeys" className="text-blue-900 underline">API Keys page</Link>.
                </p>
              </div>

              <div>
                <p className="font-medium mb-2">Python</p>
                <pre className="rounded bg-muted p-2 overflow-x-auto text-xs">
                  {`import requests

api_key = "ppr_xxxxxxxxxxxx"  # Use your full API key
headers = {"Authorization": f"Bearer {api_key}"}
response = requests.get(
  "${baseUrl}/api/ide/findings",
  params={"projectId": "${selectedProjectId}"},
  headers=headers
)
findings = response.json()["findings"]`}
                </pre>
              </div>

              <div>
                <p className="font-medium mb-2">JavaScript</p>
                <pre className="rounded bg-muted p-2 overflow-x-auto text-xs">
                  {`const apiKey = "ppr_xxxxxxxxxxxx";  // Use your full API key
const response = await fetch(
  "${baseUrl}/api/ide/findings?projectId=${selectedProjectId}",
  {
    headers: {
      "Authorization": \`Bearer \${apiKey}\`
    }
  }
);
const { findings } = await response.json();`}
                </pre>
              </div>
            </CardContent>
          </Card>
        </>
      )}

      {(!hasRequirements && projects.length > 0 && apiKeys.length > 0) && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Ready to configure?</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground mb-4">
              Select a project and API key above, then click "Show Configuration" to get your setup details.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
