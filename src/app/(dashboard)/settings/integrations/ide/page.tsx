"use client";

import { useState, useEffect, useSyncExternalStore, type ReactNode } from "react";
import { useSearchParams } from "next/navigation";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Copy } from "lucide-react";
import Link from "next/link";
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

const KEY_PLACEHOLDER = "YOUR_PEPPER_API_KEY";

const MCP_TOOLS: Array<[string, string]> = [
  ["findings_for_file", "Findings in the file you are editing, from the repository's latest completed scan"],
  ["list_repositories", "Repositories with their latest scan status and severity counts"],
  ["list_scans / get_scan", "Scan history, progress, severity counts, build-gate result, incomplete-scan note"],
  ["list_findings / get_finding", "Findings with filters; full details, CWE / OWASP, reproduction steps, remediation"],
  ["start_scan / rescan", "Queue a scan of a repository or repository URL (Developer role)"],
  ["update_finding_status", "Triage with a note: Open, In progress, Resolved (Developer role)"],
];

const noSubscription = () => () => undefined;

function copyToClipboard(text: string) {
  void navigator.clipboard.writeText(text);
  toast.success("Copied to clipboard");
}

function Snippet({ code, label }: { code: string; label?: string }) {
  return (
    <div className="space-y-2">
      <pre className="overflow-x-auto rounded bg-muted p-3 text-xs">{code}</pre>
      <Button variant="outline" size="sm" onClick={() => copyToClipboard(code)}>
        <Copy className="mr-2 h-4 w-4" />
        {label ?? "Copy"}
      </Button>
    </div>
  );
}

function Steps({ children }: { children: ReactNode }) {
  return <ol className="list-decimal space-y-1 pl-5 text-sm text-muted-foreground">{children}</ol>;
}

export default function IdeIntegrationPage() {
  const searchParams = useSearchParams();
  const apiKeyFromUrl = searchParams.get("apiKey");

  // Empty on the server and during hydration (no window there), then this
  // instance's origin, so the first client render matches the server's.
  const baseUrl = useSyncExternalStore(
    noSubscription,
    () => window.location.origin,
    () => "",
  );
  const [projects, setProjects] = useState<Array<{ id: string; name: string }>>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>("");
  const [apiKeys, setApiKeys] = useState<Array<{ id: string; prefix: string; name: string }>>([]);
  const [selectedKeyId, setSelectedKeyId] = useState<string>("");
  const [fullApiKey, setFullApiKey] = useState<string>(apiKeyFromUrl || "");

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
  const isFullKeyProvided = fullApiKey.trim().startsWith("ppr_") && fullApiKey.trim().length > 10;
  const key = isFullKeyProvided ? fullApiKey.trim() : KEY_PLACEHOLDER;
  const mcpUrl = `${baseUrl}/api/mcp`;
  const bearer = `Bearer ${key}`;

  // VS Code prompts for the key once and stores it securely, so the file
  // can be committed without the secret.
  const vscodeConfig = JSON.stringify(
    {
      servers: {
        pepper: {
          type: "http",
          url: mcpUrl,
          headers: { Authorization: "Bearer ${input:pepper-api-key}" },
        },
      },
      inputs: [
        {
          type: "promptString",
          id: "pepper-api-key",
          description: "Pepper API key",
          password: true,
        },
      ],
    },
    null,
    2,
  );

  const visualStudioConfig = JSON.stringify(
    {
      servers: {
        pepper: { type: "http", url: mcpUrl, headers: { Authorization: bearer } },
      },
    },
    null,
    2,
  );

  // GitHub Copilot for JetBrains IDEs and for Eclipse share this format.
  const copilotPluginConfig = JSON.stringify(
    {
      servers: {
        pepper: { url: mcpUrl, requestInit: { headers: { Authorization: bearer } } },
      },
    },
    null,
    2,
  );

  const cursorConfig = JSON.stringify(
    {
      mcpServers: {
        pepper: { url: mcpUrl, headers: { Authorization: bearer } },
      },
    },
    null,
    2,
  );

  const claudeCodeCommand = `claude mcp add --transport http pepper ${mcpUrl} \\
  --header "Authorization: ${bearer}"`;

  const genericConfig = JSON.stringify(
    {
      mcpServers: {
        pepper: { type: "http", url: mcpUrl, headers: { Authorization: bearer } },
      },
    },
    null,
    2,
  );

  const stdioBridgeConfig = JSON.stringify(
    {
      mcpServers: {
        pepper: {
          command: "npx",
          args: ["-y", "mcp-remote", mcpUrl, "--header", `Authorization: ${bearer}`],
        },
      },
    },
    null,
    2,
  );

  const mcpCurl = `curl -s ${mcpUrl} \\
  -H "Authorization: ${bearer}" \\
  -H "Content-Type: application/json" \\
  -H "Accept: application/json, text/event-stream" \\
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'`;

  const findingsCurl = selectedProjectId
    ? `curl "${baseUrl}/api/ide/findings?projectId=${selectedProjectId}" \\
  -H "Authorization: ${bearer}"`
    : "";

  return (
    <div className="max-w-3xl space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Settings", href: "/settings/integrations" },
          { label: "IDE" },
        ]}
      />

      <div>
        <h1 className="text-2xl font-bold">IDE Integration</h1>
        <p className="text-muted-foreground">
          Pepper runs a Model Context Protocol (MCP) server. Connect the AI assistant in your
          IDE to it and ask, in the editor, which issues Pepper found in the file you are
          working on, why they matter and how to fix them; start scans and triage findings
          without leaving the IDE. It works with any MCP-capable assistant, such as GitHub
          Copilot (VS Code, Visual Studio, JetBrains IDEs, Eclipse), Cursor and Claude Code.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Editor extension</CardTitle>
          <CardDescription>
            Findings as squiggles and Problems-panel entries on the lines they are about, details on
            hover, rescans from the editor and an instant secrets check when you save. No AI assistant
            needed.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div>
            <p className="font-medium">VS Code, Cursor, Windsurf</p>
            <ol className="ml-5 mt-1 list-decimal space-y-1 text-muted-foreground">
              <li>
                Install <code className="rounded bg-muted px-1">pepper-sast-&lt;version&gt;.vsix</code> from
                the Pepper release (Extensions → ⋯ → Install from VSIX…).
              </li>
              <li>
                Run <strong>Pepper: Sign in</strong> and enter{" "}
                <code className="rounded bg-muted px-1">{baseUrl}</code> and an API key.
              </li>
              <li>
                Open a repository that Pepper has scanned: it is matched by its git remote.
              </li>
            </ol>
          </div>
          <div>
            <p className="font-medium">JetBrains IDEs and Eclipse</p>
            <p className="mt-1 text-muted-foreground">
              The same language server works with the <strong>LSP4IJ</strong> plugin (IntelliJ IDEA,
              PyCharm, WebStorm, GoLand, Rider, also Community editions) and with{" "}
              <strong>LSP4E</strong> in Eclipse. Download{" "}
              <code className="rounded bg-muted px-1">pepper-lsp-&lt;version&gt;.js</code> from the release
              and start it with <code className="rounded bg-muted px-1">node pepper-lsp.js --stdio</code>{" "}
              (Node 18 or newer). The setup is described in <code className="rounded bg-muted px-1">ide/README.md</code>.
            </p>
          </div>
        </CardContent>
      </Card>

      <Card className="border-primary/20 bg-primary/5">
        <CardHeader>
          <CardTitle className="text-lg">1. Choose an API key</CardTitle>
          <CardDescription>
            The assistant acts as the key&apos;s creator in this organization, with at most the
            Developer role. A key created by a Viewer can read findings but cannot start scans
            or change statuses.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {apiKeys.length === 0 ? (
            <div className="rounded bg-muted p-3 text-sm text-muted-foreground">
              No API keys yet.{" "}
              <Link href="/settings/apikeys" className="text-primary hover:underline">
                Create an API key
              </Link>{" "}
              first.
            </div>
          ) : (
            <div>
              <label className="mb-2 block text-sm font-medium">API key</label>
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
          )}
          <div>
            <label className="mb-2 block text-sm font-medium">Full API key (optional)</label>
            <Input
              type="password"
              autoComplete="off"
              placeholder={selectedKey ? `${selectedKey.prefix}…` : "ppr_…"}
              value={fullApiKey}
              onChange={(e) => setFullApiKey(e.target.value)}
            />
            <p className="mt-1 text-xs text-muted-foreground">
              Keys are shown only once, when created. Paste the full key here to fill it into the
              snippets below (it stays in this browser), or replace{" "}
              <code className="rounded bg-muted px-1">{KEY_PLACEHOLDER}</code> yourself. On the{" "}
              <Link href="/settings/apikeys" className="text-primary underline">
                API Keys page
              </Link>
              , <strong>Setup in IDE</strong> opens this page with a new key filled in.
            </p>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">2. Add Pepper to your assistant</CardTitle>
          <CardDescription>
            Server URL <code className="rounded bg-muted px-1">{mcpUrl}</code> · transport:
            Streamable HTTP · header{" "}
            <code className="rounded bg-muted px-1">Authorization: Bearer &lt;API key&gt;</code>.
            Menu names and file locations differ between assistants and versions; where they do,
            follow your assistant&apos;s MCP settings.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="vscode">
            <TabsList className="flex h-auto flex-wrap justify-start">
              <TabsTrigger value="vscode">VS Code</TabsTrigger>
              <TabsTrigger value="visualstudio">Visual Studio</TabsTrigger>
              <TabsTrigger value="jetbrains">JetBrains / Android Studio</TabsTrigger>
              <TabsTrigger value="eclipse">Eclipse</TabsTrigger>
              <TabsTrigger value="cursor">Cursor</TabsTrigger>
              <TabsTrigger value="claude">Claude Code</TabsTrigger>
              <TabsTrigger value="other">Other</TabsTrigger>
            </TabsList>

            <TabsContent value="vscode" className="space-y-3 pt-3">
              <Steps>
                <li>
                  Save this as <code>.vscode/mcp.json</code> in your workspace (or add it to your
                  user MCP configuration).
                </li>
                <li>
                  Start the <strong>pepper</strong> server when VS Code offers to; it asks for the
                  API key once and stores it securely, so the file holds no secret.
                </li>
                <li>Open Copilot Chat in Agent mode; the Pepper tools appear in the tools list.</li>
              </Steps>
              <Snippet code={vscodeConfig} label="Copy .vscode/mcp.json" />
            </TabsContent>

            <TabsContent value="visualstudio" className="space-y-3 pt-3">
              <Steps>
                <li>
                  Visual Studio 2022 (17.14 or later) with GitHub Copilot: save this as{" "}
                  <code>.mcp.json</code> next to your solution, or in your user profile folder for
                  every solution.
                </li>
                <li>Open Copilot Chat, switch to Agent mode and enable the Pepper tools.</li>
                <li>Keep a file that contains the key out of source control.</li>
              </Steps>
              <Snippet code={visualStudioConfig} label="Copy .mcp.json" />
            </TabsContent>

            <TabsContent value="jetbrains" className="space-y-3 pt-3">
              <p className="text-sm text-muted-foreground">
                IntelliJ IDEA, Android Studio, PyCharm, WebStorm, Rider and the other JetBrains IDEs.
              </p>
              <Steps>
                <li>
                  <strong>GitHub Copilot plugin:</strong> in Copilot Chat switch to Agent mode, open
                  the tools menu and choose to add MCP tools; paste the server entry below into the{" "}
                  <code>mcp.json</code> that opens.
                </li>
                <li>
                  <strong>JetBrains AI Assistant:</strong> add an MCP server under Settings → Tools →
                  AI Assistant → Model Context Protocol (MCP), with the URL and header above. If your
                  version only accepts command-based (stdio) servers, use the bridge under{" "}
                  <em>Other</em>.
                </li>
              </Steps>
              <Snippet code={copilotPluginConfig} label="Copy Copilot mcp.json" />
            </TabsContent>

            <TabsContent value="eclipse" className="space-y-3 pt-3">
              <Steps>
                <li>
                  Install GitHub Copilot for Eclipse, then open its MCP settings (Preferences →
                  GitHub Copilot → MCP) and add the server configuration below.
                </li>
                <li>Use Copilot Chat in Agent mode to call the Pepper tools.</li>
              </Steps>
              <Snippet code={copilotPluginConfig} label="Copy server configuration" />
              <p className="text-xs text-muted-foreground">
                <strong>e² studio</strong> is built on Eclipse: if your e² studio version can install
                an MCP-capable assistant plugin (check the plugin&apos;s supported Eclipse versions),
                configure it the same way.
              </p>
            </TabsContent>

            <TabsContent value="cursor" className="space-y-3 pt-3">
              <Steps>
                <li>
                  Add this to <code>.cursor/mcp.json</code> in the project, or{" "}
                  <code>~/.cursor/mcp.json</code> for all projects.
                </li>
                <li>Enable the server under Cursor Settings → MCP, then use Agent chat.</li>
              </Steps>
              <Snippet code={cursorConfig} label="Copy mcp.json" />
            </TabsContent>

            <TabsContent value="claude" className="space-y-3 pt-3">
              <Steps>
                <li>Run this in your project&apos;s terminal (add <code>--scope user</code> for all projects).</li>
                <li>
                  Check it with <code>claude mcp list</code>, or <code>/mcp</code> inside Claude Code.
                </li>
              </Steps>
              <Snippet code={claudeCodeCommand} label="Copy command" />
            </TabsContent>

            <TabsContent value="other" className="space-y-3 pt-3">
              <p className="text-sm text-muted-foreground">
                Any MCP client that supports remote (Streamable HTTP) servers with custom headers —
                for example Continue, Cline or Windsurf — can use the entry below; the file name and
                top-level key vary by client.
              </p>
              <Snippet code={genericConfig} label="Copy configuration" />
              <p className="text-sm text-muted-foreground">
                Clients that only launch local (stdio) servers can reach Pepper through a bridge
                such as the open-source <code>mcp-remote</code> package (downloaded from the npm
                registry on first use, or installed from your internal mirror):
              </p>
              <Snippet code={stdioBridgeConfig} label="Copy stdio bridge configuration" />
              <p className="text-xs text-muted-foreground">
                <strong>NetBeans</strong> and other editors: use an MCP-capable assistant plugin
                where one is available for your editor, with the settings above.
              </p>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">3. Try it</CardTitle>
          <CardDescription>
            Ask your assistant, for example: &quot;Which Pepper findings are in this file?&quot;,
            &quot;Explain finding … and how to fix it&quot;, or &quot;Start a Pepper scan of this
            repository&quot;.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-sm">
          <ul className="space-y-1">
            {MCP_TOOLS.map(([name, text]) => (
              <li key={name}>
                <code className="rounded bg-muted px-1 text-xs">{name}</code>{" "}
                <span className="text-muted-foreground">— {text}</span>
              </li>
            ))}
          </ul>
          <p className="text-xs text-muted-foreground">
            Secrets are only ever returned masked. Marking a finding False positive or Accepted
            risk needs the Security role, which API keys do not carry: do that here in Pepper.
            Starting scans and status changes are recorded in the audit log.
          </p>
          <div>
            <p className="mb-2 font-medium">Check the connection from a terminal</p>
            <Snippet code={mcpCurl} label="Copy cURL command" />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Findings REST API</CardTitle>
          <CardDescription>
            For scripts and custom editor plugins: the latest findings of a repository, optionally
            for one file, with the same API key.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-sm">
          {projects.length === 0 ? (
            <div className="rounded bg-muted p-3 text-sm text-muted-foreground">
              No repositories yet.{" "}
              <Link href="/scans/new" className="text-primary hover:underline">
                Start a scan
              </Link>{" "}
              first.
            </div>
          ) : (
            <div>
              <label className="mb-2 block text-sm font-medium">Repository</label>
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
          )}

          <div>
            <label className="font-medium text-muted-foreground">Endpoint</label>
            <code className="mt-1 block overflow-x-auto rounded bg-muted p-2 text-xs">
              GET {baseUrl}/api/ide/findings
            </code>
          </div>

          <div>
            <label className="font-medium text-muted-foreground">Parameters</label>
            <ul className="mt-1 space-y-2 text-xs">
              <li><code className="rounded bg-muted px-1">repositoryId</code> - Required (repository id; <code className="rounded bg-muted px-1">projectId</code> also works)</li>
              <li><code className="rounded bg-muted px-1">branch</code> - Optional (that branch&apos;s latest scan, else the repository&apos;s latest)</li>
              <li><code className="rounded bg-muted px-1">filePath</code> - Optional (filter to file)</li>
              <li><code className="rounded bg-muted px-1">minSeverity</code> - Optional (INFO, LOW, MEDIUM, HIGH, CRITICAL)</li>
              <li><code className="rounded bg-muted px-1">includeTriaged</code> - Optional (<code className="rounded bg-muted px-1">true</code> also returns resolved and accepted-risk findings)</li>
            </ul>
          </div>

          {findingsCurl && <Snippet code={findingsCurl} label="Copy cURL command" />}

          <div>
            <label className="font-medium text-muted-foreground">Response</label>
            <pre className="mt-1 overflow-x-auto rounded bg-muted p-2 text-xs">
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

          <div>
            <p className="mb-2 font-medium">Python</p>
            <pre className="overflow-x-auto rounded bg-muted p-2 text-xs">
              {`import requests

api_key = "${key}"
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
            <p className="mb-2 font-medium">JavaScript</p>
            <pre className="overflow-x-auto rounded bg-muted p-2 text-xs">
              {`const apiKey = "${key}";
const response = await fetch(
  "${baseUrl}/api/ide/findings?projectId=${selectedProjectId}",
  { headers: { "Authorization": \`Bearer \${apiKey}\` } }
);
const { findings } = await response.json();`}
            </pre>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
