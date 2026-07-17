"use client";

import { useState, useEffect, useRef } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  CheckCircle2,
  XCircle,
  Loader2,
  Shield,
  Sparkles,
  Database,
} from "lucide-react";
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

const PROVIDER_DEFAULTS: Record<
  string,
  { url: string; model: string; doc: string }
> = {
  openai: {
    url: "https://api.openai.com/v1",
    model: "gpt-4o-mini",
    doc: "platform.openai.com/api-keys",
  },
  anthropic: {
    url: "https://api.anthropic.com/v1",
    model: "claude-sonnet-4-6",
    doc: "console.anthropic.com/settings/keys",
  },
  openrouter: {
    url: "https://openrouter.ai/api/v1",
    model: "google/gemini-2.5-flash",
    doc: "openrouter.ai/keys",
  },
  azure: {
    url: "https://YOUR_RESOURCE.openai.azure.com",
    model: "gpt-4o-mini",
    doc: "portal.azure.com",
  },
  ollama: {
    url: "http://host.docker.internal:11434",
    model: "qwen2.5:3b",
    doc: "ollama.com/library",
  },
  vllm: {
    url: "http://localhost:8000/v1",
    model: "meta-llama/Llama-3-8b",
    doc: "docs.vllm.ai",
  },
  custom: {
    url: "",
    model: "",
    doc: "",
  },
};

const DEFAULT_SETTINGS = {
  llmProvider: "openai",
  llmBaseUrl: "https://api.openai.com/v1",
  llmModel: "gpt-4o-mini",
  llmApiKey: "",
  hasApiKey: false,
  enableLlmSast: true,
  enableLlmSecrets: true,
  osvApiUrl: "https://api.osv.dev",
  vulnDbMode: "online",
};

type LlmSettings = typeof DEFAULT_SETTINGS;

function ProviderIcon({ provider }: { provider: string }) {
  const icons: Record<string, string> = {
    openai: "⚡",
    anthropic: "🧠",
    openrouter: "🔀",
    azure: "☁️",
    ollama: "🦙",
    vllm: "⚙️",
    custom: "🔌",
  };
  return <span className="mr-2">{icons[provider] || "🔌"}</span>;
}

export default function LlmSettingsPage() {
  const [loading, setLoading] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<
    "idle" | "success" | "error"
  >("idle");
  const [testError, setTestError] = useState("");
  const [settings, setSettings] = useState<LlmSettings>(DEFAULT_SETTINGS);
  const customRef = useRef({ url: "", model: "" });

  useEffect(() => {
    fetch("/api/settings/llm")
      .then((res) => res.json())
      .then((data) => setSettings((s) => ({ ...s, ...data })));
  }, []);

  async function saveSettings(nextSettings: LlmSettings, silent = false) {
    setLoading(true);
    try {
      const res = await fetch("/api/settings/llm", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(nextSettings),
      });
      if (!res.ok) throw new Error("Failed to save");
      if (!silent) toast.success("Settings saved");
    } catch {
      toast.error("Failed to save settings");
    } finally {
      setLoading(false);
    }
  }

  async function handleSave() {
    await saveSettings(settings);
  }

  async function testConnection() {
    setTesting(true);
    setTestResult("idle");
    setTestError("");
    try {
      const res = await fetch("/api/settings/llm/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          llmProvider: settings.llmProvider,
          llmBaseUrl: settings.llmBaseUrl,
          llmModel: settings.llmModel,
          llmApiKey: settings.llmApiKey || undefined,
        }),
      });
      if (res.ok) {
        setTestResult("success");
        toast.success("Connection successful");
      } else {
        const data = await res.json().catch(() => ({}));
        setTestResult("error");
        setTestError(data.error || "Connection failed");
        toast.error(data.error || "Connection failed");
      }
    } catch {
      setTestResult("error");
      setTestError("Check the URL and network");
      toast.error("Connection failed — check the URL and network");
    } finally {
      setTesting(false);
    }
  }

  async function updateSettings(
    patch: Partial<
      Pick<LlmSettings, "enableLlmSast" | "enableLlmSecrets" | "vulnDbMode">
    >,
  ) {
    const nextSettings = { ...settings, ...patch };
    setSettings(nextSettings);
    await saveSettings(nextSettings, true);
  }

  function handleProviderChange(v: string) {
    const d = PROVIDER_DEFAULTS[v];
    if (!d) return;

    if (v === "custom") {
      customRef.current = {
        url: settings.llmBaseUrl,
        model: settings.llmModel,
      };
      setSettings((s) => ({ ...s, llmProvider: v }));
    } else {
      setSettings((s) => ({
        ...s,
        llmProvider: v,
        llmBaseUrl: d.url || customRef.current.url,
        llmModel: d.model || customRef.current.model,
      }));
    }
    setTestResult("idle");
    setTestError("");
  }

  const provider = PROVIDER_DEFAULTS[settings.llmProvider];

  return (
    <div className="max-w-2xl space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "LLM config" },
        ]}
      />
      <div>
        <h1 className="text-2xl font-bold">LLM Configuration</h1>
        <p className="text-muted-foreground">
          Configure the LLM provider for AI-assisted code analysis
        </p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Sparkles className="h-5 w-5 text-primary" />
            <CardTitle>AI Provider</CardTitle>
          </div>
          <CardDescription>
            Choose your LLM provider and enter credentials
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="space-y-2">
            <Label>Provider</Label>
            <Select
              value={settings.llmProvider}
              onValueChange={handleProviderChange}
            >
              <SelectTrigger className="w-full">
                <SelectValue>
                  <span className="flex items-center">
                    <ProviderIcon provider={settings.llmProvider} />
                    {settings.llmProvider === "ollama" && "Ollama (Local, recommended)"}
                    {settings.llmProvider === "openai" && "OpenAI"}
                    {settings.llmProvider === "anthropic" && "Anthropic (Claude)"}
                    {settings.llmProvider === "openrouter" && "OpenRouter (Multi-model)"}
                    {settings.llmProvider === "azure" && "Azure OpenAI"}
                    {settings.llmProvider === "vllm" && "vLLM"}
                    {settings.llmProvider === "custom" && "Custom Endpoint"}
                  </span>
                </SelectValue>
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ollama">
                  <ProviderIcon provider="ollama" />Ollama (Local, recommended)
                </SelectItem>
                <SelectItem value="openai">
                  <ProviderIcon provider="openai" />OpenAI
                </SelectItem>
                <SelectItem value="anthropic">
                  <ProviderIcon provider="anthropic" />Anthropic (Claude)
                </SelectItem>
                <SelectItem value="openrouter">
                  <ProviderIcon provider="openrouter" />OpenRouter (Multi-model)
                </SelectItem>
                <SelectItem value="azure">
                  <ProviderIcon provider="azure" />Azure OpenAI
                </SelectItem>
                <SelectItem value="vllm">
                  <ProviderIcon provider="vllm" />vLLM
                </SelectItem>
                <SelectItem value="custom">
                  <ProviderIcon provider="custom" />Custom Endpoint
                </SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>Base URL</Label>
              <Input
                value={settings.llmBaseUrl}
                onChange={(e) => {
                  setSettings((s) => ({ ...s, llmBaseUrl: e.target.value }));
                  setTestResult("idle");
                }}
                placeholder="https://api.openai.com/v1"
              />
            </div>
            <div className="space-y-2">
              <Label>Model</Label>
              <Input
                value={settings.llmModel}
                onChange={(e) => {
                  setSettings((s) => ({ ...s, llmModel: e.target.value }));
                  setTestResult("idle");
                }}
                placeholder="gpt-4o-mini"
              />
            </div>
          </div>

          {settings.llmProvider !== "ollama" && (
            <div className="space-y-2">
              <Label>
                API Key
                {settings.hasApiKey && (
                  <Badge variant="outline" className="ml-2 text-xs">
                    Configured
                  </Badge>
                )}
              </Label>
              <Input
                type="password"
                value={settings.llmApiKey}
                onChange={(e) => {
                  setSettings((s) => ({ ...s, llmApiKey: e.target.value }));
                  setTestResult("idle");
                }}
                placeholder={
                  settings.hasApiKey
                    ? "Leave empty to keep current key"
                    : "Enter API key"
                }
              />
            </div>
          )}

          {testResult === "success" && (
            <div className="flex items-center gap-2 rounded-md border border-green-200 bg-green-50 px-3 py-2 text-sm text-green-700">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              Connection successful — provider is reachable
            </div>
          )}
          {testResult === "error" && (
            <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              <XCircle className="h-4 w-4 shrink-0" />
              {testError || "Connection failed"}
            </div>
          )}

          {settings.llmProvider === "ollama" && (
            <div className="rounded-md bg-muted/50 p-3 text-sm text-muted-foreground">
              Ollama runs locally — no API key needed. The model will be pulled
              automatically on first scan. Make sure the Ollama service is
              running (included in Docker Compose).
            </div>
          )}

          <div className="flex gap-3 pt-2">
            {settings.llmProvider !== "ollama" && (
              <Button
                variant="outline"
                onClick={testConnection}
                disabled={testing || loading || !settings.llmApiKey}
              >
                {testing ? (
                  <>
                    <Loader2 className="mr-1 h-4 w-4 animate-spin" />
                    Testing...
                  </>
                ) : (
                  "Test Connection"
                )}
              </Button>
            )}
            <Button onClick={handleSave} disabled={loading || testing}>
              {loading ? "Saving..." : "Save Settings"}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            <CardTitle>AI Features</CardTitle>
          </div>
          <CardDescription>
            Toggle which scans use AI assistance
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <Label>AI-assisted SAST</Label>
              <p className="text-sm text-muted-foreground">
                Use AI to analyze code for vulnerabilities
              </p>
            </div>
            <Switch
              checked={settings.enableLlmSast}
              disabled={loading}
              onCheckedChange={(v) => updateSettings({ enableLlmSast: v })}
            />
          </div>
          <div className="flex items-center justify-between">
            <div>
              <Label>AI-assisted Secret Detection</Label>
              <p className="text-sm text-muted-foreground">
                Use AI to reduce false positives in secret detection
              </p>
            </div>
            <Switch
              checked={settings.enableLlmSecrets}
              disabled={loading}
              onCheckedChange={(v) => updateSettings({ enableLlmSecrets: v })}
            />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Database className="h-5 w-5 text-primary" />
            <CardTitle>Vulnerability Database</CardTitle>
          </div>
          <CardDescription>
            Configure how vulnerability data is sourced for SCA scans
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Mode</Label>
            <Select
              value={settings.vulnDbMode}
              onValueChange={(v) =>
                updateSettings({
                  vulnDbMode: v as LlmSettings["vulnDbMode"],
                })
              }
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="online">Online (OSV.dev API)</SelectItem>
                <SelectItem value="mirror">Mirrored (Self-hosted)</SelectItem>
                <SelectItem value="offline">
                  Offline (Disable DB lookup)
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>OSV API URL</Label>
            <Input
              value={settings.osvApiUrl}
              disabled={settings.vulnDbMode === "offline"}
              onChange={(e) =>
                setSettings((s) => ({ ...s, osvApiUrl: e.target.value }))
              }
              placeholder="https://api.osv.dev"
            />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
