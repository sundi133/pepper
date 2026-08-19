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
  AlertTriangle,
} from "lucide-react";
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

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
  opencode: {
    url: "https://opencode.ai/zen/v1",
    model: "deepseek-v4-flash-free",
    doc: "opencode.ai/docs/zen",
  },
  custom: {
    url: "",
    model: "",
    doc: "",
  },
};

const PROVIDER_MODELS: Record<string, { top: string[]; budget: string[] }> = {
  openai: {
    top: ["gpt-4o", "gpt-4.1", "o3", "o4-mini"],
    budget: ["gpt-4o-mini", "gpt-4.1-mini", "o3-mini"],
  },
  anthropic: {
    top: ["claude-opus-4-6", "claude-sonnet-4-6"],
    budget: ["claude-haiku-4-5-20251001"],
  },
  openrouter: {
    top: [
      "google/gemini-2.5-flash",
      "google/gemini-2.5-pro",
      "anthropic/claude-sonnet-4-6",
      "moonshotai/kimi-k3",
      "z-ai/glm-5.2",
    ],
    budget: [
      "google/gemini-2.0-flash",
      "deepseek/deepseek-chat",
      "meta-llama/llama-3.3-70b",
      "mistralai/mistral-small",
    ],
  },
  azure: {
    top: ["gpt-4o", "gpt-4.1"],
    budget: ["gpt-4o-mini", "gpt-4.1-mini"],
  },
  ollama: {
    top: ["qwen2.5:7b", "llama3.2:7b", "mistral:7b"],
    budget: ["qwen2.5:3b", "llama3.2:3b", "phi4:latest"],
  },
  vllm: {
    top: ["meta-llama/Llama-3-70b", "mistralai/Mixtral-8x7B"],
    budget: ["meta-llama/Llama-3-8b", "mistralai/Mistral-7B"],
  },
  opencode: {
    top: ["gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex"],
    budget: [
      "deepseek-v4-flash-free",
      "mimo-v2.5-free",
      "north-mini-code-free",
      "nemotron-3-ultra-free",
      "big-pickle",
    ],
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
    opencode: "🌀",
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
  const [useCustomModel, setUseCustomModel] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [deletingKey, setDeletingKey] = useState(false);
  const [resetDialogOpen, setResetDialogOpen] = useState(false);
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

  async function handleReset() {
    setResetting(true);
    try {
      const res = await fetch("/api/settings/llm", { method: "DELETE" });
      if (!res.ok) throw new Error("Failed to reset");
      setSettings((s) => ({
        ...s,
        llmProvider: "openai",
        llmBaseUrl: "https://api.openai.com/v1",
        llmModel: "gpt-4o-mini",
        llmApiKey: "",
        hasApiKey: false,
      }));
      setUseCustomModel(false);
      setTestResult("idle");
      toast.success("Settings reset to defaults");
    } catch {
      toast.error("Failed to reset settings");
    } finally {
      setResetting(false);
      setResetDialogOpen(false);
    }
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

  async function deleteApiKey() {
    setDeletingKey(true);
    try {
      const res = await fetch("/api/settings/llm/key", { method: "DELETE" });
      if (!res.ok) throw new Error("Failed to delete API key");
      setSettings((s) => ({ ...s, llmApiKey: "", hasApiKey: false }));
      setTestResult("idle");
      setTestError("");
      toast.success("API key deleted");
    } catch {
      toast.error("Failed to delete API key");
    } finally {
      setDeletingKey(false);
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
    setUseCustomModel(false);
  }

  function handleModelSelect(value: string) {
    if (value === "__custom__") {
      setUseCustomModel(true);
      return;
    }
    setSettings((s) => ({ ...s, llmModel: value }));
  }

  const needsKey = settings.llmProvider !== "ollama";
  const isCustomProvider = settings.llmProvider === "custom";
  const models = PROVIDER_MODELS[settings.llmProvider];

  function modelInList(): boolean {
    if (!models) return false;
    return [...models.top, ...models.budget].includes(settings.llmModel);
  }

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
            <div>
              <CardTitle>AI Provider</CardTitle>
              <CardDescription>
                Choose your LLM provider and enter credentials
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="flex items-center gap-2 rounded-md border border-primary/20 bg-primary/5 px-3 py-2 text-sm">
            <Sparkles className="h-4 w-4 shrink-0 text-primary" />
            <div className="min-w-0">
              <span className="text-muted-foreground">Currently used for scans: </span>
              <span className="font-semibold">{settings.llmModel}</span>
              <span className="text-muted-foreground">
                {" "}via {settings.llmProvider}
              </span>
              <Badge variant="secondary" className="ml-2">
                {settings.hasApiKey ? "DB key" : "Default settings"}
              </Badge>
            </div>
          </div>

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
                    {settings.llmProvider === "opencode" && "OpenCode Zen (Free)"}
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
                <SelectItem value="opencode">
                  <ProviderIcon provider="opencode" />OpenCode Zen (Free)
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
              {!isCustomProvider && models && !useCustomModel ? (
                <Select
                  value={modelInList() ? settings.llmModel : "__custom__"}
                  onValueChange={handleModelSelect}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select a model" />
                  </SelectTrigger>
                  <SelectContent className="max-h-72">
                    <div className="px-2 py-1.5 text-xs font-semibold text-muted-foreground">
                      Top models
                    </div>
                    {models.top.map((m) => (
                      <SelectItem key={m} value={m}>
                        {m}
                      </SelectItem>
                    ))}
                    <div className="px-2 py-1.5 text-xs font-semibold text-muted-foreground">
                      Budget
                    </div>
                    {models.budget.map((m) => (
                      <SelectItem key={m} value={m}>
                        {m}
                      </SelectItem>
                    ))}
                    <SelectItem
                      value="__custom__"
                      className="border-t text-muted-foreground text-xs italic"
                    >
                      Type custom name...
                    </SelectItem>
                  </SelectContent>
                </Select>
              ) : (
                <Input
                  value={settings.llmModel}
                  onChange={(e) => {
                    setSettings((s) => ({ ...s, llmModel: e.target.value }));
                    setTestResult("idle");
                  }}
                  placeholder={
                    isCustomProvider ? "gpt-4o-mini" : "Enter model name"
                  }
                />
              )}
              {useCustomModel && (
                <p className="text-xs text-muted-foreground">
                  Type any model name above.{" "}
                  <button
                    className="underline"
                    onClick={() => setUseCustomModel(false)}
                  >
                    Back to list
                  </button>
                </p>
              )}
            </div>
          </div>

          {needsKey && (
            <div className="space-y-2">
              <Label>
                API Key
                {settings.hasApiKey && (
                  <Badge variant="outline" className="ml-2 text-xs font-normal">
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

          {settings.llmProvider === "opencode" && (
            <div className="rounded-md bg-muted/50 p-3 text-sm text-muted-foreground">
              OpenCode Zen offers free models. Sign in at{" "}
              <a
                href="https://opencode.ai/auth"
                target="_blank"
                rel="noopener noreferrer"
                className="underline"
              >
                opencode.ai/auth
              </a>{" "}
              to get your API key. The free models (DeepSeek V4 Flash Free,
              MiMo-V2.5 Free, etc.) cost nothing to use. Get the full model list
              at{" "}
              <a
                href="https://opencode.ai/docs/zen"
                target="_blank"
                rel="noopener noreferrer"
                className="underline"
              >
                opencode.ai/docs/zen
              </a>
              .
            </div>
          )}

          <div className="flex flex-wrap gap-3 pt-2">
            {needsKey && (
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
            {needsKey && settings.hasApiKey && (
              <Button
                variant="destructive"
                onClick={deleteApiKey}
                disabled={deletingKey || loading}
              >
                {deletingKey ? "Deleting..." : "Delete API Key"}
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
            <div>
              <CardTitle>AI Features</CardTitle>
              <CardDescription>
                Toggle which scans use AI assistance
              </CardDescription>
            </div>
          </div>
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
            <div>
              <CardTitle>Vulnerability Database</CardTitle>
              <CardDescription>
                Configure how vulnerability data is sourced for SCA scans
              </CardDescription>
            </div>
          </div>
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

      <Card className="border-destructive/20">
        <CardHeader>
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <div>
              <CardTitle>Reset Configuration</CardTitle>
              <CardDescription>
                Reset all LLM settings to their defaults
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Dialog open={resetDialogOpen} onOpenChange={setResetDialogOpen}>
            <DialogTrigger asChild>
              <Button variant="destructive" disabled={resetting}>
                {resetting ? "Resetting..." : "Reset to defaults"}
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Reset LLM Configuration?</DialogTitle>
                <DialogDescription>
                  This will reset your provider, model, API key, and all LLM
                  settings to their factory defaults. This action cannot be
                  undone.
                </DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button
                  variant="outline"
                  onClick={() => setResetDialogOpen(false)}
                >
                  Cancel
                </Button>
                <Button
                  variant="destructive"
                  onClick={handleReset}
                  disabled={resetting}
                >
                  {resetting ? "Resetting..." : "Reset"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </CardContent>
      </Card>
    </div>
  );
}
