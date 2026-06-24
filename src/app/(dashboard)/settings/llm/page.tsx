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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

const DEFAULT_SETTINGS = {
  llmProvider: "openai",
  llmBaseUrl: "https://api.openai.com/v1",
  llmModel: "gpt-4o-mini",
  llmApiKey: "",
  hasApiKey: false,
  enableLlmSast: true,
  enableLlmSecrets: true,
  enableLlmPrDiff: false,
  enableLlmSca: false,
  enableLlmIac: false,
  enableLlmZeroDay: false,
  enableLlmContainer: false,
  osvApiUrl: "https://api.osv.dev",
  vulnDbMode: "online",
};

type LlmSettings = typeof DEFAULT_SETTINGS;

export default function LlmSettingsPage() {
  const [loading, setLoading] = useState(false);
  const [settings, setSettings] = useState<LlmSettings>(DEFAULT_SETTINGS);

  useEffect(() => {
    fetch("/api/settings/llm")
      .then((res) => res.json())
      .then((data) => {
        const mergedSettings: LlmSettings = {
          ...DEFAULT_SETTINGS,
          ...data,
        };
        setSettings(mergedSettings);
      });
  }, []);

  async function saveSettings(nextSettings: LlmSettings, silent = false) {
    setLoading(true);
    try {
      // Don't send hasApiKey or empty llmApiKey to API
      const { hasApiKey, ...dataToSend } = nextSettings as any;
      const payload = {
        ...dataToSend,
        llmApiKey: (dataToSend.llmApiKey || "") === "" ? "" : dataToSend.llmApiKey,
      };

      const res = await fetch("/api/settings/llm", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        const error = data?.error || "Failed to save";
        throw new Error(error);
      }
      if (!silent) toast.success("Settings saved");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to save settings";
      console.error("Save error:", message, error);
      toast.error(message);
    } finally {
      setLoading(false);
    }
  }

  async function handleSave() {
    await saveSettings(settings);
  }

  async function updateSettings(
    patch: Partial<
      Pick<LlmSettings, "enableLlmSast" | "enableLlmSecrets" | "enableLlmPrDiff" | "enableLlmSca" | "enableLlmIac" | "enableLlmZeroDay" | "enableLlmContainer" | "vulnDbMode" | "osvApiUrl">
    >,
  ) {
    const nextSettings = { ...settings, ...patch };
    setSettings(nextSettings);
    await saveSettings(nextSettings, true);
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
          <CardTitle>LLM Provider</CardTitle>
          <CardDescription>
            Supports Ollama, OpenAI, Anthropic, OpenRouter, Azure, vLLM, or
            any OpenAI-compatible endpoint
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Provider</Label>
            <Select
              value={settings.llmProvider}
              onValueChange={(v) => {
                const defaults: Record<string, { url: string; model: string }> =
                  {
                    openai: {
                      url: "https://api.openai.com/v1",
                      model: "gpt-4o-mini",
                    },
                    anthropic: {
                      url: "https://api.anthropic.com/v1",
                      model: "claude-sonnet-4-6",
                    },
                    openrouter: {
                      url: "https://openrouter.ai/api/v1",
                      model: "google/gemini-2.5-flash",
                    },
                    azure: {
                      url: "https://YOUR_RESOURCE.openai.azure.com",
                      model: "gpt-4o-mini",
                    },
                    ollama: {
                      url: "http://host.docker.internal:11434",
                      model: "qwen2.5:3b",
                    },
                    vllm: {
                      url: "http://localhost:8000/v1",
                      model: "meta-llama/Llama-3-8b",
                    },
                    custom: { url: "", model: "" },
                  };
                const d = defaults[v] || defaults.custom;
                setSettings((s) => ({
                  ...s,
                  llmProvider: v,
                  llmBaseUrl: d.url,
                  llmModel: d.model,
                }));
              }}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ollama">
                  Ollama (Local, recommended)
                </SelectItem>
                <SelectItem value="openai">OpenAI</SelectItem>
                <SelectItem value="anthropic">
                  Anthropic (Claude)
                </SelectItem>
                <SelectItem value="openrouter">
                  OpenRouter (Multi-model)
                </SelectItem>
                <SelectItem value="azure">Azure OpenAI</SelectItem>
                <SelectItem value="vllm">vLLM</SelectItem>
                <SelectItem value="custom">Custom Endpoint</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label>Base URL</Label>
            <Input
              value={settings.llmBaseUrl}
              onChange={(e) =>
                setSettings((s) => ({ ...s, llmBaseUrl: e.target.value }))
              }
              placeholder="https://api.openai.com/v1"
            />
          </div>

          <div className="space-y-2">
            <Label>Model</Label>
            <Input
              value={settings.llmModel}
              onChange={(e) =>
                setSettings((s) => ({ ...s, llmModel: e.target.value }))
              }
              placeholder="gpt-4o-mini"
            />
          </div>

          {settings.llmProvider !== "ollama" && (
            <div className="space-y-2">
              <Label>API Key {settings.hasApiKey && "(configured)"}</Label>
              <Input
                type="password"
                value={settings.llmApiKey}
                onChange={(e) =>
                  setSettings((s) => ({ ...s, llmApiKey: e.target.value }))
                }
                placeholder={
                  settings.hasApiKey
                    ? "Leave empty to keep current key"
                    : "Enter API key"
                }
              />
            </div>
          )}

          {settings.llmProvider === "ollama" && (
            <div className="rounded-md bg-muted p-3 text-sm text-muted-foreground">
              Ollama runs locally — no API key needed. The model will be pulled
              automatically on first scan. Make sure the Ollama service is
              running (included in Docker Compose).
            </div>
          )}

          {settings.llmProvider === "anthropic" && (
            <div className="rounded-md bg-muted p-3 text-sm text-muted-foreground">
              Anthropic provides Claude models for advanced code analysis. Get
              your API key at{" "}
              <a
                href="https://console.anthropic.com/settings/keys"
                target="_blank"
                rel="noopener noreferrer"
                className="underline"
              >
                console.anthropic.com
              </a>
              . Models:{" "}
              <code className="text-xs">claude-opus-4-6</code>,{" "}
              <code className="text-xs">claude-sonnet-4-6</code>,{" "}
              <code className="text-xs">claude-haiku-4-5-20251001</code>.
            </div>
          )}

          {settings.llmProvider === "openai" && (
            <div className="rounded-md bg-muted p-3 text-sm text-muted-foreground">
              Get your API key at{" "}
              <a
                href="https://platform.openai.com/api-keys"
                target="_blank"
                rel="noopener noreferrer"
                className="underline"
              >
                platform.openai.com
              </a>
              . Models:{" "}
              <code className="text-xs">gpt-4o</code>,{" "}
              <code className="text-xs">gpt-4o-mini</code>,{" "}
              <code className="text-xs">gpt-4.1</code>,{" "}
              <code className="text-xs">gpt-4.1-mini</code>,{" "}
              <code className="text-xs">o3</code>,{" "}
              <code className="text-xs">o3-mini</code>,{" "}
              <code className="text-xs">o4-mini</code>.
            </div>
          )}

          {settings.llmProvider === "openrouter" && (
            <div className="rounded-md bg-muted p-3 text-sm text-muted-foreground">
              OpenRouter gives access to 100+ models (Google Gemini, Meta Llama,
              Mistral, DeepSeek, etc.) through a single API key. Get your key at{" "}
              <a
                href="https://openrouter.ai/keys"
                target="_blank"
                rel="noopener noreferrer"
                className="underline"
              >
                openrouter.ai/keys
              </a>
              . You can use any model ID from the OpenRouter catalog (e.g.{" "}
              <code className="text-xs">google/gemini-2.5-flash</code>,{" "}
              <code className="text-xs">deepseek/deepseek-coder</code>).
            </div>
          )}

          <div className="flex items-center justify-between pt-4">
            <div>
              <Label>Enable LLM for SAST</Label>
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
              <Label>Enable LLM for Secrets</Label>
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

          <div className="flex items-center justify-between">
            <div>
              <Label>Enable LLM for PR Diff</Label>
              <p className="text-sm text-muted-foreground">
                Use AI to analyze changes in pull requests
              </p>
            </div>
            <Switch
              checked={settings.enableLlmPrDiff}
              disabled={loading}
              onCheckedChange={(v) => updateSettings({ enableLlmPrDiff: v })}
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <Label>Enable LLM for SCA</Label>
              <p className="text-sm text-muted-foreground">
                Use AI for supply chain and dependency analysis
              </p>
            </div>
            <Switch
              checked={settings.enableLlmSca}
              disabled={loading}
              onCheckedChange={(v) => updateSettings({ enableLlmSca: v })}
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <Label>Enable LLM for IaC</Label>
              <p className="text-sm text-muted-foreground">
                Use AI to analyze Infrastructure as Code configurations
              </p>
            </div>
            <Switch
              checked={settings.enableLlmIac}
              disabled={loading}
              onCheckedChange={(v) => updateSettings({ enableLlmIac: v })}
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <Label>Enable LLM for Zero-Day</Label>
              <p className="text-sm text-muted-foreground">
                Use AI for advanced zero-day and business logic vulnerability detection
              </p>
            </div>
            <Switch
              checked={settings.enableLlmZeroDay}
              disabled={loading}
              onCheckedChange={(v) => updateSettings({ enableLlmZeroDay: v })}
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <Label>Enable LLM for Container</Label>
              <p className="text-sm text-muted-foreground">
                Use AI to analyze container images and configurations
              </p>
            </div>
            <Switch
              checked={settings.enableLlmContainer}
              disabled={loading}
              onCheckedChange={(v) => updateSettings({ enableLlmContainer: v })}
            />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Vulnerability Database</CardTitle>
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
            <p className="text-xs text-muted-foreground mt-2">
              {settings.vulnDbMode === "online" && (
                <>
                  <span className="font-semibold">Online:</span> Fetches real-time vulnerability data from OSV.dev. Requires internet connection. Recommended for most deployments.
                </>
              )}
              {settings.vulnDbMode === "mirror" && (
                <>
                  <span className="font-semibold">Mirrored:</span> Uses a self-hosted copy of the vulnerability database. Requires you to set up and maintain your own database mirror.
                </>
              )}
              {settings.vulnDbMode === "offline" && (
                <>
                  <span className="font-semibold">Offline:</span> Disables vulnerability database lookups. SCA scans will report dependencies without checking for known vulnerabilities.
                </>
              )}
            </p>
          </div>

          {settings.vulnDbMode !== "offline" && (
            <div className="space-y-2">
              <Label>
                {settings.vulnDbMode === "online" ? "OSV" : "Database"} API URL
              </Label>
              <Input
                value={settings.osvApiUrl}
                disabled={loading}
                onChange={(e) => {
                  const newUrl = e.target.value;
                  setSettings((s) => ({ ...s, osvApiUrl: newUrl }));
                }}
                onBlur={(e) => {
                  const newUrl = e.target.value;
                  if (newUrl && newUrl !== settings.osvApiUrl) {
                    void updateSettings({ osvApiUrl: newUrl });
                  }
                }}
                placeholder={
                  settings.vulnDbMode === "online"
                    ? "https://api.osv.dev"
                    : "https://your-mirror.example.com"
                }
              />
              <p className="text-xs text-muted-foreground">
                {settings.vulnDbMode === "online"
                  ? "Official OSV.dev API endpoint for fetching vulnerability data"
                  : "URL of your self-hosted vulnerability database"}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      <Button onClick={handleSave} disabled={loading}>
        {loading ? "Saving..." : "Save Settings"}
      </Button>
    </div>
  );
}
