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
import {
  CheckCircle,
  AlertCircle,
  Loader,
  Brain,
  Cloud,
  Server,
  Zap,
  Code2,
  Eye,
  EyeOff,
} from "lucide-react";

const DEFAULT_SETTINGS = {
  llmProvider: "openai",
  llmBaseUrl: "https://api.openai.com/v1",
  llmModel: "gpt-4o-mini",
  llmApiKey: "",
  hasApiKey: false,
  enableLlmSast: true,
  enableLlmSecrets: true,
  enableLlmSca: true,
  enableLlmIac: true,
  enableLlmZeroDay: true,
  enableLlmContainer: true,
  osvApiUrl: "https://api.osv.dev",
  vulnDbMode: "online",
};

type LlmSettings = typeof DEFAULT_SETTINGS;

type ProviderVerificationState = {
  status: "idle" | "verifying" | "success" | "error";
  message: string;
};

const PROVIDERS = [
  {
    id: "openai",
    name: "OpenAI",
    subtitle: "Connected",
    description: "GPT-4, GPT-4o, GPT-4 Turbo models",
    icon: Brain,
    baseUrl: "https://api.openai.com/v1",
    models: [
      "gpt-4o",
      "gpt-4o-mini",
      "gpt-4-turbo",
      "gpt-4",
      "gpt-3.5-turbo",
    ],
    requiresApiKey: true,
    keyUrl: "https://platform.openai.com/api-keys",
    color: "text-green-600",
  },
  {
    id: "claude",
    name: "Claude (Anthropic)",
    subtitle: "Multi-version",
    description: "Claude 3.5 Sonnet, Opus, Haiku models via Anthropic API",
    icon: Brain,
    baseUrl: "https://api.anthropic.com/v1",
    models: [
      "claude-3-5-sonnet-20241022",
      "claude-3-5-haiku-20241022",
      "claude-3-opus-20250219",
      "claude-3-sonnet-20240229",
    ],
    requiresApiKey: true,
    keyUrl: "https://console.anthropic.com/dashboard",
    color: "text-purple-600",
  },
  {
    id: "openrouter",
    name: "OpenRouter",
    subtitle: "Multi-model",
    description: "Access 100+ models (Google Gemini, Meta Llama, Mistral, DeepSeek)",
    icon: Cloud,
    baseUrl: "https://openrouter.ai/api/v1",
    models: [
      "google/gemini-2.5-flash",
      "google/gemini-2.5-pro",
      "meta-llama/llama-3.1-405b",
      "meta-llama/llama-3.1-70b",
      "mistral/mistral-large",
      "deepseek/deepseek-chat",
    ],
    requiresApiKey: true,
    keyUrl: "https://openrouter.ai/keys",
    color: "text-blue-600",
  },
  {
    id: "azure",
    name: "Azure OpenAI",
    subtitle: "Enterprise",
    description: "Azure-hosted OpenAI models",
    icon: Cloud,
    baseUrl: "https://YOUR_RESOURCE.openai.azure.com/openai/deployments/YOUR_DEPLOYMENT/chat/completions?api-version=2024-02-15-preview",
    models: ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4"],
    requiresApiKey: true,
    keyUrl: "https://portal.azure.com",
    color: "text-blue-500",
  },
  {
    id: "ollama",
    name: "Ollama",
    subtitle: "Local",
    description: "Local LLM (recommended for privacy, no API key needed)",
    icon: Server,
    baseUrl: "http://localhost:11434",
    models: [
      "qwen2.5:3b",
      "qwen2.5:7b",
      "llama2:7b",
      "llama2:13b",
      "mistral:7b",
      "neural-chat:7b",
    ],
    requiresApiKey: false,
    keyUrl: null,
    color: "text-orange-600",
  },
  {
    id: "vllm",
    name: "vLLM",
    subtitle: "Self-hosted",
    description: "Self-hosted LLM inference server",
    icon: Zap,
    baseUrl: "http://localhost:8000/v1",
    models: [
      "meta-llama/Llama-3.1-8B-Instruct",
      "meta-llama/Llama-3.1-70B-Instruct",
      "mistralai/Mistral-7B-Instruct-v0.2",
      "NousResearch/Nous-Hermes-2-Mixtral-8x7B-DPO",
    ],
    requiresApiKey: false,
    keyUrl: null,
    color: "text-yellow-600",
  },
  {
    id: "custom",
    name: "Custom Endpoint",
    subtitle: "Compatible",
    description: "Any OpenAI-compatible endpoint",
    icon: Code2,
    baseUrl: "",
    models: [],
    requiresApiKey: false,
    keyUrl: null,
    color: "text-gray-600",
  },
];

export default function LlmSettingsPage() {
  const [loading, setLoading] = useState(false);
  const [settings, setSettings] = useState<LlmSettings>(DEFAULT_SETTINGS);
  const [selectedModel, setSelectedModel] = useState("");
  const [customBaseUrl, setCustomBaseUrl] = useState("");
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [showApiKey, setShowApiKey] = useState(false);
  const [providerVerification, setProviderVerification] = useState<
    Record<string, ProviderVerificationState>
  >({});

  useEffect(() => {
    fetch("/api/settings/llm")
      .then((res) => res.json())
      .then((data) => {
        setSettings((s) => ({ ...s, ...data }));
        setSelectedModel(data.llmModel || "");
      });
  }, []);

  const currentProvider = PROVIDERS.find(
    (p) => p.id === settings.llmProvider
  );

  async function handleVerifyAndSave() {
    if (!selectedModel) {
      toast.error("Please select a model");
      return;
    }

    if (currentProvider?.requiresApiKey && !apiKeyInput) {
      toast.error("Please enter an API key");
      return;
    }

    const providerId = settings.llmProvider;
    setProviderVerification((prev) => ({
      ...prev,
      [providerId]: { status: "verifying", message: "Testing connection..." },
    }));

    try {
      const baseUrl =
        providerId === "custom" ? customBaseUrl : currentProvider?.baseUrl;

      if (!baseUrl) {
        throw new Error("Base URL is required");
      }

      const res = await fetch("/api/settings/llm/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          llmProvider: providerId,
          llmBaseUrl: baseUrl,
          llmModel: selectedModel,
          llmApiKey: apiKeyInput,
        }),
      });

      const data = await res.json();

      if (res.ok && data.success) {
        setProviderVerification((prev) => ({
          ...prev,
          [providerId]: {
            status: "success",
            message: data.message || "Verification successful!",
          },
        }));

        // Save settings after successful verification
        setLoading(true);
        const saveRes = await fetch("/api/settings/llm", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            llmProvider: providerId,
            llmBaseUrl: baseUrl,
            llmModel: selectedModel,
            llmApiKey: apiKeyInput,
            enableLlmSast: settings.enableLlmSast,
            enableLlmSecrets: settings.enableLlmSecrets,
            osvApiUrl: settings.osvApiUrl,
            vulnDbMode: settings.vulnDbMode,
          }),
        });

        if (saveRes.ok) {
          setSettings((s) => ({
            ...s,
            llmProvider: providerId,
            llmBaseUrl: baseUrl,
            llmModel: selectedModel,
            llmApiKey: "",
            hasApiKey: !!apiKeyInput,
          }));
          toast.success("Settings saved successfully!");
          setApiKeyInput("");
        } else {
          toast.error("Failed to save settings");
        }

        setLoading(false);
      } else {
        setProviderVerification((prev) => ({
          ...prev,
          [providerId]: {
            status: "error",
            message: data.error || "Verification failed",
          },
        }));
        toast.error(data.error || "Verification failed");
      }
    } catch (error) {
      const errorMsg =
        error instanceof Error ? error.message : "Connection failed";
      setProviderVerification((prev) => ({
        ...prev,
        [providerId]: {
          status: "error",
          message: errorMsg,
        },
      }));
      toast.error(errorMsg);
    }
  }

  async function updateSettings(
    patch: Partial<
      Pick<
        LlmSettings,
        | "enableLlmSast"
        | "enableLlmSecrets"
        | "enableLlmSca"
        | "enableLlmIac"
        | "enableLlmZeroDay"
        | "enableLlmContainer"
        | "vulnDbMode"
      >
    >,
  ) {
    const nextSettings = { ...settings, ...patch };
    setSettings(nextSettings);

    try {
      await fetch("/api/settings/llm", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(nextSettings),
      });
      toast.success("Settings updated");
    } catch {
      toast.error("Failed to update settings");
    }
  }

  const verificationState = providerVerification[settings.llmProvider] || {
    status: "idle",
    message: "",
  };

  return (
    <div className="max-w-7xl space-y-8">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "LLM config" },
        ]}
      />
      <div>
        <h1 className="text-3xl font-bold">LLM Configuration</h1>
        <p className="text-muted-foreground">
          Select and configure your LLM provider for AI-assisted code analysis
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>AI Provider</CardTitle>
          <CardDescription>
            Choose which AI runs SAST scans, attack planning, and remediation.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Provider Selection Grid */}
          <div className="grid gap-3 grid-cols-2 md:grid-cols-4">
            {PROVIDERS.map((provider) => {
              const IconComponent = provider.icon;
              const isSelected = settings.llmProvider === provider.id;
              const hasKey =
                isSelected && settings.hasApiKey && provider.requiresApiKey;

              return (
                <button
                  key={provider.id}
                  onClick={() => {
                    setSettings((s) => ({
                      ...s,
                      llmProvider: provider.id,
                    }));
                    setSelectedModel(settings.llmModel);
                    setApiKeyInput("");
                    setShowApiKey(false);
                    setCustomBaseUrl("");
                  }}
                  className={`flex flex-col items-center gap-2 p-4 rounded-lg border-2 transition-all ${
                    isSelected
                      ? "border-purple-400 bg-purple-50"
                      : "border-slate-200 bg-white hover:border-slate-300"
                  }`}
                >
                  <IconComponent
                    className={`h-6 w-6 ${
                      isSelected ? "text-purple-600" : "text-slate-500"
                    }`}
                  />
                  <span className="text-xs font-medium text-slate-700">
                    {provider.name}
                  </span>
                  {isSelected && hasKey && (
                    <span className="text-xs text-emerald-600 font-semibold">
                      ✓ Configured
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Configuration Section - Show when provider selected */}
          {settings.llmProvider && (
            <div className="border-t border-slate-200 pt-6 space-y-4">
              {(() => {
                const provider = PROVIDERS.find(
                  (p) => p.id === settings.llmProvider
                );
                if (!provider) return null;

                return (
                  <>
                    {/* Base URL */}
                    <div className="space-y-2">
                      <Label className="text-sm font-medium">Base URL</Label>
                      {provider.id === "custom" ? (
                        <Input
                          value={customBaseUrl}
                          onChange={(e) => setCustomBaseUrl(e.target.value)}
                          placeholder="https://your-endpoint.com/v1"
                        />
                      ) : (
                        <div className="bg-slate-50 border border-slate-200 rounded-md px-3 py-2 text-sm font-mono text-slate-700 truncate">
                          {provider.baseUrl}
                        </div>
                      )}
                    </div>

                    {/* Model Selection */}
                    <div className="space-y-2">
                      <Label className="text-sm font-medium">Model</Label>
                      {provider.models.length > 0 ? (
                        <Select value={selectedModel} onValueChange={setSelectedModel}>
                          <SelectTrigger>
                            <SelectValue placeholder="Select a model" />
                          </SelectTrigger>
                          <SelectContent>
                            {provider.models.map((model) => (
                              <SelectItem key={model} value={model}>
                                {model}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      ) : (
                        <Input
                          value={selectedModel}
                          onChange={(e) => setSelectedModel(e.target.value)}
                          placeholder="Enter model name"
                        />
                      )}
                    </div>

                    {/* API Key */}
                    {provider.requiresApiKey && (
                      <div className="space-y-2">
                        <Label className="text-sm font-medium">
                          API Key
                          {provider.keyUrl && (
                            <a
                              href={provider.keyUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="ml-2 text-purple-600 hover:underline text-xs font-normal"
                            >
                              (Get key)
                            </a>
                          )}
                        </Label>
                        <div className="flex gap-2">
                          <Input
                            type={showApiKey ? "text" : "password"}
                            value={apiKeyInput}
                            onChange={(e) => setApiKeyInput(e.target.value)}
                            placeholder={
                              settings.hasApiKey && !apiKeyInput
                                ? "••••••••••••••••"
                                : "Enter your API key"
                            }
                            className="font-mono"
                          />
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() => setShowApiKey(!showApiKey)}
                          >
                            {showApiKey ? (
                              <EyeOff className="h-4 w-4" />
                            ) : (
                              <Eye className="h-4 w-4" />
                            )}
                          </Button>
                        </div>
                      </div>
                    )}

                    {/* Verify & Save */}
                    {selectedModel && (
                      <Button
                        onClick={handleVerifyAndSave}
                        disabled={
                          loading || verificationState.status === "verifying"
                        }
                        className="w-full"
                      >
                        {verificationState.status === "verifying" ? (
                          <>
                            <Loader className="mr-2 h-4 w-4 animate-spin" />
                            Verifying...
                          </>
                        ) : verificationState.status === "success" ? (
                          <>
                            <CheckCircle className="mr-2 h-4 w-4" />
                            Verified & Saved
                          </>
                        ) : (
                          "Verify & Save"
                        )}
                      </Button>
                    )}

                    {/* Status Message */}
                    {verificationState.status === "error" && (
                      <div className="rounded-md bg-red-50 border border-red-200 p-3 text-sm text-red-700">
                        {verificationState.message}
                      </div>
                    )}

                    {verificationState.status === "success" && (
                      <div className="rounded-md bg-emerald-50 border border-emerald-200 p-3 text-sm text-emerald-700">
                        {verificationState.message}
                      </div>
                    )}
                  </>
                );
              })()}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Features Section */}
      <Card>
        <CardHeader>
          <CardTitle>Features</CardTitle>
          <CardDescription>Configure LLM-powered analysis features</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between rounded-lg border border-slate-200 p-4">
            <div>
              <Label className="font-semibold">Enable LLM for SAST</Label>
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

          <div className="flex items-center justify-between rounded-lg border border-slate-200 p-4">
            <div>
              <Label className="font-semibold">Enable LLM for Secrets</Label>
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

          <div className="flex items-center justify-between rounded-lg border border-slate-200 p-4">
            <div>
              <Label className="font-semibold">Enable LLM for SCA</Label>
              <p className="text-sm text-muted-foreground">
                Use AI to enhance dependency analysis and vulnerability correlation
              </p>
            </div>
            <Switch
              checked={settings.enableLlmSca}
              disabled={loading}
              onCheckedChange={(v) => updateSettings({ enableLlmSca: v })}
            />
          </div>

          <div className="flex items-center justify-between rounded-lg border border-slate-200 p-4">
            <div>
              <Label className="font-semibold">Enable LLM for IaC</Label>
              <p className="text-sm text-muted-foreground">
                Use AI to analyze Infrastructure as Code (Terraform, CloudFormation) for misconfigurations
              </p>
            </div>
            <Switch
              checked={settings.enableLlmIac}
              disabled={loading}
              onCheckedChange={(v) => updateSettings({ enableLlmIac: v })}
            />
          </div>

          <div className="flex items-center justify-between rounded-lg border border-slate-200 p-4">
            <div>
              <Label className="font-semibold">Enable LLM for Zero-Day</Label>
              <p className="text-sm text-muted-foreground">
                Use AI to detect emerging and zero-day vulnerabilities
              </p>
            </div>
            <Switch
              checked={settings.enableLlmZeroDay}
              disabled={loading}
              onCheckedChange={(v) => updateSettings({ enableLlmZeroDay: v })}
            />
          </div>

          <div className="flex items-center justify-between rounded-lg border border-slate-200 p-4">
            <div>
              <Label className="font-semibold">Enable LLM for Container</Label>
              <p className="text-sm text-muted-foreground">
                Use AI to analyze Docker images and container configurations
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

      {/* Vulnerability Database Section */}
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
