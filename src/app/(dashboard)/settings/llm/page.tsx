"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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

export default function LlmSettingsPage() {
  const [loading, setLoading] = useState(false);
  const [settings, setSettings] = useState({
    llmProvider: "openai",
    llmBaseUrl: "https://api.openai.com/v1",
    llmModel: "gpt-4o-mini",
    llmApiKey: "",
    hasApiKey: false,
    enableLlmSast: true,
    enableLlmSecrets: true,
    osvApiUrl: "https://api.osv.dev",
    vulnDbMode: "online",
  });

  useEffect(() => {
    fetch("/api/settings/llm")
      .then((res) => res.json())
      .then((data) => setSettings((s) => ({ ...s, ...data })));
  }, []);

  async function handleSave() {
    setLoading(true);
    try {
      const res = await fetch("/api/settings/llm", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(settings),
      });
      if (!res.ok) throw new Error("Failed to save");
      toast.success("Settings saved");
    } catch {
      toast.error("Failed to save settings");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-2xl space-y-6">
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
            Supports any OpenAI-compatible API endpoint (OpenAI, Azure, Ollama, vLLM)
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Provider</Label>
            <Select
              value={settings.llmProvider}
              onValueChange={(v) => {
                const defaults: Record<string, { url: string; model: string }> = {
                  openai: { url: "https://api.openai.com/v1", model: "gpt-4o-mini" },
                  azure: { url: "https://YOUR_RESOURCE.openai.azure.com", model: "gpt-4o-mini" },
                  ollama: { url: "http://host.docker.internal:11434", model: "qwen2.5:3b" },
                  vllm: { url: "http://localhost:8000/v1", model: "meta-llama/Llama-3-8b" },
                  custom: { url: "", model: "" },
                };
                const d = defaults[v] || defaults.custom;
                setSettings((s) => ({ ...s, llmProvider: v, llmBaseUrl: d.url, llmModel: d.model }));
              }}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ollama">Ollama (Local, recommended)</SelectItem>
                <SelectItem value="openai">OpenAI</SelectItem>
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
              onChange={(e) => setSettings((s) => ({ ...s, llmBaseUrl: e.target.value }))}
              placeholder="https://api.openai.com/v1"
            />
          </div>

          <div className="space-y-2">
            <Label>Model</Label>
            <Input
              value={settings.llmModel}
              onChange={(e) => setSettings((s) => ({ ...s, llmModel: e.target.value }))}
              placeholder="gpt-4o-mini"
            />
          </div>

          {settings.llmProvider !== "ollama" && (
            <div className="space-y-2">
              <Label>API Key {settings.hasApiKey && "(configured)"}</Label>
              <Input
                type="password"
                value={settings.llmApiKey}
                onChange={(e) => setSettings((s) => ({ ...s, llmApiKey: e.target.value }))}
                placeholder={settings.hasApiKey ? "Leave empty to keep current key" : "Enter API key"}
              />
            </div>
          )}

          {settings.llmProvider === "ollama" && (
            <div className="rounded-md bg-muted p-3 text-sm text-muted-foreground">
              Ollama runs locally — no API key needed. The model will be pulled automatically on first scan.
              Make sure the Ollama service is running (included in Docker Compose).
            </div>
          )}

          <div className="flex items-center justify-between pt-4">
            <div>
              <Label>Enable LLM for SAST</Label>
              <p className="text-sm text-muted-foreground">Use AI to analyze code for vulnerabilities</p>
            </div>
            <Switch
              checked={settings.enableLlmSast}
              onCheckedChange={(v) => setSettings((s) => ({ ...s, enableLlmSast: v }))}
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <Label>Enable LLM for Secrets</Label>
              <p className="text-sm text-muted-foreground">Use AI to reduce false positives in secret detection</p>
            </div>
            <Switch
              checked={settings.enableLlmSecrets}
              onCheckedChange={(v) => setSettings((s) => ({ ...s, enableLlmSecrets: v }))}
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
              onValueChange={(v) => setSettings((s) => ({ ...s, vulnDbMode: v }))}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="online">Online (OSV.dev API)</SelectItem>
                <SelectItem value="mirror">Mirrored (Self-hosted)</SelectItem>
                <SelectItem value="offline">Offline (Bundled snapshot)</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label>OSV API URL</Label>
            <Input
              value={settings.osvApiUrl}
              onChange={(e) => setSettings((s) => ({ ...s, osvApiUrl: e.target.value }))}
              placeholder="https://api.osv.dev"
            />
          </div>
        </CardContent>
      </Card>

      <Button onClick={handleSave} disabled={loading}>
        {loading ? "Saving..." : "Save Settings"}
      </Button>
    </div>
  );
}
