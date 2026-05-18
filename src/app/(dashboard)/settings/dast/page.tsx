"use client";

import { useEffect, useState } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

export default function DastSettingsPage() {
  const [enabled, setEnabled] = useState(false);
  const [endpoint, setEndpoint] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [hasApiKey, setHasApiKey] = useState(false);
  const [configYaml, setConfigYaml] = useState("");
  const [hasConfigYaml, setHasConfigYaml] = useState(false);
  const [saving, setSaving] = useState(false);

  async function load() {
    const res = await fetch("/api/settings/dast");
    if (!res.ok) return;
    const j = (await res.json()) as {
      enabled: boolean;
      endpoint: string;
      hasApiKey: boolean;
      configYaml: string;
      hasConfigYaml: boolean;
    };
    setEnabled(j.enabled);
    setEndpoint(j.endpoint);
    setHasApiKey(j.hasApiKey);
    setConfigYaml(j.configYaml);
    setHasConfigYaml(j.hasConfigYaml);
  }

  useEffect(() => {
    void load();
  }, []);

  async function save() {
    setSaving(true);
    try {
      const res = await fetch("/api/settings/dast", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enabled,
          endpoint,
          apiKey: apiKey || undefined,
          configYaml,
        }),
      });
      if (!res.ok) toast.error("Save failed");
      else {
        toast.success("DAST settings saved");
        setApiKey("");
        void load();
      }
    } finally {
      setSaving(false);
    }
  }

  async function test() {
    const res = await fetch("/api/settings/dast", { method: "POST" });
    const j = (await res.json()) as { ok?: boolean; status?: number; error?: string };
    if (res.ok && j.ok) toast.success(`Dapper reachable (HTTP ${j.status})`);
    else toast.error(j.error || `Dapper unreachable (HTTP ${j.status ?? "?"})`);
  }

  return (
    <div className="max-w-2xl space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Settings", href: "/settings/integrations" },
          { label: "DAST (Dapper)" },
        ]}
      />
      <div>
        <h1 className="text-2xl font-bold">Dynamic application security testing</h1>
        <p className="text-muted-foreground">
          Delegate runtime testing to{" "}
          <a
            className="underline"
            href="https://github.com/sundi133/dapper"
            target="_blank"
            rel="noreferrer"
          >
            dapper
          </a>
          . Per-project target URLs are configured on the project settings page.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Dapper instance</CardTitle>
          <CardDescription>
            When enabled, FULL and DAST_ONLY scans on projects with a{" "}
            <code>dastTargetUrl</code> will trigger a dapper run.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <Label htmlFor="dast-enabled">Enable DAST scanner</Label>
            <Switch
              id="dast-enabled"
              checked={enabled}
              onCheckedChange={setEnabled}
            />
          </div>
          <div className="space-y-1">
            <Label>Dapper endpoint</Label>
            <Input
              placeholder="http://dapper:8080"
              value={endpoint}
              onChange={(e) => setEndpoint(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label>API key {hasApiKey && <span className="text-xs text-muted-foreground">(stored)</span>}</Label>
            <Input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={hasApiKey ? "•••••• stored" : ""}
            />
          </div>
          <div className="space-y-1">
            <Label>
              Dapper config YAML{" "}
              {hasConfigYaml && <span className="text-xs text-muted-foreground">(stored)</span>}
            </Label>
            <textarea
              className="min-h-[220px] w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm shadow-sm outline-none ring-offset-background placeholder:text-muted-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
              placeholder={`# Paste the contents of your dapper config here.\nauthentication:\n  login_type: form\n  login_url: https://example.com/login\n  credentials:\n    username: admin\n    password: password`}
              value={configYaml}
              onChange={(e) => setConfigYaml(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              Pepper stores this encrypted and writes it into the Dapper workspace as a config
              file when local orchestration runs.
            </p>
          </div>
          <div className="flex gap-2">
            <Button disabled={saving} onClick={() => void save()}>
              {saving ? "Saving…" : "Save"}
            </Button>
            <Button variant="outline" disabled={!endpoint} onClick={() => void test()}>
              Test connection
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
