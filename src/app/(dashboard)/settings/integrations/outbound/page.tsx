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
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";
import { Plus, Trash2 } from "lucide-react";

type IntegrationKind = "SLACK" | "JIRA" | "WEBHOOK";

interface IntegrationRow {
  id: string;
  kind: IntegrationKind;
  name: string;
  enabled: boolean;
  updatedAt: string;
}

interface ApiList {
  integrations: IntegrationRow[];
}

type WebhookEvent = "scan.completed" | "scan.gate_failed" | "finding.new.critical" | "finding.new.high";

const WEBHOOK_EVENTS: { value: WebhookEvent; label: string; description: string }[] = [
  { value: "scan.completed", label: "Scan completed", description: "Every time a scan finishes" },
  { value: "scan.gate_failed", label: "Gate failed", description: "When the build gate is blocked" },
  { value: "finding.new.critical", label: "New critical finding", description: "When a new critical severity finding is detected" },
  { value: "finding.new.high", label: "New high finding", description: "When a new high or critical finding is detected" },
];

const PAYLOAD_TEMPLATES = [
  { value: "default", label: "Default JSON (Pepper native format)" },
  { value: "slack", label: "Slack incoming webhook (Block Kit)" },
  { value: "teams", label: "Microsoft Teams (MessageCard)" },
  { value: "pagerduty", label: "PagerDuty Events API v2" },
  { value: "linear", label: "Linear create-issue format" },
];

const SEVERITY_OPTIONS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export default function OutboundIntegrationsPage() {
  const [rows, setRows] = useState<IntegrationRow[]>([]);
  const [loading, setLoading] = useState(true);

  // Slack form
  const [slackWebhook, setSlackWebhook] = useState("");
  const [slackChannel, setSlackChannel] = useState("");

  // Jira form
  const [jiraUrl, setJiraUrl] = useState("");
  const [jiraEmail, setJiraEmail] = useState("");
  const [jiraToken, setJiraToken] = useState("");
  const [jiraProject, setJiraProject] = useState("");
  const [jiraIssueType, setJiraIssueType] = useState("Bug");

  // Generic webhook form
  const [whUrl, setWhUrl] = useState("");
  const [whEvents, setWhEvents] = useState<WebhookEvent[]>(["scan.completed", "scan.gate_failed"]);
  const [whMinSeverity, setWhMinSeverity] = useState("INFO");
  const [whTemplate, setWhTemplate] = useState("default");
  const [whSecret, setWhSecret] = useState("");
  const [whHeaders, setWhHeaders] = useState<{ key: string; value: string }[]>([]);

  async function reload() {
    setLoading(true);
    try {
      const res = await fetch("/api/integrations");
      if (res.ok) {
        const data = (await res.json()) as ApiList;
        setRows(data.integrations);
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void reload();
  }, []);

  async function save(payload: {
    kind: IntegrationKind;
    config: unknown;
    name: string;
  }) {
    const res = await fetch("/api/integrations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const j = (await res.json()) as { error?: string };
      toast.error(j.error || "Save failed");
      return;
    }
    toast.success(`${payload.kind} integration saved`);
    void reload();
  }

  async function remove(id: string) {
    if (!confirm("Delete this integration?")) return;
    const res = await fetch(`/api/integrations/${id}`, { method: "DELETE" });
    if (res.ok) {
      toast.success("Deleted");
      void reload();
    } else toast.error("Delete failed");
  }

  async function testIntegration(kind: IntegrationKind, config: unknown) {
    const res = await fetch("/api/integrations/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind, config }),
    });
    const j = (await res.json()) as { error?: string; ok?: boolean };
    if (res.ok && j.ok) toast.success(`${kind} test ok`);
    else toast.error(j.error || `${kind} test failed`);
  }

  function toggleWhEvent(event: WebhookEvent) {
    setWhEvents((prev) =>
      prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event],
    );
  }

  function addHeader() {
    setWhHeaders((prev) => [...prev, { key: "", value: "" }]);
  }

  function updateHeader(idx: number, field: "key" | "value", val: string) {
    setWhHeaders((prev) => prev.map((h, i) => (i === idx ? { ...h, [field]: val } : h)));
  }

  function removeHeader(idx: number) {
    setWhHeaders((prev) => prev.filter((_, i) => i !== idx));
  }

  function buildWebhookConfig() {
    return {
      webhookUrl: whUrl,
      events: whEvents,
      minSeverity: whMinSeverity !== "INFO" ? whMinSeverity : undefined,
      payloadTemplate: whTemplate !== "default" ? whTemplate : undefined,
      secret: whSecret || undefined,
      headers: whHeaders.filter((h) => h.key && h.value),
    };
  }

  return (
    <div className="max-w-3xl space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Settings", href: "/settings/integrations" },
          { label: "Outbound" },
        ]}
      />
      <div>
        <h1 className="text-2xl font-bold">Outbound integrations</h1>
        <p className="text-muted-foreground">
          Forward findings to ticketing and chat tools. Secrets are
          encrypted at rest with AES-256-GCM.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Active integrations</CardTitle>
          <CardDescription>
            {loading
              ? "Loading…"
              : rows.length === 0
                ? "No integrations configured yet."
                : `${rows.length} integration(s) active.`}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          {rows.map((r) => (
            <div key={r.id} className="flex items-center justify-between border-b py-2 last:border-0">
              <div className="flex items-center gap-2">
                <Badge variant="outline">{r.kind}</Badge>
                <span>{r.name}</span>
                {!r.enabled && <Badge variant="secondary">disabled</Badge>}
              </div>
              <Button size="sm" variant="ghost" onClick={() => void remove(r.id)}>
                Delete
              </Button>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* ── Slack ── */}
      <Card>
        <CardHeader>
          <CardTitle>Slack</CardTitle>
          <CardDescription>
            Incoming webhook URL. Notifies on scan complete and gate failures.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-1">
            <Label>Webhook URL</Label>
            <Input
              placeholder="https://hooks.slack.com/services/..."
              value={slackWebhook}
              onChange={(e) => setSlackWebhook(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label>Channel (optional)</Label>
            <Input
              placeholder="#security"
              value={slackChannel}
              onChange={(e) => setSlackChannel(e.target.value)}
            />
          </div>
          <div className="flex gap-2">
            <Button
              disabled={!slackWebhook}
              onClick={() =>
                void save({
                  kind: "SLACK",
                  name: `Slack (${slackChannel || "default"})`,
                  config: {
                    webhookUrl: slackWebhook,
                    channel: slackChannel || undefined,
                    notifyOn: ["scan_complete", "gate_failed"],
                  },
                })
              }
            >
              Save Slack integration
            </Button>
            <Button
              variant="outline"
              disabled={!slackWebhook}
              onClick={() =>
                void testIntegration("SLACK", {
                  webhookUrl: slackWebhook,
                  channel: slackChannel || undefined,
                  notifyOn: ["scan_complete"],
                })
              }
            >
              Send test message
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* ── Jira ── */}
      <Card>
        <CardHeader>
          <CardTitle>Jira</CardTitle>
          <CardDescription>
            Opens tickets in your project for new CRITICAL/HIGH findings.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label>Base URL</Label>
              <Input
                placeholder="https://your-org.atlassian.net"
                value={jiraUrl}
                onChange={(e) => setJiraUrl(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label>Project key</Label>
              <Input
                placeholder="SEC"
                value={jiraProject}
                onChange={(e) => setJiraProject(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label>Email</Label>
              <Input
                placeholder="bot@your-org.com"
                value={jiraEmail}
                onChange={(e) => setJiraEmail(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label>API token</Label>
              <Input
                type="password"
                value={jiraToken}
                onChange={(e) => setJiraToken(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label>Issue type</Label>
              <Input
                value={jiraIssueType}
                onChange={(e) => setJiraIssueType(e.target.value)}
              />
            </div>
          </div>
          <div className="flex gap-2">
            <Button
              disabled={!jiraUrl || !jiraEmail || !jiraToken || !jiraProject}
              onClick={() =>
                void save({
                  kind: "JIRA",
                  name: `Jira (${jiraProject})`,
                  config: {
                    baseUrl: jiraUrl,
                    email: jiraEmail,
                    apiToken: jiraToken,
                    projectKey: jiraProject,
                    issueType: jiraIssueType,
                    openForSeverities: ["CRITICAL", "HIGH"],
                  },
                })
              }
            >
              Save Jira integration
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* ── Generic Webhook ── */}
      <Card>
        <CardHeader>
          <CardTitle>Generic Webhook</CardTitle>
          <CardDescription>
            POST scan events to any URL — Slack, Teams, PagerDuty, Linear, Zapier, email relay, or your own endpoint.
            Payload shape is configurable with pre-built templates.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* URL */}
          <div className="space-y-1">
            <Label>Webhook URL</Label>
            <Input
              placeholder="https://hooks.example.com/..."
              value={whUrl}
              onChange={(e) => setWhUrl(e.target.value)}
            />
          </div>

          {/* Events */}
          <div className="space-y-2">
            <Label>Trigger on</Label>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {WEBHOOK_EVENTS.map((ev) => (
                <label key={ev.value} className="flex items-start gap-2 rounded-md border p-2.5 cursor-pointer hover:bg-muted/50">
                  <Checkbox
                    checked={whEvents.includes(ev.value)}
                    onCheckedChange={() => toggleWhEvent(ev.value)}
                    className="mt-0.5"
                  />
                  <div>
                    <p className="text-sm font-medium">{ev.label}</p>
                    <p className="text-xs text-muted-foreground">{ev.description}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Payload template */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label>Payload template</Label>
              <Select value={whTemplate} onValueChange={setWhTemplate}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PAYLOAD_TEMPLATES.map((t) => (
                    <SelectItem key={t.value} value={t.value}>
                      {t.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label>Min severity (skip if no findings meet threshold)</Label>
              <Select value={whMinSeverity} onValueChange={setWhMinSeverity}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SEVERITY_OPTIONS.map((s) => (
                    <SelectItem key={s} value={s}>{s}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Custom headers */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label>Custom headers</Label>
              <Button type="button" size="sm" variant="outline" onClick={addHeader} className="h-7 gap-1 text-xs">
                <Plus className="h-3 w-3" /> Add header
              </Button>
            </div>
            {whHeaders.length === 0 && (
              <p className="text-xs text-muted-foreground">No custom headers. Add one for Bearer auth or API keys.</p>
            )}
            {whHeaders.map((h, idx) => (
              <div key={idx} className="flex items-center gap-2">
                <Input
                  placeholder="Header name (e.g. Authorization)"
                  value={h.key}
                  onChange={(e) => updateHeader(idx, "key", e.target.value)}
                  className="flex-1"
                />
                <Input
                  placeholder="Value (e.g. Bearer token…)"
                  value={h.value}
                  onChange={(e) => updateHeader(idx, "value", e.target.value)}
                  className="flex-1"
                  type="password"
                />
                <Button
                  type="button"
                  size="icon"
                  variant="ghost"
                  onClick={() => removeHeader(idx)}
                  className="h-8 w-8 shrink-0 text-muted-foreground hover:text-destructive"
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            ))}
          </div>

          {/* Signing secret */}
          <div className="space-y-1">
            <Label>Signing secret (optional)</Label>
            <Input
              type="password"
              placeholder="Used to generate X-Pepper-Signature: sha256=… header"
              value={whSecret}
              onChange={(e) => setWhSecret(e.target.value)}
            />
            <p className="text-[11px] text-muted-foreground">
              If set, each request includes a HMAC-SHA256 signature so your endpoint can verify it came from Pepper.
            </p>
          </div>

          <div className="flex gap-2">
            <Button
              disabled={!whUrl || whEvents.length === 0}
              onClick={() => {
                const config = buildWebhookConfig();
                void save({
                  kind: "WEBHOOK",
                  name: (() => {
                    try { return `Webhook (${new URL(whUrl).host})`; } catch { return "Webhook"; }
                  })(),
                  config,
                });
              }}
            >
              Save webhook
            </Button>
            <Button
              variant="outline"
              disabled={!whUrl}
              onClick={() => void testIntegration("WEBHOOK", buildWebhookConfig())}
            >
              Send test event
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
