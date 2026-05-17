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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

type IntegrationKind = "SLACK" | "JIRA" | "SIEM" | "DAST";

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

  // SIEM form
  const [siemEndpoint, setSiemEndpoint] = useState("");
  const [siemFormat, setSiemFormat] = useState<"cef" | "leef" | "json">("cef");
  const [siemKey, setSiemKey] = useState("");

  // Dapper form
  const [dapperEndpoint, setDapperEndpoint] = useState("");
  const [dapperKey, setDapperKey] = useState("");

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

  async function testIntegration(
    kind: IntegrationKind,
    config: unknown,
  ) {
    const res = await fetch("/api/integrations/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind, config }),
    });
    const j = (await res.json()) as { error?: string; ok?: boolean };
    if (res.ok && j.ok) toast.success(`${kind} test ok`);
    else toast.error(j.error || `${kind} test failed`);
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
          Forward findings to ticketing, chat and SIEM tools. Secrets are
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

      <Card>
        <CardHeader>
          <CardTitle>SIEM</CardTitle>
          <CardDescription>
            HTTPS endpoint or syslog target (udp://host:514 / tcp://host:601)
            for CEF, LEEF or JSON event forwarding.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-1">
            <Label>Endpoint</Label>
            <Input
              placeholder="https://collector.example.com/intake  or  udp://siem:514"
              value={siemEndpoint}
              onChange={(e) => setSiemEndpoint(e.target.value)}
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label>Format</Label>
              <Select
                value={siemFormat}
                onValueChange={(v) =>
                  setSiemFormat(v as "cef" | "leef" | "json")
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="cef">CEF</SelectItem>
                  <SelectItem value="leef">LEEF</SelectItem>
                  <SelectItem value="json">JSON</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label>Bearer token (HTTPS only)</Label>
              <Input
                type="password"
                value={siemKey}
                onChange={(e) => setSiemKey(e.target.value)}
              />
            </div>
          </div>
          <div className="flex gap-2">
            <Button
              disabled={!siemEndpoint}
              onClick={() =>
                void save({
                  kind: "SIEM",
                  name: `SIEM (${siemFormat.toUpperCase()})`,
                  config: {
                    endpoint: siemEndpoint,
                    format: siemFormat,
                    apiKey: siemKey || undefined,
                  },
                })
              }
            >
              Save SIEM integration
            </Button>
            <Button
              variant="outline"
              disabled={!siemEndpoint}
              onClick={() =>
                void testIntegration("SIEM", {
                  endpoint: siemEndpoint,
                  format: siemFormat,
                  apiKey: siemKey || undefined,
                })
              }
            >
              Send test event
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Dapper (DAST)</CardTitle>
          <CardDescription>
            Delegate dynamic application security testing to{" "}
            <a
              href="https://github.com/sundi133/dapper"
              className="underline"
              target="_blank"
              rel="noreferrer"
            >
              dapper
            </a>
            . Set the target URL per project in its settings.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-1">
            <Label>Dapper endpoint</Label>
            <Input
              placeholder="http://dapper:8080"
              value={dapperEndpoint}
              onChange={(e) => setDapperEndpoint(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label>API key (optional)</Label>
            <Input
              type="password"
              value={dapperKey}
              onChange={(e) => setDapperKey(e.target.value)}
            />
          </div>
          <Button
            disabled={!dapperEndpoint}
            onClick={() =>
              void save({
                kind: "DAST",
                name: "Dapper",
                config: {
                  endpoint: dapperEndpoint,
                  apiKey: dapperKey || undefined,
                },
              })
            }
          >
            Save Dapper integration
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
