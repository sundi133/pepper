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
import { toast } from "sonner";
import { Eye, EyeOff, KeyRound } from "lucide-react";

type WebhookMeta = {
  hasGithub: boolean;
  hasGitlab: boolean;
  hasBitbucket: boolean;
  hasAzureDevOps: boolean;
  envFallback: {
    github: boolean;
    gitlab: boolean;
    bitbucket: boolean;
    azureDevOps: boolean;
  };
};

function randomSecret(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function SecretField({
  id,
  label,
  value,
  onChange,
  configured,
  envActive,
  onClear,
  onRevealSaved,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  configured: boolean;
  envActive: boolean;
  onClear: () => void;
  onRevealSaved: () => Promise<string | null>;
}) {
  const [show, setShow] = useState(false);
  const [revealing, setRevealing] = useState(false);

  return (
    <div className="space-y-1.5 rounded-lg border p-3">
      <div className="flex items-center justify-between gap-2">
        <Label htmlFor={id}>{label}</Label>
        <div className="flex flex-wrap gap-1 justify-end">
          {configured ? (
            <Badge variant="secondary">Saved in Pepper</Badge>
          ) : null}
          {envActive ? (
            <Badge variant="outline">Env fallback active</Badge>
          ) : null}
        </div>
      </div>
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Input
            id={id}
            type={show ? "text" : "password"}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder={
              configured
                ? "Leave blank to keep current — use Show saved to view"
                : "Paste or generate a secret"
            }
            autoComplete="new-password"
            className="pr-10"
          />
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
            aria-label={show ? "Hide secret" : "Show secret"}
            onClick={() => setShow((s) => !s)}
          >
            {show ? (
              <EyeOff className="h-4 w-4 text-muted-foreground" />
            ) : (
              <Eye className="h-4 w-4 text-muted-foreground" />
            )}
          </Button>
        </div>
        <Button
          type="button"
          variant="outline"
          onClick={() => onChange(randomSecret())}
        >
          Generate
        </Button>
        {configured ? (
          <>
            <Button
              type="button"
              variant="outline"
              disabled={revealing}
              onClick={() => {
                setRevealing(true);
                void onRevealSaved()
                  .then((plain) => {
                    if (plain) {
                      onChange(plain);
                      setShow(true);
                    } else toast.error("No saved secret for this field");
                  })
                  .finally(() => setRevealing(false));
              }}
            >
              {revealing ? "…" : "Show saved"}
            </Button>
            <Button type="button" variant="ghost" onClick={onClear}>
              Clear
            </Button>
          </>
        ) : null}
      </div>
    </div>
  );
}

export function WebhookSecretsCard() {
  const [meta, setMeta] = useState<WebhookMeta | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [github, setGithub] = useState("");
  const [gitlab, setGitlab] = useState("");
  const [bitbucket, setBitbucket] = useState("");
  const [azureDevOps, setAzureDevOps] = useState("");
  const [clearGithub, setClearGithub] = useState(false);
  const [clearGitlab, setClearGitlab] = useState(false);
  const [clearBitbucket, setClearBitbucket] = useState(false);
  const [clearAzure, setClearAzure] = useState(false);
  const [saving, setSaving] = useState(false);

  async function load() {
    setLoadError(null);
    const res = await fetch("/api/settings/webhooks");
    const data = (await res.json()) as WebhookMeta & {
      error?: string;
      detail?: string;
    };
    if (!res.ok) {
      setLoadError(data.error || data.detail || `HTTP ${res.status}`);
      return;
    }
    setMeta(data);
  }

  async function revealField(
    key: "github" | "gitlab" | "bitbucket" | "azureDevOps",
  ): Promise<string | null> {
    const res = await fetch("/api/settings/webhooks?reveal=1");
    const data = (await res.json()) as Record<string, string | null | undefined> & {
      error?: string;
      detail?: string;
    };
    if (!res.ok) {
      toast.error(data.error || data.detail || "Could not load saved secret");
      return null;
    }
    return data[key] ?? null;
  }

  useEffect(() => {
    void load();
  }, []);

  async function save() {
    setSaving(true);
    try {
      const body: Record<string, string | null> = {};
      if (clearGithub) body.github = null;
      else if (github.trim()) body.github = github.trim();
      if (clearGitlab) body.gitlab = null;
      else if (gitlab.trim()) body.gitlab = gitlab.trim();
      if (clearBitbucket) body.bitbucket = null;
      else if (bitbucket.trim()) body.bitbucket = bitbucket.trim();
      if (clearAzure) body.azureDevOps = null;
      else if (azureDevOps.trim()) body.azureDevOps = azureDevOps.trim();

      const res = await fetch("/api/settings/webhooks", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = (await res.json()) as { error?: string; detail?: string };
      if (!res.ok) {
        toast.error(
          [data.error, data.detail].filter(Boolean).join(" — ") ||
            "Failed to save webhook secrets",
        );
        return;
      }
      toast.success("Webhook secrets saved");
      setGithub("");
      setGitlab("");
      setBitbucket("");
      setAzureDevOps("");
      setClearGithub(false);
      setClearGitlab(false);
      setClearBitbucket(false);
      setClearAzure(false);
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  const hasPendingSave =
    clearGithub ||
    clearGitlab ||
    clearBitbucket ||
    clearAzure ||
    github.trim().length > 0 ||
    gitlab.trim().length > 0 ||
    bitbucket.trim().length > 0 ||
    azureDevOps.trim().length > 0;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <KeyRound className="h-5 w-5" />
          <CardTitle>Webhook secrets</CardTitle>
          <Badge variant="outline">Required for 401-free deliveries</Badge>
        </div>
        <CardDescription>
          Set the same secret here and in each Git host webhook configuration.
          Use the eye icon to show a value while typing, or <strong>Show saved</strong>{" "}
          to load secrets already stored in Pepper (then copy to GitHub/GitLab).
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {loadError ? (
          <p className="text-sm text-destructive rounded-md border border-destructive/30 bg-destructive/5 p-3">
            {loadError}
          </p>
        ) : null}
        <SecretField
          id="wh-github"
          label="GitHub webhook secret"
          value={github}
          onChange={(v) => {
            setGithub(v);
            setClearGithub(false);
          }}
          configured={!!meta?.hasGithub}
          envActive={!!meta?.envFallback.github}
          onClear={() => {
            setGithub("");
            setClearGithub(true);
          }}
          onRevealSaved={() => revealField("github")}
        />
        <SecretField
          id="wh-gitlab"
          label="GitLab webhook secret token"
          value={gitlab}
          onChange={(v) => {
            setGitlab(v);
            setClearGitlab(false);
          }}
          configured={!!meta?.hasGitlab}
          envActive={!!meta?.envFallback.gitlab}
          onClear={() => {
            setGitlab("");
            setClearGitlab(true);
          }}
          onRevealSaved={() => revealField("gitlab")}
        />
        <SecretField
          id="wh-bitbucket"
          label="Bitbucket webhook secret"
          value={bitbucket}
          onChange={(v) => {
            setBitbucket(v);
            setClearBitbucket(false);
          }}
          configured={!!meta?.hasBitbucket}
          envActive={!!meta?.envFallback.bitbucket}
          onClear={() => {
            setBitbucket("");
            setClearBitbucket(true);
          }}
          onRevealSaved={() => revealField("bitbucket")}
        />
        <SecretField
          id="wh-azure"
          label="Azure DevOps basic auth password"
          value={azureDevOps}
          onChange={(v) => {
            setAzureDevOps(v);
            setClearAzure(false);
          }}
          configured={!!meta?.hasAzureDevOps}
          envActive={!!meta?.envFallback.azureDevOps}
          onClear={() => {
            setAzureDevOps("");
            setClearAzure(true);
          }}
          onRevealSaved={() => revealField("azureDevOps")}
        />
        <Button
          onClick={() => void save()}
          disabled={saving || !hasPendingSave}
        >
          {saving ? "Saving…" : "Save webhook secrets"}
        </Button>
        {!hasPendingSave ? (
          <p className="text-xs text-muted-foreground">
            Generate or paste a secret, then save. The button enables when there
            is something to write.
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}
