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
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

export default function SigningSettingsPage() {
  const [enabled, setEnabled] = useState(false);
  const [mode, setMode] = useState<"keyless" | "key">("keyless");
  const [identity, setIdentity] = useState("");
  const [pem, setPem] = useState("");
  const [hasKey, setHasKey] = useState(false);
  const [saving, setSaving] = useState(false);

  async function load() {
    const res = await fetch("/api/settings/signing");
    if (!res.ok) return;
    const j = (await res.json()) as {
      enabled: boolean;
      mode: "keyless" | "key";
      identity: string;
      hasKey: boolean;
    };
    setEnabled(j.enabled);
    setMode(j.mode);
    setIdentity(j.identity);
    setHasKey(j.hasKey);
  }

  useEffect(() => {
    void load();
  }, []);

  async function save() {
    setSaving(true);
    try {
      const res = await fetch("/api/settings/signing", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enabled,
          mode,
          identity,
          privateKeyPem: pem || undefined,
        }),
      });
      if (!res.ok) toast.error("Save failed");
      else {
        toast.success("Signing settings saved");
        setPem("");
        void load();
      }
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="max-w-2xl space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Settings", href: "/settings/integrations" },
          { label: "Code signing" },
        ]}
      />
      <div>
        <h1 className="text-2xl font-bold">Code signing</h1>
        <p className="text-muted-foreground">
          Sign SBOM and SARIF artifacts so downstream consumers can verify
          provenance. Keyless mode uses sigstore cosign via Fulcio + Rekor; key
          mode uses a stored RSA private key.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Signing</CardTitle>
          <CardDescription>
            When enabled, every scan&apos;s SBOM artifacts are signed and the
            signature bundle is uploaded as a SIGNATURE artifact.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <Label htmlFor="sign-enabled">Sign artifacts</Label>
            <Switch
              id="sign-enabled"
              checked={enabled}
              onCheckedChange={setEnabled}
            />
          </div>
          <div className="space-y-1">
            <Label>Mode</Label>
            <Select
              value={mode}
              onValueChange={(v) => setMode(v as "keyless" | "key")}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="keyless">Keyless (cosign + sigstore)</SelectItem>
                <SelectItem value="key">Key-based (RSA PEM)</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label>Identity (OIDC subject for keyless, free-text label for key)</Label>
            <Input
              value={identity}
              onChange={(e) => setIdentity(e.target.value)}
              placeholder="ci@pepper.local"
            />
          </div>
          {mode === "key" && (
            <div className="space-y-1">
              <Label>
                Private key (PEM) {hasKey && (
                  <span className="text-xs text-muted-foreground">(stored)</span>
                )}
              </Label>
              <Textarea
                rows={6}
                value={pem}
                onChange={(e) => setPem(e.target.value)}
                placeholder={hasKey ? "•••••• stored" : "-----BEGIN PRIVATE KEY-----\n..."}
              />
            </div>
          )}
          <Button disabled={saving} onClick={() => void save()}>
            {saving ? "Saving…" : "Save"}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
