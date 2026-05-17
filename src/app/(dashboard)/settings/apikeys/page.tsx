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
import { Copy } from "lucide-react";
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

interface Key {
  id: string;
  name: string;
  prefix: string;
  lastUsedAt: string | null;
  createdAt: string;
  expiresAt: string | null;
}

export default function ApiKeysPage() {
  const [keys, setKeys] = useState<Key[]>([]);
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [revealed, setRevealed] = useState<string | null>(null);

  async function reload() {
    const res = await fetch("/api/apikeys");
    if (res.ok) {
      const j = (await res.json()) as { keys: Key[] };
      setKeys(j.keys);
    }
  }

  useEffect(() => {
    void reload();
  }, []);

  async function create() {
    if (!name.trim()) return;
    setCreating(true);
    try {
      const res = await fetch("/api/apikeys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
      });
      if (!res.ok) {
        const j = (await res.json()) as { error?: string };
        toast.error(j.error || "Create failed");
        return;
      }
      const data = (await res.json()) as { plaintext: string; prefix: string };
      setRevealed(data.plaintext);
      setName("");
      void reload();
    } finally {
      setCreating(false);
    }
  }

  async function revoke(id: string) {
    if (!confirm("Revoke this API key? Any clients using it will stop working.")) return;
    const res = await fetch(`/api/apikeys/${id}`, { method: "DELETE" });
    if (res.ok) {
      toast.success("Revoked");
      void reload();
    } else toast.error("Revoke failed");
  }

  return (
    <div className="max-w-2xl space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Settings", href: "/settings/integrations" },
          { label: "API Keys" },
        ]}
      />
      <div>
        <h1 className="text-2xl font-bold">API keys</h1>
        <p className="text-muted-foreground">
          Used by CI/CD pipelines, pre-commit hooks, IDE plugins, and the
          public REST API.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Create new key</CardTitle>
          <CardDescription>
            Tokens are shown once and stored hashed. Treat them like passwords.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-1">
            <Label>Name</Label>
            <Input
              placeholder="github-actions-prod"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <Button disabled={!name.trim() || creating} onClick={() => void create()}>
            {creating ? "Creating…" : "Create key"}
          </Button>
          {revealed && (
            <div className="rounded-md border border-amber-400 bg-amber-50 p-3 text-xs dark:bg-amber-950/30">
              <div className="mb-1 font-medium">Copy this value now — it won&apos;t be shown again.</div>
              <div className="flex items-center gap-2">
                <code className="flex-1 break-all">{revealed}</code>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    navigator.clipboard.writeText(revealed);
                    toast.success("Copied");
                  }}
                >
                  <Copy className="h-3 w-3" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Active keys</CardTitle>
        </CardHeader>
        <CardContent>
          {keys.length === 0 ? (
            <p className="text-sm text-muted-foreground">No keys yet.</p>
          ) : (
            <div className="divide-y text-sm">
              {keys.map((k) => (
                <div key={k.id} className="flex items-center justify-between py-2">
                  <div>
                    <div className="font-medium">{k.name}</div>
                    <div className="text-xs text-muted-foreground">
                      {k.prefix}…  •  created {new Date(k.createdAt).toLocaleDateString()}
                      {k.lastUsedAt
                        ? ` • last used ${new Date(k.lastUsedAt).toLocaleString()}`
                        : " • never used"}
                    </div>
                  </div>
                  <Button size="sm" variant="ghost" onClick={() => void revoke(k.id)}>
                    Revoke
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
