"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { ExternalLink } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";

interface Installation {
  id: string;
  installationId: string;
  accountLogin: string;
  accountType: string;
  repositorySelection: string;
  suspended: boolean;
  configureUrl: string;
}

/**
 * GitHub App installations (docs/GITHUB_APP_SPEC.md §9). Renders nothing when
 * the App isn't configured on this server, so the page is unchanged then.
 */
export function GithubAppSection({ onLoaded }: { onLoaded?: (configured: boolean, installations: number) => void }) {
  const [state, setState] = useState<{ configured: boolean; installations: Installation[] } | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  /** Organization policy: personal (OAuth) GitHub connections allowed. */
  const [allowPersonal, setAllowPersonal] = useState<boolean | null>(null);
  const [savingPolicy, setSavingPolicy] = useState(false);
  // The latest callback, without making `load` (and the effect) change each render.
  const onLoadedRef = useRef(onLoaded);
  useEffect(() => {
    onLoadedRef.current = onLoaded;
  }, [onLoaded]);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/integrations/github/app");
      if (!res.ok) return;
      const data = (await res.json()) as { configured: boolean; installations: Installation[] };
      setState(data);
      onLoadedRef.current?.(data.configured, data.installations.length);
      if (data.configured) {
        const policy = await fetch("/api/integrations/github");
        if (policy.ok) setAllowPersonal(((await policy.json()) as { allowPersonalGithub?: boolean }).allowPersonalGithub ?? true);
      }
    } catch {
      // the OAuth section still works
    }
  }, []);

  useEffect(() => {
    void load();
    const params = new URLSearchParams(window.location.search);
    const status = params.get("githubApp");
    if (status === "installed") toast.success("GitHub App connected");
    if (status === "error") toast.error(params.get("message") || "The GitHub App could not be connected");
  }, [load]);

  async function remove(inst: Installation) {
    if (!confirm(`Unlink the GitHub App installation on ${inst.accountLogin}? It stays installed on GitHub; uninstall it there to revoke its access.`)) return;
    setRemoving(inst.installationId);
    try {
      const res = await fetch(`/api/integrations/github/app/${inst.installationId}`, { method: "DELETE" });
      if (!res.ok) throw new Error(((await res.json()) as { error?: string }).error || "Failed to unlink");
      toast.success(`Unlinked ${inst.accountLogin}`);
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to unlink");
    } finally {
      setRemoving(null);
    }
  }

  async function setPolicy(allow: boolean) {
    if (!allow && !state?.installations.length) {
      toast.error("Install the GitHub App first: with personal connections off, Pepper reaches GitHub only through the App.");
      return;
    }
    setSavingPolicy(true);
    try {
      const res = await fetch("/api/integrations/github", {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ allowPersonalGithub: allow }),
      });
      if (!res.ok) throw new Error(((await res.json()) as { error?: string }).error || "Failed to save");
      setAllowPersonal(allow);
      toast.success(allow ? "Personal GitHub connections allowed" : "GitHub App only: personal connections are off");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to save");
    } finally {
      setSavingPolicy(false);
    }
  }

  if (!state?.configured) return null;

  return (
    <div className="space-y-3 rounded-md border border-primary/20 bg-primary/5 p-4">
      <div className="flex items-center gap-2">
        <p className="font-medium">GitHub App</p>
        <Badge variant="secondary">Recommended</Badge>
      </div>
      <p className="text-sm text-muted-foreground">
        Pepper acts as its own GitHub App on the organizations and repositories you choose, with
        fine-grained permissions and tokens that expire after an hour. Scans, PR comments and fix
        pull requests keep working when people leave.
      </p>
      {state.installations.length === 0 ? (
        <p className="text-sm text-muted-foreground">Not installed yet.</p>
      ) : (
        <ul className="space-y-2">
          {state.installations.map((i) => (
            <li key={i.id} className="flex flex-wrap items-center justify-between gap-2 rounded border bg-background px-3 py-2 text-sm">
              <span>
                <strong>{i.accountLogin}</strong>{" "}
                <span className="text-muted-foreground">
                  · {i.accountType === "Organization" ? "organization" : "user"} ·{" "}
                  {i.repositorySelection === "all" ? "all repositories" : "selected repositories"}
                </span>
                {i.suspended && (
                  <Badge variant="destructive" className="ml-2">
                    Suspended
                  </Badge>
                )}
              </span>
              <span className="flex gap-2">
                <Button variant="outline" size="sm" asChild>
                  <a href={i.configureUrl} target="_blank" rel="noopener noreferrer">
                    <ExternalLink className="mr-1 h-3 w-3" />
                    Configure on GitHub
                  </a>
                </Button>
                <Button variant="ghost" size="sm" disabled={removing === i.installationId} onClick={() => void remove(i)}>
                  {removing === i.installationId ? "Unlinking…" : "Unlink"}
                </Button>
              </span>
            </li>
          ))}
        </ul>
      )}
      {allowPersonal !== null && (
        <label className="flex items-start gap-3 rounded border bg-background px-3 py-2 text-sm">
          <Switch checked={allowPersonal} disabled={savingPolicy} onCheckedChange={(v) => void setPolicy(v)} />
          <span>
            <span className="font-medium">Allow personal GitHub connections</span>
            <span className="block text-muted-foreground">
              Off: Pepper uses only the GitHub App; &quot;Connect GitHub&quot; and pasted tokens for App-covered repositories are refused.
            </span>
          </span>
        </label>
      )}
      <Button asChild>
        <Link href="/api/integrations/github/app/install" prefetch={false}>
          {state.installations.length ? "Install on another organization" : "Install GitHub App"}
        </Link>
      </Button>
    </div>
  );
}
