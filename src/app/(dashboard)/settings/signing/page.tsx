"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useSession } from "next-auth/react";
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
import { Badge } from "@/components/ui/badge";
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  Download,
  KeyRound,
  Loader2,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

type Mode = "keyless" | "key";

interface SigningState {
  enabled: boolean;
  mode: Mode;
  identity: string;
  hasKey: boolean;
  keyValid: boolean;
  key: { type: string; bits: number; fingerprint: string; publicKeyPem: string } | null;
  keyless: { available: boolean; reason?: string };
  lastSigned: { scanId: string; at: string } | null;
  lastFailure: { scanId: string | null; at: string; reason?: string } | null;
}

async function apiError(res: Response, fallback: string): Promise<string> {
  if (res.status === 403) return "You need the Security or Admin role to change signing";
  const body = (await res.json().catch(() => null)) as { error?: string } | null;
  return body?.error || fallback;
}

const MODES: Array<{ id: Mode; title: string; description: string }> = [
  {
    id: "key",
    title: "Key-based",
    description: "Sign with your organization's RSA or EC private key. Works anywhere.",
  },
  {
    id: "keyless",
    title: "Keyless (Sigstore)",
    description:
      "cosign with a short-lived Fulcio certificate, logged in Rekor. Needs cosign and SIGSTORE_ID_TOKEN on the worker.",
  },
];

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString();
}

function CodeBlock({ children }: { children: string }) {
  return (
    <div className="group relative">
      <pre className="overflow-x-auto rounded-md bg-muted p-3 pr-10 text-xs leading-relaxed">
        {children}
      </pre>
      <button
        type="button"
        className="absolute right-2 top-2 rounded p-1 text-muted-foreground hover:bg-background hover:text-foreground"
        aria-label="Copy command"
        onClick={() => {
          void navigator.clipboard.writeText(children);
          toast.success("Copied");
        }}
      >
        <Copy className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}

export default function SigningSettingsPage() {
  const { data: session } = useSession();
  const orgRole = session?.user?.memberships?.[0]?.role;
  // The API requires SECURITY or above; don't offer controls that will 403.
  const canEdit = orgRole === "ADMIN" || orgRole === "SECURITY";

  const [state, setState] = useState<SigningState | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [mode, setMode] = useState<Mode>("key");
  const [identity, setIdentity] = useState("");
  const [pem, setPem] = useState("");
  const [saving, setSaving] = useState(false);

  async function load() {
    setLoadError(null);
    try {
      const res = await fetch("/api/settings/signing");
      if (!res.ok) {
        setLoadError(await apiError(res, "Couldn't load signing settings"));
        return;
      }
      const j = (await res.json()) as SigningState;
      setState(j);
      setEnabled(j.enabled);
      setMode(j.mode);
      setIdentity(j.identity);
    } catch {
      setLoadError("Couldn't load signing settings");
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function put(privateKeyPem: string | null | undefined, successMessage: string) {
    setSaving(true);
    try {
      const res = await fetch("/api/settings/signing", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enabled,
          mode,
          identity,
          ...(privateKeyPem !== undefined ? { privateKeyPem } : {}),
        }),
      });
      if (!res.ok) {
        toast.error(await apiError(res, "Save failed"));
        return;
      }
      toast.success(successMessage);
      setPem("");
      await load();
    } finally {
      setSaving(false);
    }
  }

  function removeKey() {
    if (!confirm("Remove the stored signing key? Key-based signing will be turned off.")) return;
    if (mode === "key") setEnabled(false);
    // Send with signing off when in key mode, since key mode needs a key.
    setSaving(true);
    void fetch("/api/settings/signing", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        enabled: mode === "key" ? false : enabled,
        mode,
        identity,
        privateKeyPem: null,
      }),
    })
      .then(async (res) => {
        if (!res.ok) toast.error(await apiError(res, "Couldn't remove the key"));
        else toast.success("Signing key removed");
        await load();
      })
      .finally(() => setSaving(false));
  }

  function downloadPublicKey() {
    if (!state?.key) return;
    const blob = new Blob([state.key.publicKeyPem], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "pepper-signing.pub";
    a.click();
    URL.revokeObjectURL(url);
  }

  if (loadError) {
    return (
      <div className="max-w-2xl space-y-4">
        <h1 className="text-2xl font-bold">Code signing</h1>
        <div className="flex items-center justify-between rounded-md border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300">
          <span>{loadError}</span>
          <Button size="sm" variant="outline" onClick={() => void load()}>
            Retry
          </Button>
        </div>
      </div>
    );
  }

  if (!state) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" /> Loading signing settings…
      </div>
    );
  }

  const keyReady = state.hasKey && state.keyValid;
  const willHaveKey = keyReady || pem.trim().length > 0;
  const saveBlocked = enabled && mode === "key" && !willHaveKey;
  const isActive = state.enabled && (state.mode === "key" ? keyReady : state.keyless.available);

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
          Sign every scan&apos;s SBOMs (CycloneDX, SPDX) and VEX statements, so customers and
          auditors can prove a report came from you and hasn&apos;t been edited.
        </p>
      </div>

      {/* Current status, so "saved" is never mistaken for "working". */}
      <Card>
        <CardContent className="space-y-2 pt-6 text-sm">
          <div className="flex items-center gap-2">
            {isActive ? (
              <CheckCircle2 className="h-4 w-4 text-emerald-600" />
            ) : (
              <AlertTriangle className="h-4 w-4 text-amber-600" />
            )}
            <span className="font-medium">
              {!state.enabled
                ? "Signing is off"
                : isActive
                  ? `Signing is on (${state.mode === "key" ? "key-based" : "keyless"})`
                  : state.mode === "key"
                    ? "Signing is on but no usable key is stored"
                    : `Signing is on but keyless may not work: ${state.keyless.reason}`}
            </span>
          </div>
          {state.lastSigned && (
            <p className="text-muted-foreground">
              Last signed:{" "}
              <Link className="underline" href={`/scans/${state.lastSigned.scanId}`}>
                scan on {formatDate(state.lastSigned.at)}
              </Link>
            </p>
          )}
          {state.lastFailure && (
            <p className="text-red-600 dark:text-red-400">
              Signing failed{" "}
              {state.lastFailure.scanId ? (
                <Link className="underline" href={`/scans/${state.lastFailure.scanId}`}>
                  on {formatDate(state.lastFailure.at)}
                </Link>
              ) : (
                `on ${formatDate(state.lastFailure.at)}`
              )}
              {state.lastFailure.reason ? `: ${state.lastFailure.reason}` : ""}
            </p>
          )}
          <p className="text-xs text-muted-foreground">
            Signing runs on scans that produce an SBOM (projects with dependency manifests).
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Settings</CardTitle>
          <CardDescription>
            Signatures are stored as each scan&apos;s signature file, next to its SBOMs.
            {!canEdit && session ? " Only Security and Admin roles can change these settings." : ""}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="flex items-center justify-between">
            <Label htmlFor="sign-enabled">Sign artifacts</Label>
            <Switch
              id="sign-enabled"
              checked={enabled}
              onCheckedChange={setEnabled}
              disabled={!canEdit}
            />
          </div>

          <fieldset className="space-y-2" disabled={!canEdit}>
            <legend className="mb-1 text-sm font-medium">Mode</legend>
            <div className="grid gap-2 sm:grid-cols-2">
              {MODES.map((m) => (
                <label
                  key={m.id}
                  className={`cursor-pointer rounded-md border p-3 text-sm transition-colors ${
                    mode === m.id
                      ? "border-indigo-500 bg-indigo-50/60 dark:bg-indigo-950/30"
                      : "hover:bg-muted/50"
                  }`}
                >
                  <input
                    type="radio"
                    name="mode"
                    value={m.id}
                    checked={mode === m.id}
                    onChange={() => setMode(m.id)}
                    className="sr-only"
                  />
                  <span className="flex items-center gap-2 font-medium">
                    {m.title}
                    {m.id === "keyless" && !state.keyless.available && (
                      <Badge variant="outline" className="text-[10px]">
                        not detected
                      </Badge>
                    )}
                  </span>
                  <span className="mt-1 block text-xs text-muted-foreground">{m.description}</span>
                </label>
              ))}
            </div>
          </fieldset>

          <div className="space-y-1">
            <Label htmlFor="sign-identity">
              {mode === "keyless" ? "Expected OIDC identity" : "Signer label"}
            </Label>
            <Input
              id="sign-identity"
              value={identity}
              maxLength={256}
              disabled={!canEdit}
              onChange={(e) => setIdentity(e.target.value)}
              placeholder={mode === "keyless" ? "ci@your-company.com" : "Acme Security"}
            />
            <p className="text-xs text-muted-foreground">
              {mode === "keyless"
                ? "The certificate identity verifiers should check with --certificate-identity."
                : "Recorded in each signature so readers know who signed."}
            </p>
          </div>

          {mode === "key" && (
            <div className="space-y-2">
              <Label htmlFor="sign-key">
                {keyReady ? "Replace private key" : "Private key (PEM)"}
              </Label>
              <Textarea
                id="sign-key"
                rows={5}
                value={pem}
                disabled={!canEdit}
                onChange={(e) => setPem(e.target.value)}
                className="font-mono text-xs"
                placeholder={"-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----"}
              />
              <p className="text-xs text-muted-foreground">
                RSA (2048 bits or more) or EC P-256/384/521, unencrypted. Stored encrypted and never
                shown again. Generate one with{" "}
                <code className="rounded bg-muted px-1">
                  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out pepper.key
                </code>
              </p>
              {state.hasKey && !state.keyValid && (
                <p className="text-xs text-red-600">
                  The stored key can&apos;t be read (it may have been encrypted with an old secret).
                  Upload a new key.
                </p>
              )}
            </div>
          )}

          <div className="flex items-center gap-3">
            <Button
              disabled={saving || !canEdit || saveBlocked}
              onClick={() => void put(pem.trim() ? pem : undefined, "Signing settings saved")}
            >
              {saving ? "Saving…" : "Save"}
            </Button>
            {saveBlocked && (
              <span className="text-xs text-muted-foreground">
                Add a private key to turn on key-based signing.
              </span>
            )}
          </div>
        </CardContent>
      </Card>

      {state.hasKey && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="h-4 w-4" /> Signing key
            </CardTitle>
            <CardDescription>
              Share the public key with anyone who needs to verify your reports.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            {state.key ? (
              <>
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
                  <dt className="text-muted-foreground">Type</dt>
                  <dd>
                    {state.key.type} {state.key.bits}-bit
                  </dd>
                  <dt className="text-muted-foreground">Fingerprint</dt>
                  <dd className="break-all font-mono text-xs">{state.key.fingerprint}</dd>
                </dl>
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" variant="outline" onClick={downloadPublicKey}>
                    <Download className="mr-1.5 h-3.5 w-3.5" /> Download public key
                  </Button>
                  {canEdit && (
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-red-600 hover:text-red-700"
                      disabled={saving}
                      onClick={removeKey}
                    >
                      <Trash2 className="mr-1.5 h-3.5 w-3.5" /> Remove key
                    </Button>
                  )}
                </div>
              </>
            ) : (
              <div className="flex items-center justify-between">
                <span className="text-red-600">The stored key is unreadable.</span>
                {canEdit && (
                  <Button size="sm" variant="outline" disabled={saving} onClick={removeKey}>
                    <Trash2 className="mr-1.5 h-3.5 w-3.5" /> Remove key
                  </Button>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>How to verify a report</CardTitle>
          <CardDescription>
            Download the SBOM and the signature file from a scan&apos;s Export menu, then run:
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          {state.mode === "keyless" ? (
            <CodeBlock>{`jq '.cyclonedx.cosignBundle' signature.json > sbom.bundle
cosign verify-blob sbom.cyclonedx.json \\
  --bundle sbom.bundle \\
  --certificate-identity ${identity || "<identity>"} \\
  --certificate-oidc-issuer <issuer>`}</CodeBlock>
          ) : (
            <CodeBlock>{`jq -r '.cyclonedx.signature' signature.json | base64 -d > sbom.sig
openssl dgst -sha256 -verify pepper-signing.pub \\
  -signature sbom.sig sbom.cyclonedx.json`}</CodeBlock>
          )}
          <p className="text-xs text-muted-foreground">
            Use <code>.spdx</code>, <code>.openvex</code> or <code>.cyclonedx-vex</code> for the
            other files. A scan&apos;s Export menu also has <em>Verify signatures</em>, which
            re-checks the stored files against your current key.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
