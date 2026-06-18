"use client";

import React, { useState } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Copy, Zap } from "lucide-react";
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

export default function PrecommitInstallPage() {
  const [mounted, setMounted] = useState(false);
  const [baseUrl, setBaseUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [apiKey, setApiKey] = useState<string | null>(null);

  React.useEffect(() => {
    setBaseUrl(typeof window !== "undefined" ? window.location.origin : "");
    setMounted(true);
  }, []);

  const installCommand = apiKey
    ? `curl -fsSL ${baseUrl}/api/precommit/install.sh | bash -s -- ${baseUrl} ${apiKey}`
    : null;

  async function generateAndInstall() {
    setLoading(true);
    try {
      const res = await fetch("/api/apikeys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: "precommit-hook" }),
      });
      if (!res.ok) {
        const text = await res.text();
        let errorMsg = "Failed to create API key";
        try {
          const data = JSON.parse(text) as { error?: string };
          errorMsg = data.error || `Status ${res.status}`;
        } catch {
          errorMsg = `Status ${res.status}: ${text.slice(0, 100)}`;
        }
        console.error("API key creation failed:", { status: res.status, text });
        toast.error(errorMsg);
        return;
      }
      const data = (await res.json()) as { plaintext: string };
      setApiKey(data.plaintext);
      toast.success("API key created! Copy the command below.");
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Network error";
      console.error("API key creation error:", err);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  }

  function copy(s: string) {
    navigator.clipboard.writeText(s);
    toast.success("Copied to clipboard");
  }

  return (
    <div className="max-w-2xl space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Settings", href: "/settings/integrations" },
          { label: "Pre-commit hook" },
        ]}
      />
      <div>
        <h1 className="text-2xl font-bold">Pre-commit hook</h1>
        <p className="text-muted-foreground">
          Block commits that contain secrets or HIGH/CRITICAL SAST findings.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>One-Click Setup</CardTitle>
          <CardDescription>
            Generate API key and installation script automatically.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {!installCommand ? (
            <Button
              onClick={() => void generateAndInstall()}
              disabled={loading}
              size="lg"
              className="w-full"
            >
              <Zap className="mr-2 h-5 w-5" />
              {loading ? "Creating API key..." : "Generate Install Script"}
            </Button>
          ) : (
            <>
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">Install Command</span>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => copy(installCommand)}
                  >
                    <Copy className="mr-2 h-4 w-4" /> Copy
                  </Button>
                </div>
                <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs font-mono">
                  {installCommand}
                </pre>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setApiKey(null)}
              >
                Generate New Key
              </Button>
            </>
          )}

          <div className="space-y-2 border-t pt-4">
            <span className="text-sm font-medium">How it works</span>
            <ul className="list-disc pl-5 space-y-1 text-xs text-muted-foreground">
              <li>Click the button to auto-generate an API key</li>
              <li>Copy the command and run it in your git repository root</li>
              <li>
                On <code>git commit</code>, staged files are checked for secrets
                and SAST issues
              </li>
              <li>
                Commit is blocked if any <Badge variant="outline">CRITICAL</Badge>{" "}
                or <Badge variant="outline">HIGH</Badge> severity issue is found
              </li>
              <li>
                Override with <code>PEPPER_FAIL_ON=CRITICAL</code> env var
              </li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
