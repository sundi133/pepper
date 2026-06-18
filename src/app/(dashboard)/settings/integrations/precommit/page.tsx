"use client";

import { useState } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Copy } from "lucide-react";
import { toast } from "sonner";
import Link from "next/link";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

export default function PrecommitInstallPage() {
  const [baseUrl] = useState(() =>
    typeof window !== "undefined" ? window.location.origin : "",
  );
  const [apiKey, setApiKey] = useState("");

  const installCommand = apiKey
    ? `curl -fsSL ${baseUrl}/api/precommit/install.sh | bash -s -- ${baseUrl} ${apiKey}`
    : `curl -fsSL ${baseUrl}/api/precommit/install.sh | bash -s -- ${baseUrl} <YOUR_API_KEY>`;

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
          <CardTitle>Quick Install</CardTitle>
          <CardDescription>
            Enter your API key to generate the install command.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="apikey" className="text-sm font-medium">
              API Key{" "}
              <Link
                href="/settings/apikeys"
                className="text-xs text-blue-600 hover:underline"
              >
                (create one)
              </Link>
            </label>
            <Input
              id="apikey"
              placeholder="ppr_xxxxxxxxxxxx"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="font-mono text-xs"
            />
          </div>

          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Install Command</span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => copy(installCommand)}
                disabled={!apiKey}
              >
                <Copy className="mr-2 h-4 w-4" /> Copy
              </Button>
            </div>
            <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs">
              {installCommand}
            </pre>
          </div>

          <div className="space-y-2 border-t pt-4">
            <span className="text-sm font-medium">How it works</span>
            <ul className="list-disc pl-5 space-y-1 text-xs text-muted-foreground">
              <li>
                Copy the command above and run it in your git repository root
              </li>
              <li>
                On <code>git commit</code>, staged files are POSTed to{" "}
                <code>/api/precommit/scan</code>
              </li>
              <li>Pepper runs secret + SAST pattern checks in memory</li>
              <li>
                Commit is blocked if any <Badge variant="outline">CRITICAL</Badge>{" "}
                or <Badge variant="outline">HIGH</Badge> issue is found
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
