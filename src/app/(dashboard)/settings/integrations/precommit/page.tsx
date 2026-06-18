"use client";

import { useState, useEffect } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Copy, Plus } from "lucide-react";
import { toast } from "sonner";
import Link from "next/link";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  maskedKey: string;
}

export default function PrecommitInstallPage() {
  const [baseUrl] = useState(() =>
    typeof window !== "undefined" ? window.location.origin : "",
  );
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [selectedKeyId, setSelectedKeyId] = useState<string>("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchApiKeys() {
      try {
        const res = await fetch("/api/apikeys");
        const data = await res.json();
        setApiKeys(data.keys || []);
        if (data.keys?.length > 0) {
          setSelectedKeyId(data.keys[0].id);
        }
      } catch (err) {
        toast.error("Failed to load API keys");
      } finally {
        setLoading(false);
      }
    }
    fetchApiKeys();
  }, []);

  const selectedKey = apiKeys.find((k) => k.id === selectedKeyId);
  const installCommand = selectedKey
    ? `curl -fsSL ${baseUrl}/api/precommit/install.sh | bash -s -- ${baseUrl} ${selectedKey.prefix}...`
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
            Select an API key and copy the one-liner to run in any git repository.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {loading ? (
            <div className="text-sm text-muted-foreground">Loading API keys...</div>
          ) : apiKeys.length === 0 ? (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                No API keys found. Create one to get started.
              </p>
              <Link href="/settings/apikeys">
                <Button size="sm">
                  <Plus className="mr-2 h-4 w-4" /> Create API Key
                </Button>
              </Link>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="space-y-2">
                <label className="text-sm font-medium">Select API Key</label>
                <Select value={selectedKeyId} onValueChange={setSelectedKeyId}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {apiKeys.map((key) => (
                      <SelectItem key={key.id} value={key.id}>
                        {key.name} ({key.prefix}...)
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
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
                <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs">
                  {installCommand}
                </pre>
              </div>
            </div>
          )}

          <div className="space-y-2 border-t pt-4">
            <span className="text-sm font-medium">How it works</span>
            <ul className="list-disc pl-5 space-y-1 text-xs text-muted-foreground">
              <li>
                Run the command above in your git repository root directory
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
