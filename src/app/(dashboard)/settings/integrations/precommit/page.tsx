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
import { Copy } from "lucide-react";
import { toast } from "sonner";
import Link from "next/link";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

export default function PrecommitInstallPage() {
  const [baseUrl] = useState(() =>
    typeof window !== "undefined" ? window.location.origin : "",
  );

  const oneliner = `curl -fsSL ${baseUrl}/api/precommit/install.sh | bash -s -- ${baseUrl} <YOUR_API_KEY>`;
  const manual = `# Save the hook
curl -fsSL ${baseUrl}/api/precommit/install.sh > pepper-install.sh
bash pepper-install.sh ${baseUrl} ppr_xxxx...`;

  function copy(s: string) {
    navigator.clipboard.writeText(s);
    toast.success("Copied");
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
          <CardTitle>Install</CardTitle>
          <CardDescription>
            Run this inside any git repository you want to protect. Issue an{" "}
            <Link href="/settings/apikeys" className="underline">
              API key
            </Link>{" "}
            first.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-medium">One-liner</span>
              <Button variant="ghost" size="sm" onClick={() => copy(oneliner)}>
                <Copy className="mr-2 h-4 w-4" /> Copy
              </Button>
            </div>
            <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs">
              {oneliner}
            </pre>
          </div>
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-medium">Manual</span>
              <Button variant="ghost" size="sm" onClick={() => copy(manual)}>
                <Copy className="mr-2 h-4 w-4" /> Copy
              </Button>
            </div>
            <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs">
              {manual}
            </pre>
          </div>
          <div className="space-y-1">
            <span className="font-medium">How it works</span>
            <ul className="list-disc pl-5 text-muted-foreground">
              <li>
                On <code>git commit</code>, staged files are POSTed to{" "}
                <code>/api/precommit/scan</code>.
              </li>
              <li>Pepper runs secret + SAST pattern checks in memory.</li>
              <li>
                Commit is blocked if any <Badge variant="outline">CRITICAL</Badge>{" "}
                or <Badge variant="outline">HIGH</Badge> issue is reported.
              </li>
              <li>
                Override severity gate with <code>PEPPER_FAIL_ON</code> env var,
                e.g. <code>PEPPER_FAIL_ON=CRITICAL</code>.
              </li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
