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
import { Copy } from "lucide-react";
import Link from "next/link";
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

export default function IdeIntegrationPage() {
  const [baseUrl] = useState(() =>
    typeof window !== "undefined" ? window.location.origin : "",
  );
  const example = `GET ${baseUrl}/api/ide/findings?projectId=<PROJECT_ID>&filePath=src/foo.ts
Authorization: Bearer ppr_xxxx...`;

  return (
    <div className="max-w-2xl space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Settings", href: "/settings/integrations" },
          { label: "IDE plugins" },
        ]}
      />
      <div>
        <h1 className="text-2xl font-bold">IDE plugin endpoint</h1>
        <p className="text-muted-foreground">
          Authenticated REST surface for editor extensions to fetch latest
          findings for the file you have open.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Endpoint</CardTitle>
          <CardDescription>
            Issue an{" "}
            <Link href="/settings/apikeys" className="underline">
              API key
            </Link>{" "}
            and call:
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs">
            {example}
          </pre>
          <Button
            variant="outline"
            onClick={() => {
              navigator.clipboard.writeText(example);
              toast.success("Copied");
            }}
          >
            <Copy className="mr-2 h-4 w-4" />
            Copy example
          </Button>
          <p className="text-muted-foreground">
            Returns the latest completed scan plus the findings touching the
            specified <code>filePath</code> (omit to get all findings). Filter
            by <code>minSeverity=HIGH</code> to suppress noise.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
