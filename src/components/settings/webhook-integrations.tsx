"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Copy, Eye, EyeOff, KeyRound, AlertCircle } from "lucide-react";
import { toast } from "sonner";

interface WebhookConfig {
  name: string;
  icon: React.ReactNode;
  url: string;
  secretKey: string;
  secretLabel: string;
  description: string;
  triggers: string;
}

function randomSecret(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function WebhookIntegrations() {
  const [webhookUrl, setWebhookUrl] = useState("");
  const [mounted, setMounted] = useState(false);

  // GitHub
  const [githubSecret, setGithubSecret] = useState("");
  const [githubShow, setGithubShow] = useState(false);

  // GitLab
  const [gitlabSecret, setGitlabSecret] = useState("");
  const [gitlabShow, setGitlabShow] = useState(false);

  // Bitbucket
  const [bitbucketSecret, setBitbucketSecret] = useState("");
  const [bitbucketShow, setBitbucketShow] = useState(false);

  // Azure
  const [azureSecret, setAzureSecret] = useState("");
  const [azureShow, setAzureShow] = useState(false);

  useEffect(() => {
    setWebhookUrl(
      typeof window !== "undefined"
        ? `${window.location.origin}/api/webhooks`
        : ""
    );
    setMounted(true);
  }, []);

  function copyUrl(url: string) {
    navigator.clipboard.writeText(url);
    toast.success("Copied to clipboard");
  }

  if (!mounted) return null;

  const webhooks: WebhookConfig[] = [
    {
      name: "GitHub",
      icon: (
        <svg className="h-8 w-8" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v 3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
        </svg>
      ),
      url: `${webhookUrl}/github`,
      secretKey: "github",
      secretLabel: "GitHub webhook secret",
      description: "Scan pull requests and pushes on GitHub",
      triggers: "Pull requests, Pushes",
    },
    {
      name: "GitLab",
      icon: (
        <svg className="h-8 w-8" viewBox="0 0 24 24" fill="#FC6D26">
          <path d="M23.6 9.3l-1.3-4c-.2-.6-.8-1-1.5-1h-20c-.7 0-1.3.4-1.5 1l-1.3 4c-.2.6 0 1.3.4 1.8l9.3 7.7c.6.5 1.5.5 2.1 0l9.3-7.7c.4-.5.6-1.2.4-1.8z"/>
        </svg>
      ),
      url: `${webhookUrl}/gitlab`,
      secretKey: "gitlab",
      secretLabel: "GitLab webhook secret token",
      description: "Scan merge requests and pushes on GitLab",
      triggers: "Merge requests, Pushes",
    },
    {
      name: "Bitbucket Cloud",
      icon: (
        <svg className="h-8 w-8" viewBox="0 0 24 24" fill="#0052CC">
          <path d="M2 2h8v8H2V2zm12 0h8v8h-8V2zM2 14h8v8H2v-8zm12 0h8v8h-8v-8z"/>
        </svg>
      ),
      url: `${webhookUrl}/bitbucket`,
      secretKey: "bitbucket",
      secretLabel: "Bitbucket webhook secret",
      description: "Scan pull requests and pushes on Bitbucket",
      triggers: "Pull requests, Pushes",
    },
    {
      name: "Azure DevOps",
      icon: (
        <svg className="h-8 w-8" viewBox="0 0 24 24" fill="#0078D4">
          <path d="M2 2h8v8H2V2zm12 0h8v8h-8V2zM2 14h8v8H2v-8zm12 0h8v8h-8v-8z"/>
        </svg>
      ),
      url: `${webhookUrl}/azure-devops`,
      secretKey: "azure",
      secretLabel: "Azure DevOps basic auth password",
      description: "Scan pull requests and pushes on Azure DevOps",
      triggers: "Code pushed, PR events",
    },
  ];

  const getSecretValue = (key: string) => {
    switch (key) {
      case "github":
        return githubSecret;
      case "gitlab":
        return gitlabSecret;
      case "bitbucket":
        return bitbucketSecret;
      case "azure":
        return azureSecret;
      default:
        return "";
    }
  };

  const setSecretValue = (key: string, value: string) => {
    switch (key) {
      case "github":
        setGithubSecret(value);
        break;
      case "gitlab":
        setGitlabSecret(value);
        break;
      case "bitbucket":
        setBitbucketSecret(value);
        break;
      case "azure":
        setAzureSecret(value);
        break;
    }
  };

  const getShowValue = (key: string) => {
    switch (key) {
      case "github":
        return githubShow;
      case "gitlab":
        return gitlabShow;
      case "bitbucket":
        return bitbucketShow;
      case "azure":
        return azureShow;
      default:
        return false;
    }
  };

  const setShowValue = (key: string, value: boolean) => {
    switch (key) {
      case "github":
        setGithubShow(value);
        break;
      case "gitlab":
        setGitlabShow(value);
        break;
      case "bitbucket":
        setBitbucketShow(value);
        break;
      case "azure":
        setAzureShow(value);
        break;
    }
  };

  return (
    <div className="space-y-8 border-t border-gray-200 pt-8">
      {/* Header */}
      <div>
        <h2 className="text-3xl font-bold text-gray-900">Webhook Setup</h2>
        <p className="text-gray-600 mt-2">
          Configure webhooks for incremental scanning on pull requests and pushes.
        </p>
      </div>

      {/* Webhook Secrets Info Card */}
      <div className="rounded-lg border border-gray-200 bg-white overflow-hidden">
        <div className="border-b border-gray-200 px-6 py-5 bg-gray-50">
          <div className="flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-gray-700" />
            <h3 className="text-lg font-semibold text-gray-900">Webhook Secrets</h3>
            <Badge variant="outline">Required for 401-free deliveries</Badge>
          </div>
          <p className="text-sm text-gray-600 mt-3">
            Set the same secret here and in each Git host webhook configuration. Use the eye icon to show/hide while typing, or generate a random secret.
          </p>
        </div>
      </div>

      {/* 4 Grid Layout with Full Details */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {webhooks.map((webhook) => {
          const secretValue = getSecretValue(webhook.secretKey);
          const show = getShowValue(webhook.secretKey);

          return (
            <div
              key={webhook.name}
              className="rounded-lg border border-gray-200 bg-white hover:shadow-md transition-shadow overflow-hidden"
            >
              {/* Card Header */}
              <div className="border-b border-gray-200 px-6 py-5 bg-gray-50 flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div className="text-gray-700">{webhook.icon}</div>
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900">{webhook.name}</h3>
                    <p className="text-sm text-gray-600 mt-1">{webhook.description}</p>
                  </div>
                </div>
                <Badge variant="outline" className="text-xs">
                  {webhook.triggers}
                </Badge>
              </div>

              {/* Card Content */}
              <div className="px-6 py-5 space-y-4">
                {/* Setup Instructions */}
                <div className="space-y-3 pb-4 border-b">
                  <h4 className="font-semibold text-sm text-gray-900">Setup Steps:</h4>
                  <div className="text-xs text-gray-600 space-y-2">
                    {webhook.secretKey === "github" && (
                      <>
                        <p>1. Go to repo Settings → Webhooks → Add webhook</p>
                        <p>2. Paste the Webhook URL below</p>
                        <p>3. Set Content type to <code className="bg-gray-100 px-1 rounded">application/json</code></p>
                        <p>4. Add Secret from below</p>
                        <p>5. Enable Pull requests and Pushes events</p>
                        <p>6. Click Add webhook</p>
                      </>
                    )}
                    {webhook.secretKey === "gitlab" && (
                      <>
                        <p>1. Go to project Settings → Webhooks</p>
                        <p>2. Paste the Webhook URL below</p>
                        <p>3. Check Merge requests events and Push events</p>
                        <p>4. Add Secret token from below</p>
                        <p>5. Click Add webhook</p>
                      </>
                    )}
                    {webhook.secretKey === "bitbucket" && (
                      <>
                        <p>1. Open repo → Repository settings → Webhooks</p>
                        <p>2. Click Add webhook</p>
                        <p>3. Paste the Webhook URL below</p>
                        <p>4. Under Triggers, enable Push, PR created/updated</p>
                        <p>5. Add Secret from below</p>
                        <p>6. Click Save</p>
                      </>
                    )}
                    {webhook.secretKey === "azure" && (
                      <>
                        <p>1. Go to Project settings → Service hooks</p>
                        <p>2. Click Create subscription → Web Hooks</p>
                        <p>3. Select Code pushed and PR created/updated</p>
                        <p>4. Paste the Webhook URL below</p>
                        <p>5. Add Secret from below as password</p>
                        <p>6. Click Save</p>
                      </>
                    )}
                  </div>
                </div>

                {/* Webhook URL */}
                <div className="space-y-2">
                  <Label className="text-sm font-semibold text-gray-900">
                    Webhook URL
                  </Label>
                  <div className="flex gap-2">
                    <Input
                      value={webhook.url}
                      readOnly
                      className="text-xs font-mono bg-gray-50"
                    />
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={() => copyUrl(webhook.url)}
                      title="Copy webhook URL"
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                </div>

                {/* Secret Input */}
                <div className="space-y-2 pt-2">
                  <Label htmlFor={`secret-${webhook.secretKey}`} className="text-sm font-semibold text-gray-900">
                    {webhook.secretLabel}
                  </Label>
                  <div className="flex gap-2">
                    <div className="relative flex-1">
                      <Input
                        id={`secret-${webhook.secretKey}`}
                        type={show ? "text" : "password"}
                        value={secretValue}
                        onChange={(e) => setSecretValue(webhook.secretKey, e.target.value)}
                        placeholder="Generate or paste a secret"
                        autoComplete="new-password"
                        className="pr-10 text-xs"
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
                        onClick={() => setShowValue(webhook.secretKey, !show)}
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
                      size="sm"
                      onClick={() => setSecretValue(webhook.secretKey, randomSecret())}
                    >
                      Generate
                    </Button>
                  </div>

                  {/* Copy & Save Buttons */}
                  <div className="flex gap-2 pt-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="flex-1 text-xs"
                      onClick={() => copyUrl(secretValue)}
                      disabled={!secretValue}
                    >
                      <Copy className="h-3 w-3 mr-1" />
                      Copy Secret
                    </Button>
                    <Button
                      type="button"
                      className="flex-1 bg-blue-600 hover:bg-blue-700 text-white text-xs"
                      size="sm"
                      disabled={!secretValue}
                      onClick={() => toast.success("Secret configuration ready for webhook setup")}
                    >
                      Save & Use
                    </Button>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Scan Behavior Info */}
      <div className="rounded-lg border border-blue-200 bg-blue-50/50 overflow-hidden">
        <div className="px-6 py-5">
          <h3 className="text-lg font-semibold text-blue-900 flex items-center gap-2">
            <AlertCircle className="h-5 w-5" />
            Scan Behavior
          </h3>
          <div className="mt-4 space-y-2 text-sm text-blue-800">
            <p>
              <strong>Pull Request / Merge Request events</strong> trigger <code className="bg-white px-2 py-1 rounded text-xs border border-blue-300">INCREMENTAL</code> scans (changed files only)
            </p>
            <p>
              <strong>Push to default branch</strong> triggers <code className="bg-white px-2 py-1 rounded text-xs border border-blue-300">SAST_ONLY</code> scans
            </p>
            <p>
              Override with environment variables: <code className="bg-white px-2 py-1 rounded text-xs border border-blue-300 font-mono">GITHUB_WEBHOOK_MAIN_SCAN_TYPE=FULL</code>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
