"use client";

import { useState, useEffect } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Zap,
  AlertCircle,
  ChevronRight,
  HelpCircle,
  Lock,
  Check,
  MoreVertical,
  MessageSquare,
} from "lucide-react";
import Link from "next/link";
import { toast } from "sonner";

type IntegrationCategory = "all" | "source-control" | "notifications" | "issue-tracking" | "ci-cd" | "developer-tools";

interface Integration {
  id: string;
  name: string;
  category: IntegrationCategory;
  description: string;
  icon: React.ReactNode;
  features: string[];
}

export function IntegrationsDashboard() {
  const [activeCategory, setActiveCategory] = useState<IntegrationCategory>("all");
  const [searchQuery, setSearchQuery] = useState("");

  // ─── GitHub Integration ─────────────────────────────────────────────
  const [githubConn, setGithubConn] = useState<{
    connected: boolean;
    githubLogin: string | null;
    oauthConfigured: boolean;
  } | null>(null);
  const [githubDisconnecting, setGithubDisconnecting] = useState(false);

  // ─── Bitbucket Cloud ────────────────────────────────────────────────
  const [bitbucketConn, setBitbucketConn] = useState<{
    connected: boolean;
    username: string | null;
    workspace: string | null;
  } | null>(null);
  const [bitbucketFormOpen, setBitbucketFormOpen] = useState(false);
  const [bitbucketSubmitting, setBitbucketSubmitting] = useState(false);
  const [bitbucketDisconnecting, setBitbucketDisconnecting] = useState(false);
  const [bitbucketForm, setBitbucketForm] = useState({
    username: "",
    appPassword: "",
    workspace: "",
  });

  // ─── Azure DevOps Services ──────────────────────────────────────────
  const [azureConn, setAzureConn] = useState<{
    connected: boolean;
    azureOrganization: string | null;
    azureUser: string | null;
  } | null>(null);
  const [azureFormOpen, setAzureFormOpen] = useState(false);
  const [azureSubmitting, setAzureSubmitting] = useState(false);
  const [azureDisconnecting, setAzureDisconnecting] = useState(false);
  const [azureForm, setAzureForm] = useState({
    azureOrganization: "",
    pat: "",
  });

  async function refreshAzure() {
    try {
      const res = await fetch("/api/integrations/azure-devops/connect");
      if (!res.ok) return;
      const data = (await res.json()) as {
        connected?: boolean;
        azureOrganization?: string | null;
        azureUser?: string | null;
      };
      setAzureConn({
        connected: Boolean(data.connected),
        azureOrganization: data.azureOrganization ?? null,
        azureUser: data.azureUser ?? null,
      });
    } catch {
      /* ignore */
    }
  }

  async function connectAzure(e: React.FormEvent) {
    e.preventDefault();
    const azureOrganization = azureForm.azureOrganization.trim();
    const pat = azureForm.pat.trim();
    if (!azureOrganization || !pat) {
      toast.error("Organization and PAT are required");
      return;
    }
    setAzureSubmitting(true);
    try {
      const res = await fetch("/api/integrations/azure-devops/connect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ azureOrganization, pat }),
      });
      const data = (await res.json()) as { error?: string };
      if (!res.ok) {
        throw new Error(data.error || "Failed to connect Azure DevOps");
      }
      toast.success("Azure DevOps connected");
      setAzureForm({ azureOrganization: "", pat: "" });
      setAzureFormOpen(false);
      await refreshAzure();
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Failed to connect Azure DevOps",
      );
    } finally {
      setAzureSubmitting(false);
    }
  }

  async function disconnectAzure() {
    if (
      !window.confirm(
        "Disconnect Azure DevOps? Pepper will stop posting PR review threads and status checks to your ADO repositories.",
      )
    ) {
      return;
    }
    setAzureDisconnecting(true);
    try {
      const res = await fetch("/api/integrations/azure-devops/connect", {
        method: "DELETE",
      });
      if (!res.ok) throw new Error("Failed to disconnect");
      toast.success("Azure DevOps disconnected");
      setAzureConn({
        connected: false,
        azureOrganization: null,
        azureUser: null,
      });
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Failed to disconnect Azure DevOps",
      );
    } finally {
      setAzureDisconnecting(false);
    }
  }

  async function refreshBitbucket() {
    try {
      const res = await fetch("/api/integrations/bitbucket/connect");
      if (!res.ok) return;
      const data = (await res.json()) as {
        connected?: boolean;
        username?: string | null;
        workspace?: string | null;
      };
      setBitbucketConn({
        connected: Boolean(data.connected),
        username: data.username ?? null,
        workspace: data.workspace ?? null,
      });
    } catch {
      /* ignore */
    }
  }

  useEffect(() => {
    void (async () => {
      try {
        const res = await fetch("/api/integrations/github");
        if (!res.ok) return;
        const data = (await res.json()) as {
          connected?: boolean;
          githubLogin?: string | null;
          oauthConfigured?: boolean;
        };
        setGithubConn({
          connected: Boolean(data.connected),
          githubLogin: data.githubLogin ?? null,
          oauthConfigured: Boolean(data.oauthConfigured),
        });
      } catch {
        /* ignore */
      }
    })();
    void refreshBitbucket();
    void refreshAzure();
  }, []);

  async function connectBitbucket(e: React.FormEvent) {
    e.preventDefault();
    const username = bitbucketForm.username.trim();
    const appPassword = bitbucketForm.appPassword.trim();
    const workspace = bitbucketForm.workspace.trim();
    if (!username || !appPassword) {
      toast.error("Username and app password are required");
      return;
    }
    setBitbucketSubmitting(true);
    try {
      const res = await fetch("/api/integrations/bitbucket/connect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          appPassword,
          workspace: workspace || undefined,
        }),
      });
      const data = (await res.json()) as { error?: string };
      if (!res.ok) {
        throw new Error(data.error || "Failed to connect Bitbucket");
      }
      toast.success("Bitbucket connected");
      setBitbucketForm({ username: "", appPassword: "", workspace: "" });
      setBitbucketFormOpen(false);
      await refreshBitbucket();
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Failed to connect Bitbucket",
      );
    } finally {
      setBitbucketSubmitting(false);
    }
  }

  async function disconnectBitbucket() {
    if (
      !window.confirm(
        "Disconnect Bitbucket? Pepper will stop posting PR review comments and build statuses to your Bitbucket repositories.",
      )
    ) {
      return;
    }
    setBitbucketDisconnecting(true);
    try {
      const res = await fetch("/api/integrations/bitbucket/connect", {
        method: "DELETE",
      });
      if (!res.ok) throw new Error("Failed to disconnect");
      toast.success("Bitbucket disconnected");
      setBitbucketConn({ connected: false, username: null, workspace: null });
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Failed to disconnect Bitbucket",
      );
    } finally {
      setBitbucketDisconnecting(false);
    }
  }

  async function disconnectGithubOAuth() {
    if (
      !window.confirm(
        "Disconnect GitHub? You will need to authorize again to import repositories or open fix pull requests.",
      )
    ) {
      return;
    }
    setGithubDisconnecting(true);
    try {
      const res = await fetch("/api/integrations/github", { method: "DELETE" });
      const j = (await res.json()) as { error?: string };
      if (!res.ok) throw new Error(j.error || "Failed to disconnect");
      toast.success("GitHub disconnected");
      setGithubConn((prev) => ({
        connected: false,
        githubLogin: null,
        oauthConfigured: prev?.oauthConfigured ?? false,
      }));
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to disconnect GitHub");
    } finally {
      setGithubDisconnecting(false);
    }
  }

  const integrations: Integration[] = [
    {
      id: "github",
      name: "GitHub",
      category: "source-control",
      description: "Import repositories, scan pull requests, and create AI fix PRs",
      icon: <svg className="h-8 w-8" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v 3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>,
      features: ["Repository Import", "PR Scanning & Reviews", "AI Fix Pull Requests"],
    },
    {
      id: "gitlab",
      name: "GitLab",
      category: "source-control",
      description: "Automatically scan merge requests and push events",
      icon: <svg className="h-8 w-8" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12s5.374 12 12 12 12-5.373 12-12-5.374-12-12-12zm0 2c5.514 0 10 4.486 10 10s-4.486 10-10 10-10-4.486-10-10 4.486-10 10-10z"/></svg>,
      features: ["Merge Request Scanning", "Security Reports", "Webhooks Support"],
    },
    {
      id: "bitbucket",
      name: "Bitbucket Cloud",
      category: "source-control",
      description: "Scan pull requests, post comments and build statuses",
      icon: <svg className="h-8 w-8" viewBox="0 0 24 24" fill="currentColor"><path d="M0 0h24v24H0z"/></svg>,
      features: ["PR Scanning", "Inline Comments", "Build Status Updates"],
    },
    {
      id: "azure",
      name: "Azure DevOps",
      category: "source-control",
      description: "Import repos and integrate with Azure Pipelines",
      icon: <Zap className="h-8 w-8" />,
      features: ["PR Threads & Status Checks", "Pipeline Integration", "Service Hooks"],
    },
    {
      id: "slack",
      name: "Slack",
      category: "notifications",
      description: "Get security alerts and scan summaries in your channels",
      icon: <MessageSquare className="h-8 w-8" />,
      features: ["Scan Notifications", "Custom Alerts", "Channel Integration"],
    },
    {
      id: "jira",
      name: "Jira",
      category: "issue-tracking",
      description: "Create and sync issues for vulnerabilities and security findings",
      icon: <AlertCircle className="h-8 w-8" />,
      features: ["Issue Creation", "Two-way Sync", "Custom Workflows"],
    },
  ];

  const categories = [
    { id: "all", label: "All Integrations" },
    { id: "source-control", label: "Source Control" },
    { id: "notifications", label: "Notifications" },
    { id: "issue-tracking", label: "Issue Tracking" },
    { id: "ci-cd", label: "CI/CD" },
    { id: "developer-tools", label: "Developer Tools" },
  ] as const;

  const getConnectionStatus = (integrationId: string) => {
    switch (integrationId) {
      case "github":
        return githubConn?.connected ?? false;
      case "bitbucket":
        return bitbucketConn?.connected ?? false;
      case "azure":
        return azureConn?.connected ?? false;
      default:
        return false;
    }
  };

  const filteredIntegrations = integrations.filter((integration) => {
    const matchesCategory = activeCategory === "all" || integration.category === activeCategory;
    const matchesSearch =
      integration.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      integration.description.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  const handleConnect = (integrationId: string) => {
    switch (integrationId) {
      case "github":
        if (githubConn?.oauthConfigured === false) {
          toast.error("GitHub OAuth is not configured");
        } else {
          window.location.href = "/api/integrations/github/connect?returnTo=%2Fsettings%2Fintegrations";
        }
        break;
      case "bitbucket":
        setBitbucketFormOpen(true);
        break;
      case "azure":
        setAzureFormOpen(true);
        break;
      default:
        toast.info("Coming soon");
    }
  };

  const handleDisconnect = (integrationId: string) => {
    switch (integrationId) {
      case "github":
        void disconnectGithubOAuth();
        break;
      case "bitbucket":
        void disconnectBitbucket();
        break;
      case "azure":
        void disconnectAzure();
        break;
    }
  };

  return (
    <div className="min-h-screen bg-white">
      {/* Header */}
      <div className="border-b border-gray-200 px-8 py-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Integrations</h1>
            <p className="mt-2 text-base text-gray-600">
              Connect external services to Pepper and supercharge your security workflow.
            </p>
          </div>
          <Button variant="outline" className="gap-2" asChild>
            <Link href="#help">
              <HelpCircle className="h-4 w-4" />
              Learn how integrations work
            </Link>
          </Button>
        </div>
      </div>

      <div className="px-8 py-8">
        {/* Category Tabs */}
        <div className="flex gap-8 border-b border-gray-200 pb-0">
          {categories.map((cat) => (
            <button
              key={cat.id}
              onClick={() => setActiveCategory(cat.id as IntegrationCategory)}
              className={`pb-4 px-1 text-sm font-medium border-b-2 transition-colors ${
                activeCategory === cat.id
                  ? "text-blue-600 border-blue-600"
                  : "text-gray-600 border-transparent hover:text-gray-900"
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>

        <div className="mt-8 flex gap-8">
          {/* Left Sidebar */}
          <div className="w-48 flex-shrink-0">
            <div className="rounded-lg bg-blue-50 p-4 mb-6">
              <div className="flex items-center gap-3 mb-3">
                <MessageSquare className="h-5 w-5 text-blue-600" />
                <h3 className="font-semibold text-gray-900">Need help?</h3>
              </div>
              <p className="text-sm text-gray-600 mb-4">
                Learn how to set up integrations and automate your security workflow.
              </p>
              <Link href="#" className="text-sm font-medium text-blue-600 hover:text-blue-700">
                View Documentation →
              </Link>
            </div>

            <div className="space-y-3">
              <div className="rounded-lg bg-gray-100 px-4 py-3">
                <h3 className="font-semibold text-gray-900 text-sm mb-3">All Categories</h3>
                <div className="space-y-2">
                  {categories.map((cat) => (
                    <button
                      key={cat.id}
                      onClick={() => setActiveCategory(cat.id as IntegrationCategory)}
                      className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors ${
                        activeCategory === cat.id
                          ? "bg-blue-100 text-blue-900 font-medium"
                          : "text-gray-700 hover:bg-gray-200"
                      }`}
                    >
                      {cat.label}
                      {cat.id !== "all" && (
                        <span className="ml-2 text-xs text-gray-500">
                          {integrations.filter(i => i.category === cat.id).length}
                        </span>
                      )}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Right Content */}
          <div className="flex-1">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredIntegrations.map((integration) => {
                const isConnected = getConnectionStatus(integration.id);
                return (
                  <div
                    key={integration.id}
                    className="rounded-lg border border-gray-200 bg-white hover:shadow-md transition-shadow overflow-hidden"
                  >
                    {/* Card Header */}
                    <div className="border-b border-gray-200 p-6 bg-gray-50 flex items-start justify-between">
                      <div className="text-gray-700">{integration.icon}</div>
                      <button className="text-gray-400 hover:text-gray-600">
                        <MoreVertical className="h-4 w-4" />
                      </button>
                    </div>

                    {/* Card Content */}
                    <div className="p-6">
                      <div className="mb-4">
                        <div className="flex items-center gap-2 mb-2">
                          <h3 className="text-lg font-semibold text-gray-900">{integration.name}</h3>
                          <Badge
                            variant={isConnected ? "default" : "outline"}
                            className={
                              isConnected
                                ? "bg-green-100 text-green-800 border-green-300"
                                : "bg-gray-100 text-gray-800 border-gray-300"
                            }
                          >
                            {isConnected ? (
                              <>
                                <Check className="h-3 w-3 mr-1" />
                                Connected
                              </>
                            ) : (
                              "Not Connected"
                            )}
                          </Badge>
                        </div>
                        <p className="text-sm text-gray-600">{integration.description}</p>
                      </div>

                      {/* Features */}
                      <div className="space-y-2 py-4 border-t border-gray-200">
                        {integration.features.map((feature) => (
                          <div key={feature} className="flex items-center gap-2 text-sm text-gray-700">
                            <Check className="h-4 w-4 text-green-500 flex-shrink-0" />
                            {feature}
                          </div>
                        ))}
                      </div>

                      {/* Actions */}
                      <div className="flex gap-2 pt-4">
                        {isConnected ? (
                          <>
                            <Button
                              size="sm"
                              className="flex-1 bg-blue-600 hover:bg-blue-700 text-white"
                              onClick={() => {
                                /* Handle manage */
                              }}
                            >
                              Manage
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              className="flex-1"
                              onClick={() => handleDisconnect(integration.id)}
                            >
                              Disconnect
                            </Button>
                          </>
                        ) : (
                          <>
                            <Button
                              size="sm"
                              className="flex-1 bg-blue-600 hover:bg-blue-700 text-white"
                              onClick={() => handleConnect(integration.id)}
                            >
                              Connect
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              className="flex-1"
                            >
                              View Details →
                            </Button>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Developer Tools Section */}
      <div className="px-8 py-12 border-t border-gray-200 bg-gray-50">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Developer Tools</h2>
        <p className="text-gray-600 mb-8">
          Set up pre-commit hooks, IDE plugins, and other developer integrations.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* Pre-commit Hook Card */}
          <Link href="/settings/integrations/precommit">
            <div className="h-full rounded-lg border border-gray-200 bg-white hover:shadow-md transition-shadow overflow-hidden cursor-pointer">
              <div className="border-b border-gray-200 p-6 bg-gray-50 flex items-start justify-between">
                <div className="text-gray-700">
                  <Zap className="h-8 w-8" />
                </div>
                <button className="text-gray-400 hover:text-gray-600">
                  <MoreVertical className="h-4 w-4" />
                </button>
              </div>
              <div className="p-6">
                <div className="mb-4">
                  <h3 className="text-lg font-semibold text-gray-900">Pre-commit Hook</h3>
                  <p className="text-sm text-gray-600 mt-2">
                    Block commits with secrets or high-severity findings automatically.
                  </p>
                </div>
                <div className="space-y-2 py-4 border-t border-gray-200">
                  <div className="flex items-center gap-2 text-sm text-gray-700">
                    <Check className="h-4 w-4 text-green-500 flex-shrink-0" />
                    Secret Detection
                  </div>
                  <div className="flex items-center gap-2 text-sm text-gray-700">
                    <Check className="h-4 w-4 text-green-500 flex-shrink-0" />
                    SAST Blocking
                  </div>
                  <div className="flex items-center gap-2 text-sm text-gray-700">
                    <Check className="h-4 w-4 text-green-500 flex-shrink-0" />
                    One-Click Setup
                  </div>
                </div>
                <div className="flex gap-2 pt-4">
                  <Button
                    size="sm"
                    className="flex-1 bg-blue-600 hover:bg-blue-700 text-white"
                  >
                    Setup
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="flex-1"
                  >
                    Learn More →
                  </Button>
                </div>
              </div>
            </div>
          </Link>

          {/* IDE Integration Card */}
          <Link href="/settings/integrations/ide">
            <div className="h-full rounded-lg border border-gray-200 bg-white hover:shadow-md transition-shadow overflow-hidden cursor-pointer">
              <div className="border-b border-gray-200 p-6 bg-gray-50 flex items-start justify-between">
                <div className="text-gray-700">
                  <svg className="h-8 w-8" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M0 3v18h24V3H0zm9 16H2v-2h7v2zm3-5H2V4h10v10zm11 5h-7v-2h7v2zm0-5H2V4h20v10z"/>
                  </svg>
                </div>
                <button className="text-gray-400 hover:text-gray-600">
                  <MoreVertical className="h-4 w-4" />
                </button>
              </div>
              <div className="p-6">
                <div className="mb-4">
                  <h3 className="text-lg font-semibold text-gray-900">IDE Integration</h3>
                  <p className="text-sm text-gray-600 mt-2">
                    View findings in VS Code, Neovim, or any editor via API.
                  </p>
                </div>
                <div className="space-y-2 py-4 border-t border-gray-200">
                  <div className="flex items-center gap-2 text-sm text-gray-700">
                    <Check className="h-4 w-4 text-green-500 flex-shrink-0" />
                    VS Code Support
                  </div>
                  <div className="flex items-center gap-2 text-sm text-gray-700">
                    <Check className="h-4 w-4 text-green-500 flex-shrink-0" />
                    API Endpoint
                  </div>
                  <div className="flex items-center gap-2 text-sm text-gray-700">
                    <Check className="h-4 w-4 text-green-500 flex-shrink-0" />
                    Auto-Fill Setup
                  </div>
                </div>
                <div className="flex gap-2 pt-4">
                  <Button
                    size="sm"
                    className="flex-1 bg-blue-600 hover:bg-blue-700 text-white"
                  >
                    Configure
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="flex-1"
                  >
                    Learn More →
                  </Button>
                </div>
              </div>
            </div>
          </Link>
        </div>
      </div>

      {/* Security Footer */}
      <div className="border-t border-gray-200 bg-gray-50 mt-0 py-4">
        <div className="max-w-7xl mx-auto px-8 flex items-center justify-between">
          <div className="flex items-center gap-3 text-sm text-gray-600">
            <Lock className="h-4 w-4 text-gray-500" />
            <span>
              All integrations are secure and encrypted. Pepper never stores your credentials in plain text.
            </span>
          </div>
          <Button variant="link" className="text-blue-600 hover:text-blue-700 gap-1 h-auto p-0">
            Learn more about security
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Bitbucket Form Modal */}
      {bitbucketFormOpen && (
        <div className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center">
          <div className="bg-white rounded-lg p-6 max-w-md w-full">
            <h2 className="text-xl font-bold mb-4">Connect Bitbucket</h2>
            <form onSubmit={connectBitbucket} className="space-y-4">
              <div>
                <Label htmlFor="bb-username">Username</Label>
                <Input
                  id="bb-username"
                  value={bitbucketForm.username}
                  onChange={(e) =>
                    setBitbucketForm({ ...bitbucketForm, username: e.target.value })
                  }
                  placeholder="your-username"
                />
              </div>
              <div>
                <Label htmlFor="bb-password">App Password</Label>
                <Input
                  id="bb-password"
                  type="password"
                  value={bitbucketForm.appPassword}
                  onChange={(e) =>
                    setBitbucketForm({ ...bitbucketForm, appPassword: e.target.value })
                  }
                  placeholder="••••••••"
                />
              </div>
              <div>
                <Label htmlFor="bb-workspace">Workspace (optional)</Label>
                <Input
                  id="bb-workspace"
                  value={bitbucketForm.workspace}
                  onChange={(e) =>
                    setBitbucketForm({ ...bitbucketForm, workspace: e.target.value })
                  }
                  placeholder="workspace-slug"
                />
              </div>
              <div className="flex gap-2 pt-4">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setBitbucketFormOpen(false)}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={bitbucketSubmitting}
                  className="flex-1 bg-blue-600 hover:bg-blue-700 text-white"
                >
                  {bitbucketSubmitting ? "Connecting..." : "Connect"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Azure Form Modal */}
      {azureFormOpen && (
        <div className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center">
          <div className="bg-white rounded-lg p-6 max-w-md w-full">
            <h2 className="text-xl font-bold mb-4">Connect Azure DevOps</h2>
            <form onSubmit={connectAzure} className="space-y-4">
              <div>
                <Label htmlFor="az-org">Organization</Label>
                <Input
                  id="az-org"
                  value={azureForm.azureOrganization}
                  onChange={(e) =>
                    setAzureForm({ ...azureForm, azureOrganization: e.target.value })
                  }
                  placeholder="your-organization"
                />
              </div>
              <div>
                <Label htmlFor="az-pat">Personal Access Token</Label>
                <Input
                  id="az-pat"
                  type="password"
                  value={azureForm.pat}
                  onChange={(e) =>
                    setAzureForm({ ...azureForm, pat: e.target.value })
                  }
                  placeholder="••••••••"
                />
              </div>
              <div className="flex gap-2 pt-4">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setAzureFormOpen(false)}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={azureSubmitting}
                  className="flex-1 bg-blue-600 hover:bg-blue-700 text-white"
                >
                  {azureSubmitting ? "Connecting..." : "Connect"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
