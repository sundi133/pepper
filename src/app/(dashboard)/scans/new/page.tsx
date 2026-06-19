"use client";

import { useEffect, useState, useMemo } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  AlertCircle,
  CheckCircle2,
  Github,
  GitBranch,
  Lock,
  Loader2,
  Play,
  RefreshCw,
  Search,
  Bookmark,
  Eye,
  Clock,
  Upload,
} from "lucide-react";
import { cn } from "@/lib/utils";

type ScanSource = "github" | "bitbucket" | "azure" | "url" | "upload";

interface Scanner {
  id: string;
  name: string;
  engines: string[];
}

// Validate Git repository URL
function isValidGitRepoUrl(url: string): boolean {
  if (!url.trim()) return false;

  try {
    const urlObj = new URL(url);

    // Must start with http or https
    if (!["http:", "https:"].includes(urlObj.protocol)) return false;

    // Common Git hosting services
    const validHosts = [
      "github.com",
      "gitlab.com",
      "bitbucket.org",
      "dev.azure.com",
      "azure.microsoft.com",
      "gitea",
      "git.sr.ht"
    ];

    const hostname = urlObj.hostname.toLowerCase();
    const isKnownHost = validHosts.some(host => hostname.includes(host));

    // Check if it looks like a repo path (has at least owner/repo pattern)
    const hasRepoPath = urlObj.pathname.split("/").filter(p => p.length > 0).length >= 2;

    // If known host, must have repo path
    if (isKnownHost) {
      return hasRepoPath;
    }

    // For unknown hosts, just check it's a valid URL with a path
    return urlObj.pathname.length > 1;
  } catch {
    return false;
  }
}

interface Repository {
  id: number;
  fullName: string;
  name: string;
  defaultBranch: string;
  branches?: string[];
  branchesLoaded?: boolean;
  language: string | null;
  private: boolean;
  alreadyConnected?: boolean;
  owner: string;
  htmlUrl: string;
  cloneUrl: string;
  updatedAt: string | null;
}

const SOURCES = [
  { id: "github", label: "GitHub", icon: Github },
  { id: "bitbucket", label: "Bitbucket", icon: () => <div className="h-5 w-5">B</div> },
  { id: "azure", label: "Azure DevOps", icon: () => <div className="h-5 w-5">A</div> },
  { id: "url", label: "Repository URL", icon: () => <div className="h-5 w-5">🔗</div> },
  { id: "upload", label: "Upload Code", icon: () => <div className="h-5 w-5">⬆</div> },
] as const;

const SCANNERS: Scanner[] = [
  { id: "sast", name: "SAST", engines: ["Semgrep", "CodeQL"] },
  { id: "sca", name: "SCA", engines: ["OWASP Dependency Check"] },
  { id: "secrets", name: "Secrets", engines: ["Gitleaks"] },
  { id: "iac", name: "IaC", engines: ["Checkov"] },
  { id: "container", name: "Container", engines: ["Trivy"] },
  { id: "zero-day", name: "Zero-Day", engines: ["LLM Analysis"] },
];


// Scan presets - define which scanners are enabled for each preset
const SCAN_PRESETS = {
  default: {
    name: "Default (Recommended)",
    description: "SAST · SCA · Secrets · IaC · Zero-day · Container",
    scanners: ["sast", "sca", "secrets", "iac", "zero-day", "container"],
  },
  comprehensive: {
    name: "Comprehensive",
    description: "All available security scanners",
    scanners: ["sast", "sca", "secrets", "iac", "container", "zero-day"],
  },
  fast: {
    name: "Fast",
    description: "Quick scan - secrets and SCA only",
    scanners: ["sca", "secrets"],
  },
};


export default function NewScanPage() {
  const router = useRouter();
  const [scanSource, setScanSource] = useState<ScanSource>("github");
  const [selectedRepoId, setSelectedRepoId] = useState<string | null>(null);
  const [presetId, setPresetId] = useState("default");
  const [enabledScanners, setEnabledScanners] = useState<Record<string, boolean>>(
    SCANNERS.reduce((acc, s) => ({ ...acc, [s.id]: true }), {})
  );
  const [isScanning, setIsScanning] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [visibility, setVisibility] = useState("all");
  const [sort, setSort] = useState("recently-updated");
  const [currentPage, setCurrentPage] = useState(1);
  const [allRepositories, setAllRepositories] = useState<Repository[]>([]);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [recentScans, setRecentScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedBranch, setSelectedBranch] = useState<string | null>(null);
  const [expandedRepoId, setExpandedRepoId] = useState<string | null>(null);

  // State for other source types
  const [repoUrl, setRepoUrl] = useState("");
  const [repoBranch, setRepoBranch] = useState("");
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);

  // Integration connection status
  const [integrationStatus, setIntegrationStatus] = useState<{
    github?: { connected: boolean; oauthConfigured: boolean };
    bitbucket?: { connected: boolean };
    azure?: { connected: boolean };
  }>({});

  // Fetch repositories based on source
  const fetchRepositories = async () => {
    setLoading(true);
    try {
      let endpoint = "";

      if (scanSource === "github") {
        endpoint = "/api/integrations/github/repositories";
      } else if (scanSource === "bitbucket") {
        endpoint = "/api/integrations/bitbucket/repositories";
      } else if (scanSource === "azure") {
        endpoint = "/api/integrations/azure-devops/repositories";
      } else {
        return;
      }

      const res = await fetch(endpoint);
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || `Failed to fetch ${scanSource} repositories`);
      }
      const data = await res.json();
      const repos = data.repositories || [];
      setAllRepositories(repos);
      setRepositories(repos);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : `Failed to fetch ${scanSource} repositories`);
      setAllRepositories([]);
      setRepositories([]);
    } finally {
      setLoading(false);
    }
  };

  // Apply visibility filter whenever allRepositories or visibility changes
  useEffect(() => {
    if (visibility === "public") {
      setRepositories(allRepositories.filter(r => !r.private));
    } else if (visibility === "private") {
      setRepositories(allRepositories.filter(r => r.private));
    } else {
      setRepositories(allRepositories);
    }
  }, [allRepositories, visibility]);

  // Fetch branches for a specific repo
  const fetchBranches = async (repoId: string) => {
    const repo = allRepositories.find(r => String(r.id) === repoId);
    if (!repo || (repo.branches && repo.branches.length > 1)) return;

    try {
      const [owner, name] = repo.fullName.split("/");
      const res = await fetch(
        `/api/integrations/github/branches?owner=${encodeURIComponent(owner)}&repo=${encodeURIComponent(name)}`
      );
      if (!res.ok) return;

      const data = await res.json();
      const branches = data.branches || [repo.defaultBranch];

      setAllRepositories(prev =>
        prev.map(r =>
          r.id === repo.id
            ? { ...r, branches, branchesLoaded: true }
            : r
        )
      );
    } catch (error) {
      console.error("Failed to fetch branches");
    }
  };

  // Fetch recent scans
  const fetchRecentScans = async () => {
    try {
      const res = await fetch("/api/scans?limit=5");
      const data = await res.json();
      setRecentScans(data.scans || []);
    } catch (error) {
      console.error("Failed to fetch recent scans");
    }
  };

  // Check integration status on mount
  useEffect(() => {
    const checkIntegrations = async () => {
      try {
        const [githubRes, bitbucketRes, azureRes] = await Promise.all([
          fetch("/api/integrations/github"),
          fetch("/api/integrations/bitbucket/connect"),
          fetch("/api/integrations/azure-devops/connect"),
        ]);

        const status: typeof integrationStatus = {};

        if (githubRes.ok) {
          const data = await githubRes.json();
          status.github = {
            connected: Boolean(data.connected),
            oauthConfigured: Boolean(data.oauthConfigured),
          };
        }
        if (bitbucketRes.ok) {
          const data = await bitbucketRes.json();
          status.bitbucket = { connected: Boolean(data.connected) };
        }
        if (azureRes.ok) {
          const data = await azureRes.json();
          status.azure = { connected: Boolean(data.connected) };
        }

        setIntegrationStatus(status);
      } catch (error) {
        console.error("Failed to check integration status");
      }
    };

    checkIntegrations();
  }, []);

  // Initial fetch
  useEffect(() => {
    if (scanSource === "github" || scanSource === "bitbucket" || scanSource === "azure") {
      fetchRepositories();
    }
    fetchRecentScans();
  }, [scanSource]);

  const selectedRepo = allRepositories.find((r) => String(r.id) === selectedRepoId);

  const handleStartScan = async () => {
    setIsScanning(true);
    try {
      // Get enabled scanner names
      const enabledScannerIds = Object.entries(enabledScanners)
        .filter(([, enabled]) => enabled)
        .map(([id]) => id.toUpperCase());

      // Determine scan type based on enabled scanners
      const enabledScannerCount = Object.values(enabledScanners).filter(Boolean).length;
      const allScannersEnabled = enabledScannerCount === SCANNERS.length;
      
      let scanType = "FULL";
      if (!allScannersEnabled) {
        const scannersList = Object.entries(enabledScanners)
          .filter(([, enabled]) => enabled)
          .map(([id]) => id.toUpperCase())
          .sort()
          .join("_");
        
        // Map to specific scan types for common combinations
        const commonTypes: Record<string, string> = {
          "SAST": "SAST_ONLY",
          "SCA": "SCA_ONLY",
          "SECRETS": "SECRETS_ONLY",
          "IAC": "IAC_ONLY",
          "CONTAINER": "CONTAINER_ONLY",
          "ZERO_DAY": "ZERO_DAY_ONLY",
          "SAST_SCA_SECRETS": "FULL",
          "SAST_SCA_SECRETS_IAC": "FULL",
          "SAST_SCA_SECRETS_IAC_CONTAINER": "FULL",
          "SAST_SCA_SECRETS_IAC_CONTAINER_ZERO_DAY": "FULL",
        };
        
        scanType = commonTypes[scannersList] || "FULL";
      }
      
      const scanPayload: any = {
        scanType,
      };

      if (scanSource === "github") {
        if (!selectedRepoId) {
          toast.error("Please select a repository");
          setIsScanning(false);
          return;
        }
        if (!selectedBranch) {
          toast.error("Please select a branch");
          setIsScanning(false);
          return;
        }
        const repo = selectedRepo;
        if (!repo) {
          toast.error("Repository not found");
          setIsScanning(false);
          return;
        }
        scanPayload.repoUrl = repo.cloneUrl;
        scanPayload.branch = selectedBranch;
      } else if (scanSource === "bitbucket") {
        if (!selectedRepoId) {
          toast.error("Please select a repository");
          setIsScanning(false);
          return;
        }
        if (!selectedBranch) {
          toast.error("Please select a branch");
          setIsScanning(false);
          return;
        }
        const repo = selectedRepo;
        if (!repo) {
          toast.error("Repository not found");
          setIsScanning(false);
          return;
        }
        scanPayload.repoUrl = repo.cloneUrl;
        scanPayload.branch = selectedBranch;
      } else if (scanSource === "azure") {
        if (!selectedRepoId) {
          toast.error("Please select a repository");
          setIsScanning(false);
          return;
        }
        if (!selectedBranch) {
          toast.error("Please select a branch");
          setIsScanning(false);
          return;
        }
        const repo = selectedRepo;
        if (!repo) {
          toast.error("Repository not found");
          setIsScanning(false);
          return;
        }
        scanPayload.repoUrl = repo.cloneUrl;
        scanPayload.branch = selectedBranch;
      } else if (scanSource === "url") {
        if (!repoUrl.trim()) {
          toast.error("Please enter a repository URL");
          setIsScanning(false);
          return;
        }
        if (!isValidGitRepoUrl(repoUrl)) {
          toast.error("Enter a valid Git repository URL (e.g., https://github.com/owner/repo)");
          setIsScanning(false);
          return;
        }
        scanPayload.repoUrl = repoUrl.trim();
        if (repoBranch.trim()) {
          scanPayload.branch = repoBranch.trim();
        }
      }

      // Add enabled scanners to payload for all non-upload sources
      if (scanSource !== "upload") {
        scanPayload.scanners = enabledScannerIds;
      }

      if (scanSource === "upload") {
        if (!uploadedFile) {
          toast.error("Please upload a file");
          setIsScanning(false);
          return;
        }

        // For file uploads, use multipart/form-data
        const formData = new FormData();
        formData.append("file", uploadedFile);
        formData.append("data", JSON.stringify({
          scanType,
          scanners: enabledScannerIds,
        }));

        const res = await fetch("/api/scans", {
          method: "POST",
          body: formData,
        });

        if (!res.ok) {
          const errorData = await res.json();
          throw new Error(errorData.error || "Failed to start scan");
        }
        const { scanId } = await res.json();
        toast.success("Scan started");
        router.push(`/scans/${scanId}`);
        return;
      }

      // For non-upload sources, send JSON
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(scanPayload),
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "Failed to start scan");
      }
      const { scanId } = await res.json();
      toast.success("Scan started");
      router.push(`/scans/${scanId}`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to start scan");
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="space-y-6 pb-10">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Scan" },
        ]}
      />

      <div>
        <h1 className="text-3xl font-bold">Scan</h1>
        <p className="mt-1 text-slate-600">
          Scan your code for vulnerabilities, secrets, and misconfigurations.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Left Column */}
        <div className="space-y-6 lg:col-span-2">
          {/* Start a New Scan */}
          <Card>
            <CardHeader>
              <CardTitle>Start a New Scan</CardTitle>
              <CardDescription>
                Connect a repository or upload code to begin a security scan.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
                {SOURCES.map((source) => {
                  const Icon = source.icon;
                  return (
                    <button
                      key={source.id}
                      onClick={() => setScanSource(source.id as ScanSource)}
                      className={cn(
                        "relative flex flex-col items-center justify-center gap-2 rounded-lg border-2 p-4 transition-all",
                        scanSource === source.id
                          ? "border-primary bg-primary/10"
                          : "border-slate-200 hover:border-slate-300"
                      )}
                    >
                      <Icon className="h-6 w-6" />
                      <span className="text-xs font-medium text-center">{source.label}</span>
                      {scanSource === source.id && (
                        <CheckCircle2 className="absolute top-2 right-2 h-4 w-4 text-primary" />
                      )}
                    </button>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* Scan Presets */}
          <Card>
            <CardHeader>
              <CardTitle>Scan Presets</CardTitle>
              <CardDescription>
                Use a preset scan configuration or create your own.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Select
                value={presetId}
                onValueChange={(value) => {
                  setPresetId(value);
                  // Apply preset scanners
                  const preset = SCAN_PRESETS[value as keyof typeof SCAN_PRESETS];
                  if (preset) {
                    const newScanners: Record<string, boolean> = {};
                    SCANNERS.forEach((scanner) => {
                      newScanners[scanner.id] = preset.scanners.includes(scanner.id);
                    });
                    setEnabledScanners(newScanners);
                  }
                }}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(SCAN_PRESETS).map(([key, preset]) => (
                    <SelectItem key={key} value={key}>
                      {preset.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <div className="flex flex-wrap gap-2">
                {SCANNERS.map((scanner) => (
                  <button
                    key={scanner.id}
                    onClick={() =>
                      setEnabledScanners((prev) => ({
                        ...prev,
                        [scanner.id]: !prev[scanner.id],
                      }))
                    }
                    className={cn(
                      "flex items-center gap-2 rounded-full px-3 py-1.5 text-xs font-medium transition-colors",
                      enabledScanners[scanner.id]
                        ? "bg-green-100 text-green-700"
                        : "bg-slate-100 text-slate-600"
                    )}
                  >
                    {enabledScanners[scanner.id] && (
                      <CheckCircle2 className="h-3.5 w-3.5" />
                    )}
                    {scanner.name}
                  </button>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Connection Status Alerts */}
          {scanSource === "github" && !integrationStatus.github?.connected && (
            <Card className="border-amber-200 bg-amber-50">
              <CardContent className="pt-6 flex gap-3">
                <AlertCircle className="h-5 w-5 shrink-0 text-amber-600 mt-0.5" />
                <div className="flex-1">
                  <h3 className="font-medium text-amber-900 mb-1">
                    GitHub Not Connected
                  </h3>
                  <p className="text-sm text-amber-800 mb-3">
                    Connect your GitHub account to import and scan your repositories.
                  </p>
                  <Button
                    size="sm"
                    onClick={() => window.location.href = "/api/integrations/github/connect?returnTo=%2Fscans%2Fnew"}
                    className="bg-amber-600 hover:bg-amber-700"
                  >
                    Connect GitHub
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {scanSource === "bitbucket" && !integrationStatus.bitbucket?.connected && (
            <Card className="border-amber-200 bg-amber-50">
              <CardContent className="pt-6 flex gap-3">
                <AlertCircle className="h-5 w-5 shrink-0 text-amber-600 mt-0.5" />
                <div className="flex-1">
                  <h3 className="font-medium text-amber-900 mb-1">
                    Bitbucket Not Connected
                  </h3>
                  <p className="text-sm text-amber-800 mb-3">
                    Go to Settings → Integrations to connect your Bitbucket Cloud account.
                  </p>
                  <Button
                    size="sm"
                    asChild
                    className="bg-amber-600 hover:bg-amber-700"
                  >
                    <a href="/settings/integrations">
                      Setup Bitbucket
                    </a>
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {scanSource === "azure" && !integrationStatus.azure?.connected && (
            <Card className="border-amber-200 bg-amber-50">
              <CardContent className="pt-6 flex gap-3">
                <AlertCircle className="h-5 w-5 shrink-0 text-amber-600 mt-0.5" />
                <div className="flex-1">
                  <h3 className="font-medium text-amber-900 mb-1">
                    Azure DevOps Not Connected
                  </h3>
                  <p className="text-sm text-amber-800 mb-3">
                    Go to Settings → Integrations to connect your Azure DevOps account.
                  </p>
                  <Button
                    size="sm"
                    asChild
                    className="bg-amber-600 hover:bg-amber-700"
                  >
                    <a href="/settings/integrations">
                      Setup Azure DevOps
                    </a>
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Source-Specific Content */}
          {(scanSource === "github" || scanSource === "bitbucket" || scanSource === "azure") && (
            <Card>
              <CardHeader>
                <CardTitle>Select a Repository</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
                  <div className="flex-1">
                    <div className="relative">
                      <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                      <Input
                        placeholder="Search repositories..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="pl-10"
                      />
                    </div>
                  </div>
                  {scanSource === "github" && (
                    <Select value={visibility} onValueChange={setVisibility}>
                      <SelectTrigger className="sm:w-40">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">Visibility: All</SelectItem>
                        <SelectItem value="public">Public</SelectItem>
                        <SelectItem value="private">Private</SelectItem>
                      </SelectContent>
                    </Select>
                  )}
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={fetchRepositories}
                    disabled={loading}
                  >
                    <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
                  </Button>
                </div>

                {loading ? (
                  <div className="flex items-center justify-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin text-slate-400" />
                  </div>
                ) : (
                  <>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-12">
                            <input type="radio" disabled />
                          </TableHead>
                          <TableHead>Repository</TableHead>
                          <TableHead>Visibility</TableHead>
                          <TableHead>Default Branch</TableHead>
                          <TableHead>Last Updated</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {Array.isArray(repositories) && repositories.length > 0 ?
                          repositories.map((repo) => [
                          <TableRow
                            key={repo.id}
                            className={cn(
                              "cursor-pointer",
                              selectedRepoId === String(repo.id) && "bg-primary/10"
                            )}
                            onClick={() => {
                              setSelectedRepoId(String(repo.id));
                              fetchBranches(String(repo.id));
                            }}
                          >
                            <TableCell>
                              <input
                                type="radio"
                                name="repo"
                                checked={selectedRepoId === String(repo.id)}
                                onChange={() => {
                                  setSelectedRepoId(String(repo.id));
                                  fetchBranches(String(repo.id));
                                }}
                              />
                            </TableCell>
                            <TableCell>
                              <div>
                                <p className="font-medium">{repo.name}</p>
                                <p className="text-xs text-slate-500">{repo.owner}</p>
                              </div>
                            </TableCell>
                            <TableCell>
                              <Badge variant={repo.private ? "secondary" : "outline"}>
                                {repo.private ? (
                                  <>
                                    <Lock className="mr-1 h-3 w-3" />
                                    Private
                                  </>
                                ) : (
                                  <>
                                    <Eye className="mr-1 h-3 w-3" />
                                    Public
                                  </>
                                )}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center gap-1">
                                <GitBranch className="h-4 w-4 text-slate-400" />
                                {repo.defaultBranch}
                              </div>
                            </TableCell>
                            <TableCell className="text-sm text-slate-600">
                              {repo.updatedAt ? new Date(repo.updatedAt).toLocaleDateString() : "Never"}
                            </TableCell>
                          </TableRow>,
                          selectedRepoId === String(repo.id) && repo.branches && repo.branches.length > 0 && (
                            <TableRow key={`branches-${repo.id}`} className="bg-slate-50">
                              <TableCell colSpan={5} className="p-4">
                                <div className="space-y-3">
                                  <Label className="text-sm font-medium">Select branch to scan:</Label>
                                  <div className="flex flex-wrap gap-2">
                                    {repo.branches.map((branch) => (
                                      <Button
                                        key={branch}
                                        variant={selectedBranch === branch ? "default" : "outline"}
                                        size="sm"
                                        onClick={() => setSelectedBranch(branch)}
                                        className="text-xs"
                                      >
                                        <GitBranch className="mr-1 h-3 w-3" />
                                        {branch}
                                        {branch === repo.defaultBranch && (
                                          <span className="ml-1 text-xs opacity-70">(default)</span>
                                        )}
                                      </Button>
                                    ))}
                                  </div>
                                </div>
                              </TableCell>
                            </TableRow>
                          ),
                        ]).flat()
                        : (
                          <TableRow>
                            <TableCell colSpan={5} className="py-8 text-center">
                              <p className="text-slate-500">No repositories found</p>
                            </TableCell>
                          </TableRow>
                        )}
                      </TableBody>
                    </Table>

                    {repositories.length > 0 && (
                      <div className="flex items-center justify-between text-xs text-slate-600">
                        <span>Showing {repositories.length} repositories</span>
                      </div>
                    )}
                  </>
                )}
              </CardContent>
            </Card>
          )}

          {/* Repository URL Input */}
          {scanSource === "url" && (
            <Card>
              <CardHeader>
                <CardTitle>Repository URL</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="repo-url" className="text-sm font-medium mb-2 block">
                    Repository URL
                  </Label>
                  <div className="relative">
                    <Input
                      id="repo-url"
                      placeholder="e.g., https://github.com/owner/repo"
                      value={repoUrl}
                      onChange={(e) => setRepoUrl(e.target.value)}
                      className={cn(
                        repoUrl.trim() && !isValidGitRepoUrl(repoUrl)
                          ? "border-amber-500"
                          : repoUrl.trim() && isValidGitRepoUrl(repoUrl)
                            ? "border-green-500"
                            : ""
                      )}
                    />
                    {repoUrl.trim() && (
                      <div className="absolute right-3 top-1/2 -translate-y-1/2">
                        {isValidGitRepoUrl(repoUrl) ? (
                          <CheckCircle2 className="h-5 w-5 text-green-600" />
                        ) : (
                          <AlertCircle className="h-5 w-5 text-amber-600" />
                        )}
                      </div>
                    )}
                  </div>
                  {repoUrl.trim() && !isValidGitRepoUrl(repoUrl) && (
                    <p className="text-xs text-amber-600 mt-1">
                      Enter a valid Git repository URL (e.g., https://github.com/owner/repo)
                    </p>
                  )}
                </div>
                <div>
                  <Label htmlFor="repo-branch" className="text-sm font-medium mb-2 block">
                    Branch <span className="text-xs text-slate-500">(optional)</span>
                  </Label>
                  <Input
                    id="repo-branch"
                    placeholder="e.g., main, develop"
                    value={repoBranch}
                    onChange={(e) => setRepoBranch(e.target.value)}
                  />
                </div>
              </CardContent>
            </Card>
          )}

          {/* File Upload */}
          {scanSource === "upload" && (
            <Card>
              <CardHeader>
                <CardTitle>Upload Code</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="border-2 border-dashed border-slate-300 rounded-lg p-8">
                  <label className="flex flex-col items-center justify-center cursor-pointer">
                    <input
                      type="file"
                      accept=".zip,.tar,.tar.gz,.tgz"
                      onChange={(e) => {
                        if (e.target.files?.[0]) {
                          setUploadedFile(e.target.files[0]);
                        }
                      }}
                      className="hidden"
                    />
                    <div className="text-center">
                      <Upload className="h-8 w-8 mx-auto mb-2 text-slate-400" />
                      <p className="font-medium text-sm mb-1">
                        {uploadedFile ? uploadedFile.name : "Click to upload or drag and drop"}
                      </p>
                      <p className="text-xs text-slate-500">
                        ZIP, TAR, TAR.GZ (Max 100MB)
                      </p>
                    </div>
                  </label>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Recent Scans */}
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Recent Scans</CardTitle>
              </div>
              <Button variant="link" size="sm" asChild>
                <a href="/scans">View all scans →</a>
              </Button>
            </CardHeader>
            <CardContent>
              {recentScans.length === 0 ? (
                <div className="py-8 text-center">
                  <p className="text-sm text-slate-500">No recent scans</p>
                </div>
              ) : (
                <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Repository</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Started At</TableHead>
                    <TableHead>Duration</TableHead>
                    <TableHead>Findings</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {Array.isArray(recentScans) && recentScans.map((scan) => {
                    const duration = scan.startedAt && scan.completedAt
                      ? Math.round((new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime()) / 1000)
                      : null;
                    return (
                      <TableRow key={scan.id}>
                        <TableCell>{scan.project?.name || "Unknown"}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-xs">
                            {scan.scanType || "FULL"}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={cn(
                              scan.status === "COMPLETED" && "bg-green-100 text-green-700",
                              scan.status === "FAILED" && "bg-red-100 text-red-700",
                              scan.status === "RUNNING" && "bg-blue-100 text-blue-700"
                            )}
                          >
                            {scan.status?.toLowerCase()}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm">
                          {scan.startedAt ? new Date(scan.startedAt).toLocaleDateString() : "—"}
                        </TableCell>
                        <TableCell className="text-sm">
                          {duration ? `${duration}s` : "—"}
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-1">
                            {scan.criticalCount > 0 && (
                              <Badge className="bg-red-100 text-red-700 text-xs">
                                {scan.criticalCount} Critical
                              </Badge>
                            )}
                            {scan.highCount > 0 && (
                              <Badge className="bg-orange-100 text-orange-700 text-xs">
                                {scan.highCount} High
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Right Column */}
        <div className="space-y-6">
          {/* Scan Summary */}
          <Card>
            <CardHeader className="flex flex-row items-start justify-between">
              <CardTitle>Scan Summary</CardTitle>
              {((scanSource === "github" || scanSource === "bitbucket" || scanSource === "azure") && selectedRepoId) ||
              (scanSource === "url" && repoUrl.trim()) ||
              (scanSource === "upload" && uploadedFile) ? (
                <Badge className="bg-green-100 text-green-700">Ready</Badge>
              ) : (
                <Badge variant="outline">Configure</Badge>
              )}
            </CardHeader>
            <CardContent className="space-y-3">
              {selectedRepo ? (
                <>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-600">Repository</span>
                    <span className="font-medium">{selectedRepo.name}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-600">Provider</span>
                    <span className="font-medium capitalize">{scanSource}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-600">Branch</span>
                    <span className="font-medium">{selectedBranch || selectedRepo.defaultBranch}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-600">Last Updated</span>
                    <span className="font-medium">
                      {selectedRepo.updatedAt ? new Date(selectedRepo.updatedAt).toLocaleDateString() : "Never"}
                    </span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-600">Visibility</span>
                    <span className="font-medium">{selectedRepo.private ? "Private" : "Public"}</span>
                  </div>
                </>
              ) : scanSource === "url" ? (
                <>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-600">Repository URL</span>
                    <span className="font-medium truncate max-w-xs">{repoUrl || "—"}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-600">Provider</span>
                    <span className="font-medium">Repository URL</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-600">Branch</span>
                    <span className="font-medium">{repoBranch || "default"}</span>
                  </div>
                </>
              ) : scanSource === "upload" ? (
                <>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-600">File</span>
                    <span className="font-medium truncate max-w-xs">{uploadedFile?.name || "—"}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-600">File Size</span>
                    <span className="font-medium">
                      {uploadedFile ? `${(uploadedFile.size / 1024 / 1024).toFixed(2)} MB` : "—"}
                    </span>
                  </div>
                </>
              ) : (
                <p className="text-sm text-slate-500">
                  {(scanSource === "github" || scanSource === "bitbucket" || scanSource === "azure")
                    ? "Select a repository to see details"
                    : "Configure source details above"}
                </p>
              )}
            </CardContent>
          </Card>

          {/* Start Scan */}
          <Card>
            <CardContent className="pt-6">
              <Button
                className="w-full"
                onClick={handleStartScan}
                disabled={
                  isScanning ||
                  ((scanSource === "github" || scanSource === "bitbucket" || scanSource === "azure") && !selectedRepoId) ||
                  (scanSource === "url" && (!repoUrl.trim() || !isValidGitRepoUrl(repoUrl))) ||
                  (scanSource === "upload" && !uploadedFile)
                }
              >
                {isScanning ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Starting...
                  </>
                ) : (
                  <>
                    <Play className="mr-2 h-4 w-4" />
                    Start Scan
                  </>
                )}
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
