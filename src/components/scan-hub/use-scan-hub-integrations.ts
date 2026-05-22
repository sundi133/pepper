"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { toast } from "sonner";
import type {
  AzureConnectedRepo,
  AzureDevOpsStatus,
  BitbucketConnectedRepo,
  BitbucketStatus,
  GithubConnectedRepo,
  GithubStatus,
  RepoProvider,
  UnifiedConnectedRepo,
} from "./types";

const SCAN_HUB_PATH = "/scans/new";

type GithubAvailableRepo = {
  id: number;
  fullName: string;
  defaultBranch: string;
  language: string | null;
  private: boolean;
  alreadyConnected: boolean;
};

type BitbucketAvailableRepo = {
  uuid: string;
  fullName: string;
  defaultBranch: string;
  language: string | null;
  private: boolean;
  alreadyConnected: boolean;
};

type AzureAvailableRepo = {
  id: string;
  fullName: string;
  defaultBranch: string;
  alreadyConnected: boolean;
};

export function useScanHubIntegrations() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [provider, setProvider] = useState<RepoProvider>("github");
  const [status, setStatus] = useState<GithubStatus | null>(null);
  const [connected, setConnected] = useState<GithubConnectedRepo[]>([]);
  const [loading, setLoading] = useState(true);
  const [pickOpen, setPickOpen] = useState(false);
  const [pickLoading, setPickLoading] = useState(false);
  const [pickLoaded, setPickLoaded] = useState(false);
  const [pickRefreshing, setPickRefreshing] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [available, setAvailable] = useState<GithubAvailableRepo[]>([]);
  const [manualRepoUrl, setManualRepoUrl] = useState("");
  const [manualBranch, setManualBranch] = useState("");
  const [manualConnecting, setManualConnecting] = useState(false);

  const [bitbucketStatus, setBitbucketStatus] = useState<BitbucketStatus | null>(
    null,
  );
  const [bitbucketConnected, setBitbucketConnected] = useState<
    BitbucketConnectedRepo[]
  >([]);
  const [bitbucketPickOpen, setBitbucketPickOpen] = useState(false);
  const [bitbucketPickLoading, setBitbucketPickLoading] = useState(false);
  const [bitbucketPickLoaded, setBitbucketPickLoaded] = useState(false);
  const [bitbucketPickRefreshing, setBitbucketPickRefreshing] = useState(false);
  const [bitbucketConnecting, setBitbucketConnecting] = useState(false);
  const [bitbucketSelected, setBitbucketSelected] = useState<Set<string>>(
    new Set(),
  );
  const [bitbucketAvailable, setBitbucketAvailable] = useState<
    BitbucketAvailableRepo[]
  >([]);
  const [bitbucketManualUrl, setBitbucketManualUrl] = useState("");
  const [bitbucketManualBranch, setBitbucketManualBranch] = useState("");
  const [bitbucketManualConnecting, setBitbucketManualConnecting] =
    useState(false);

  const [azureStatus, setAzureStatus] = useState<AzureDevOpsStatus | null>(null);
  const [azureConnected, setAzureConnected] = useState<AzureConnectedRepo[]>([]);
  const [azurePickOpen, setAzurePickOpen] = useState(false);
  const [azurePickLoading, setAzurePickLoading] = useState(false);
  const [azurePickLoaded, setAzurePickLoaded] = useState(false);
  const [azurePickRefreshing, setAzurePickRefreshing] = useState(false);
  const [azureConnecting, setAzureConnecting] = useState(false);
  const [azureSelected, setAzureSelected] = useState<Set<string>>(new Set());
  const [azureAvailable, setAzureAvailable] = useState<AzureAvailableRepo[]>([]);
  const [azureManualUrl, setAzureManualUrl] = useState("");
  const [azureManualBranch, setAzureManualBranch] = useState("");
  const [azureManualConnecting, setAzureManualConnecting] = useState(false);

  const [providerFilter, setProviderFilter] = useState<"all" | RepoProvider>(
    "all",
  );
  const [searchQuery, setSearchQuery] = useState("");

  const githubQuery = searchParams.get("github");
  const pickQuery = searchParams.get("pick");
  const errorMessage = searchParams.get("message");

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    try {
      const [statusRes, connectedRes] = await Promise.all([
        fetch("/api/integrations/github"),
        fetch("/api/integrations/github/repositories/connected"),
      ]);
      const statusJson = (await statusRes.json()) as GithubStatus & {
        error?: string;
      };
      const connectedJson = (await connectedRes.json()) as {
        repositories?: Omit<GithubConnectedRepo, "provider">[];
        error?: string;
      };
      if (!statusRes.ok) {
        throw new Error(statusJson.error || "Failed to load GitHub status");
      }
      if (!connectedRes.ok) {
        throw new Error(connectedJson.error || "Failed to load repositories");
      }
      setStatus(statusJson);
      setConnected(
        (connectedJson.repositories ?? []).map((r) => ({
          ...r,
          provider: "github" as const,
        })),
      );
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : "Failed to load repositories",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  const loadAvailable = useCallback(async (opts?: { quiet?: boolean }) => {
    if (opts?.quiet) setPickRefreshing(true);
    else setPickLoading(true);
    try {
      const res = await fetch("/api/integrations/github/repositories");
      const json = (await res.json()) as {
        repositories?: GithubAvailableRepo[];
        error?: string;
        code?: string;
      };
      if (!res.ok) {
        if (json.code === "GITHUB_TOKEN_INVALID") {
          setStatus((s) => (s ? { ...s, connected: false } : s));
        }
        throw new Error(json.error || "Failed to list GitHub repositories");
      }
      setAvailable(json.repositories ?? []);
      setPickLoaded(true);
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : "Failed to list repositories",
      );
      setAvailable([]);
      setPickLoaded(true);
    } finally {
      setPickLoading(false);
      setPickRefreshing(false);
    }
  }, []);

  const loadBitbucketDashboard = useCallback(async () => {
    try {
      const [statusRes, connectedRes] = await Promise.all([
        fetch("/api/integrations/bitbucket/connect"),
        fetch("/api/integrations/bitbucket/repositories/connected"),
      ]);
      const statusJson = (await statusRes.json()) as BitbucketStatus & {
        error?: string;
      };
      const connectedJson = (await connectedRes.json()) as {
        repositories?: Omit<BitbucketConnectedRepo, "provider">[];
        error?: string;
      };
      if (!statusRes.ok) {
        throw new Error(statusJson.error || "Failed to load Bitbucket status");
      }
      if (!connectedRes.ok) {
        throw new Error(
          connectedJson.error || "Failed to load Bitbucket repositories",
        );
      }
      setBitbucketStatus(statusJson);
      setBitbucketConnected(
        (connectedJson.repositories ?? []).map((r) => ({
          ...r,
          provider: "bitbucket" as const,
        })),
      );
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : "Failed to load Bitbucket repositories",
      );
    }
  }, []);

  const loadBitbucketAvailable = useCallback(async (opts?: { quiet?: boolean }) => {
    if (opts?.quiet) setBitbucketPickRefreshing(true);
    else setBitbucketPickLoading(true);
    try {
      const res = await fetch("/api/integrations/bitbucket/repositories");
      const json = (await res.json()) as {
        repositories?: BitbucketAvailableRepo[];
        error?: string;
        code?: string;
      };
      if (!res.ok) {
        if (json.code === "BITBUCKET_CREDENTIALS_INVALID") {
          setBitbucketStatus((s) => (s ? { ...s, connected: false } : s));
        }
        throw new Error(json.error || "Failed to list Bitbucket repositories");
      }
      setBitbucketAvailable(json.repositories ?? []);
      setBitbucketPickLoaded(true);
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : "Failed to list Bitbucket repositories",
      );
      setBitbucketAvailable([]);
      setBitbucketPickLoaded(true);
    } finally {
      setBitbucketPickLoading(false);
      setBitbucketPickRefreshing(false);
    }
  }, []);

  const loadAzureDashboard = useCallback(async () => {
    try {
      const [statusRes, connectedRes] = await Promise.all([
        fetch("/api/integrations/azure-devops/connect"),
        fetch("/api/integrations/azure-devops/repositories/connected"),
      ]);
      const statusJson = (await statusRes.json()) as AzureDevOpsStatus & {
        error?: string;
      };
      const connectedJson = (await connectedRes.json()) as {
        repositories?: Omit<AzureConnectedRepo, "provider">[];
        error?: string;
      };
      if (!statusRes.ok) {
        throw new Error(statusJson.error || "Failed to load Azure DevOps status");
      }
      if (!connectedRes.ok) {
        throw new Error(
          connectedJson.error || "Failed to load Azure DevOps repositories",
        );
      }
      setAzureStatus(statusJson);
      setAzureConnected(
        (connectedJson.repositories ?? []).map((r) => ({
          ...r,
          provider: "azure" as const,
        })),
      );
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : "Failed to load Azure DevOps repositories",
      );
    }
  }, []);

  const loadAzureAvailable = useCallback(async (opts?: { quiet?: boolean }) => {
    if (opts?.quiet) setAzurePickRefreshing(true);
    else setAzurePickLoading(true);
    try {
      const res = await fetch("/api/integrations/azure-devops/repositories");
      const json = (await res.json()) as {
        repositories?: AzureAvailableRepo[];
        error?: string;
        code?: string;
      };
      if (!res.ok) {
        if (json.code === "AZURE_DEVOPS_CREDENTIALS_INVALID") {
          setAzureStatus((s) => (s ? { ...s, connected: false } : s));
        }
        throw new Error(json.error || "Failed to list Azure DevOps repositories");
      }
      setAzureAvailable(json.repositories ?? []);
      setAzurePickLoaded(true);
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : "Failed to list Azure DevOps repositories",
      );
      setAzureAvailable([]);
      setAzurePickLoaded(true);
    } finally {
      setAzurePickLoading(false);
      setAzurePickRefreshing(false);
    }
  }, []);

  const refreshAll = useCallback(async () => {
    await Promise.all([
      loadDashboard(),
      loadBitbucketDashboard(),
      loadAzureDashboard(),
    ]);
  }, [loadDashboard, loadBitbucketDashboard, loadAzureDashboard]);

  useEffect(() => {
    void refreshAll();
  }, [refreshAll]);

  const hasActiveGithubScan = connected.some(
    (r) => r.scanStatus === "SCANNING" || r.scanStatus === "PENDING",
  );
  const hasActiveBitbucketScan = bitbucketConnected.some(
    (r) => r.scanStatus === "SCANNING" || r.scanStatus === "PENDING",
  );
  const hasActiveAzureScan = azureConnected.some(
    (r) => r.scanStatus === "SCANNING" || r.scanStatus === "PENDING",
  );

  useEffect(() => {
    if (!hasActiveGithubScan) return;
    const t = window.setInterval(() => void loadDashboard(), 5000);
    return () => window.clearInterval(t);
  }, [hasActiveGithubScan, loadDashboard]);

  useEffect(() => {
    if (!hasActiveBitbucketScan) return;
    const t = window.setInterval(() => void loadBitbucketDashboard(), 5000);
    return () => window.clearInterval(t);
  }, [hasActiveBitbucketScan, loadBitbucketDashboard]);

  useEffect(() => {
    if (!hasActiveAzureScan) return;
    const t = window.setInterval(() => void loadAzureDashboard(), 5000);
    return () => window.clearInterval(t);
  }, [hasActiveAzureScan, loadAzureDashboard]);

  useEffect(() => {
    if (githubQuery === "connected") {
      toast.success("GitHub connected successfully");
      router.replace(SCAN_HUB_PATH, { scroll: false });
    } else if (githubQuery === "error") {
      toast.error(
        errorMessage
          ? decodeURIComponent(errorMessage)
          : "GitHub authorization failed",
      );
      router.replace(SCAN_HUB_PATH, { scroll: false });
    }
  }, [githubQuery, errorMessage, router]);

  useEffect(() => {
    if (pickQuery === "1" && status?.connected) {
      setPickOpen(true);
      void loadAvailable();
      router.replace(SCAN_HUB_PATH, { scroll: false });
    }
  }, [pickQuery, status?.connected, loadAvailable, router]);

  const allConnected = useMemo((): UnifiedConnectedRepo[] => {
    return [...connected, ...bitbucketConnected, ...azureConnected].sort(
      (a, b) => {
        const ta = a.lastScanAt ? new Date(a.lastScanAt).getTime() : 0;
        const tb = b.lastScanAt ? new Date(b.lastScanAt).getTime() : 0;
        return tb - ta;
      },
    );
  }, [connected, bitbucketConnected, azureConnected]);

  const filteredConnected = useMemo(() => {
    let list = allConnected;
    if (providerFilter !== "all") {
      list = list.filter((r) => r.provider === providerFilter);
    }
    const q = searchQuery.trim().toLowerCase();
    if (q) {
      list = list.filter(
        (r) =>
          r.name.toLowerCase().includes(q) ||
          r.fullName.toLowerCase().includes(q),
      );
    }
    return list;
  }, [allConnected, providerFilter, searchQuery]);

  const stats = useMemo(() => {
    const scanning = allConnected.filter(
      (r) => r.scanStatus === "SCANNING" || r.scanStatus === "PENDING",
    ).length;
    const withIssues = allConnected.filter(
      (r) => r.scanStatus === "ISSUES" || r.findingsCount > 0,
    ).length;
    return {
      total: allConnected.length,
      scanning,
      withIssues,
    };
  }, [allConnected]);

  const importable = useMemo(
    () => available.filter((r) => !r.alreadyConnected),
    [available],
  );
  const bitbucketImportable = useMemo(
    () => bitbucketAvailable.filter((r) => !r.alreadyConnected),
    [bitbucketAvailable],
  );
  const azureImportable = useMemo(
    () => azureAvailable.filter((r) => !r.alreadyConnected),
    [azureAvailable],
  );

  function connectGithub() {
    window.location.href = `/api/integrations/github/connect?returnTo=${encodeURIComponent(SCAN_HUB_PATH)}`;
  }

  async function disconnectGithub() {
    if (
      !window.confirm(
        "Disconnect GitHub? Import and private clone stop until you connect again.",
      )
    ) {
      return;
    }
    setDisconnecting(true);
    try {
      const res = await fetch("/api/integrations/github", { method: "DELETE" });
      const json = (await res.json()) as { error?: string };
      if (!res.ok) throw new Error(json.error || "Failed to disconnect");
      toast.success("GitHub disconnected");
      setStatus((s) =>
        s ? { ...s, connected: false, githubLogin: null } : s,
      );
      setPickOpen(false);
      setAvailable([]);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to disconnect");
    } finally {
      setDisconnecting(false);
    }
  }

  async function importSelected() {
    if (selected.size === 0) return;
    setConnecting(true);
    try {
      const res = await fetch("/api/integrations/github/repositories/connect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoIds: Array.from(selected) }),
      });
      const json = (await res.json()) as {
        connected?: { fullName: string }[];
        error?: string;
      };
      if (!res.ok) {
        throw new Error(json.error || "Failed to connect repositories");
      }
      const n = json.connected?.length ?? 0;
      toast.success(
        n > 0
          ? `Connected ${n} repositor${n === 1 ? "y" : "ies"} and queued scan${n === 1 ? "" : "s"}`
          : "No new repositories were connected",
      );
      setSelected(new Set());
      setPickOpen(false);
      await loadDashboard();
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : "Failed to connect repositories",
      );
    } finally {
      setConnecting(false);
    }
  }

  function openGithubPicker() {
    setPickOpen(true);
    setSelected(new Set());
    setPickLoaded(false);
    setAvailable([]);
    void loadAvailable();
  }

  function onPickOpenChange(open: boolean) {
    setPickOpen(open);
    if (!open) {
      setPickLoaded(false);
      setPickRefreshing(false);
      setAvailable([]);
      setSelected(new Set());
    }
  }

  async function connectManualRepo() {
    const url = manualRepoUrl.trim();
    if (!url) {
      toast.error("Enter a GitHub repository URL or owner/repo");
      return;
    }
    if (!status?.connected) {
      window.location.href = `/api/integrations/github/connect?returnTo=${encodeURIComponent(SCAN_HUB_PATH)}`;
      return;
    }
    setManualConnecting(true);
    try {
      const res = await fetch(
        "/api/integrations/github/repositories/connect-manual",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            repoUrl: url,
            branch: manualBranch.trim() || undefined,
          }),
        },
      );
      const json = (await res.json()) as {
        error?: string;
        code?: string;
        fullName?: string;
        created?: boolean;
      };
      if (!res.ok) {
        if (json.code === "GITHUB_OAUTH_REQUIRED") {
          window.location.href = `/api/integrations/github/connect?returnTo=${encodeURIComponent(SCAN_HUB_PATH)}`;
          return;
        }
        throw new Error(json.error || "Failed to connect repository");
      }
      toast.success(
        json.created
          ? `Connected ${json.fullName} and queued scan`
          : `Rescanned ${json.fullName}`,
      );
      setManualRepoUrl("");
      setManualBranch("");
      await loadDashboard();
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : "Failed to connect repository",
      );
    } finally {
      setManualConnecting(false);
    }
  }

  function openBitbucketPicker() {
    setBitbucketPickOpen(true);
    setBitbucketSelected(new Set());
    setBitbucketPickLoaded(false);
    setBitbucketAvailable([]);
    void loadBitbucketAvailable();
  }

  function onBitbucketPickOpenChange(open: boolean) {
    setBitbucketPickOpen(open);
    if (!open) {
      setBitbucketPickLoaded(false);
      setBitbucketPickRefreshing(false);
      setBitbucketAvailable([]);
      setBitbucketSelected(new Set());
    }
  }

  function openAzurePicker() {
    setAzurePickOpen(true);
    setAzureSelected(new Set());
    setAzurePickLoaded(false);
    setAzureAvailable([]);
    void loadAzureAvailable();
  }

  function onAzurePickOpenChange(open: boolean) {
    setAzurePickOpen(open);
    if (!open) {
      setAzurePickLoaded(false);
      setAzurePickRefreshing(false);
      setAzureAvailable([]);
      setAzureSelected(new Set());
    }
  }

  async function importBitbucketSelected() {
    const toImport = bitbucketAvailable.filter(
      (r) => bitbucketSelected.has(r.uuid) && !r.alreadyConnected,
    );
    if (toImport.length === 0) return;
    setBitbucketConnecting(true);
    try {
      const res = await fetch(
        "/api/integrations/bitbucket/repositories/connect",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ repoUuids: toImport.map((r) => r.uuid) }),
        },
      );
      const json = (await res.json()) as {
        connected?: { fullName: string }[];
        error?: string;
      };
      if (!res.ok) {
        throw new Error(json.error || "Failed to connect repositories");
      }
      const n = json.connected?.length ?? 0;
      toast.success(
        n > 0
          ? `Connected ${n} Bitbucket repositor${n === 1 ? "y" : "ies"} and queued scan${n === 1 ? "" : "s"}`
          : "No new Bitbucket repositories were connected",
      );
      setBitbucketSelected(new Set());
      setBitbucketPickOpen(false);
      await loadBitbucketDashboard();
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : "Failed to connect Bitbucket repositories",
      );
    } finally {
      setBitbucketConnecting(false);
    }
  }

  async function connectBitbucketManualRepo() {
    const url = bitbucketManualUrl.trim();
    if (!url) {
      toast.error("Enter a Bitbucket repository URL or workspace/repo-slug");
      return;
    }
    if (!bitbucketStatus?.connected) {
      router.push("/settings/integrations");
      return;
    }
    setBitbucketManualConnecting(true);
    try {
      const res = await fetch(
        "/api/integrations/bitbucket/repositories/connect-manual",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            repoUrl: url,
            branch: bitbucketManualBranch.trim() || undefined,
          }),
        },
      );
      const json = (await res.json()) as {
        error?: string;
        code?: string;
        fullName?: string;
        created?: boolean;
      };
      if (!res.ok) {
        if (json.code === "BITBUCKET_NOT_CONNECTED") {
          router.push("/settings/integrations");
          return;
        }
        throw new Error(json.error || "Failed to connect repository");
      }
      toast.success(
        json.created
          ? `Connected ${json.fullName} and queued scan`
          : `Updated ${json.fullName} (already connected)`,
      );
      setBitbucketManualUrl("");
      setBitbucketManualBranch("");
      await loadBitbucketDashboard();
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : "Failed to connect Bitbucket repository",
      );
    } finally {
      setBitbucketManualConnecting(false);
    }
  }

  async function importAzureSelected() {
    const toImport = azureAvailable.filter(
      (r) => azureSelected.has(r.id) && !r.alreadyConnected,
    );
    if (toImport.length === 0) return;
    setAzureConnecting(true);
    try {
      const res = await fetch(
        "/api/integrations/azure-devops/repositories/connect",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ repoIds: toImport.map((r) => r.id) }),
        },
      );
      const json = (await res.json()) as {
        connected?: { fullName: string }[];
        error?: string;
      };
      if (!res.ok) {
        throw new Error(json.error || "Failed to connect repositories");
      }
      const n = json.connected?.length ?? 0;
      toast.success(
        n > 0
          ? `Connected ${n} Azure DevOps repositor${n === 1 ? "y" : "ies"} and queued scan${n === 1 ? "" : "s"}`
          : "No new Azure DevOps repositories were connected",
      );
      setAzureSelected(new Set());
      setAzurePickOpen(false);
      await loadAzureDashboard();
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : "Failed to connect Azure DevOps repositories",
      );
    } finally {
      setAzureConnecting(false);
    }
  }

  async function connectAzureManualRepo() {
    const url = azureManualUrl.trim();
    if (!url) {
      toast.error("Enter an Azure DevOps repository URL or project/repo");
      return;
    }
    if (!azureStatus?.connected) {
      router.push("/settings/integrations");
      return;
    }
    setAzureManualConnecting(true);
    try {
      const res = await fetch(
        "/api/integrations/azure-devops/repositories/connect-manual",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            repoUrl: url,
            branch: azureManualBranch.trim() || undefined,
          }),
        },
      );
      const json = (await res.json()) as {
        error?: string;
        code?: string;
        fullName?: string;
        created?: boolean;
      };
      if (!res.ok) {
        if (json.code === "AZURE_DEVOPS_NOT_CONNECTED") {
          router.push("/settings/integrations");
          return;
        }
        throw new Error(json.error || "Failed to connect repository");
      }
      toast.success(
        json.created
          ? `Connected ${json.fullName} and queued scan`
          : `Updated ${json.fullName} (already connected)`,
      );
      setAzureManualUrl("");
      setAzureManualBranch("");
      await loadAzureDashboard();
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : "Failed to connect Azure DevOps repository",
      );
    } finally {
      setAzureManualConnecting(false);
    }
  }

  /** Smart URL: route to the right provider connect-manual handler. */
  async function connectSmartRepoUrl(
    url: string,
    branch: string,
  ): Promise<"done" | "adhoc"> {
    const trimmed = url.trim();
    if (!trimmed) {
      toast.error("Enter a repository URL or slug");
      return "done";
    }
    const { detectRepoProviderFromInput } = await import(
      "@/lib/detect-repo-provider"
    );
    const hint = detectRepoProviderFromInput(
      trimmed,
      azureStatus?.azureOrganization,
    );

    if (hint === "bitbucket") {
      if (!bitbucketStatus?.connected) {
        router.push("/settings/integrations");
        return "done";
      }
      setBitbucketManualConnecting(true);
      try {
        const res = await fetch(
          "/api/integrations/bitbucket/repositories/connect-manual",
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              repoUrl: trimmed,
              branch: branch.trim() || undefined,
            }),
          },
        );
        const json = (await res.json()) as {
          error?: string;
          fullName?: string;
          created?: boolean;
        };
        if (!res.ok) throw new Error(json.error || "Failed to connect repository");
        toast.success(
          json.created
            ? `Connected ${json.fullName} and queued scan`
            : `Updated ${json.fullName}`,
        );
        await loadBitbucketDashboard();
      } catch (e) {
        toast.error(
          e instanceof Error ? e.message : "Failed to connect repository",
        );
      } finally {
        setBitbucketManualConnecting(false);
      }
      return "done";
    }

    if (hint === "azure") {
      if (!azureStatus?.connected) {
        router.push("/settings/integrations");
        return "done";
      }
      setAzureManualConnecting(true);
      try {
        const res = await fetch(
          "/api/integrations/azure-devops/repositories/connect-manual",
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              repoUrl: trimmed,
              branch: branch.trim() || undefined,
            }),
          },
        );
        const json = (await res.json()) as {
          error?: string;
          fullName?: string;
          created?: boolean;
        };
        if (!res.ok) throw new Error(json.error || "Failed to connect repository");
        toast.success(
          json.created
            ? `Connected ${json.fullName} and queued scan`
            : `Updated ${json.fullName}`,
        );
        await loadAzureDashboard();
      } catch (e) {
        toast.error(
          e instanceof Error ? e.message : "Failed to connect repository",
        );
      } finally {
        setAzureManualConnecting(false);
      }
      return "done";
    }

    if (hint === "generic" || hint === null) {
      return "adhoc";
    }

    if (hint === "github") {
      if (!status?.connected) {
        window.location.href = `/api/integrations/github/connect?returnTo=${encodeURIComponent(SCAN_HUB_PATH)}`;
        return "done";
      }
      setManualConnecting(true);
      try {
        const res = await fetch(
          "/api/integrations/github/repositories/connect-manual",
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              repoUrl: trimmed,
              branch: branch.trim() || undefined,
            }),
          },
        );
        const json = (await res.json()) as {
          error?: string;
          code?: string;
          fullName?: string;
          created?: boolean;
        };
        if (!res.ok) {
          if (json.code === "GITHUB_OAUTH_REQUIRED") {
            window.location.href = `/api/integrations/github/connect?returnTo=${encodeURIComponent(SCAN_HUB_PATH)}`;
            return "done";
          }
          throw new Error(json.error || "Failed to connect repository");
        }
        toast.success(
          json.created
            ? `Connected ${json.fullName} and queued scan`
            : `Rescanned ${json.fullName}`,
        );
        await loadDashboard();
      } catch (e) {
        toast.error(
          e instanceof Error ? e.message : "Failed to connect repository",
        );
      } finally {
        setManualConnecting(false);
      }
      return "done";
    }

    return "adhoc";
  }

  async function createAdHocGitScan(
    url: string,
    branch: string,
    scanType: string = "FULL",
  ) {
    const formData = new FormData();
    formData.append(
      "data",
      JSON.stringify({
        scanType,
        repoUrl: url,
        branch: branch.trim() || undefined,
      }),
    );
    const res = await fetch("/api/scans", { method: "POST", body: formData });
    if (!res.ok) {
      const err = (await res.json()) as { error?: string };
      throw new Error(err.error || "Failed to create scan");
    }
    const result = (await res.json()) as { scanId: string };
    return result.scanId;
  }

  return {
    provider,
    setProvider,
    providerFilter,
    setProviderFilter,
    searchQuery,
    setSearchQuery,
    status,
    connected,
    loading,
    pickOpen,
    pickLoading,
    pickLoaded,
    pickRefreshing,
    connecting,
    disconnecting,
    selected,
    setSelected,
    available,
    importable,
    manualRepoUrl,
    setManualRepoUrl,
    manualBranch,
    setManualBranch,
    manualConnecting,
    bitbucketStatus,
    bitbucketConnected,
    bitbucketPickOpen,
    bitbucketPickLoading,
    bitbucketPickLoaded,
    bitbucketPickRefreshing,
    bitbucketConnecting,
    bitbucketSelected,
    setBitbucketSelected,
    bitbucketAvailable,
    bitbucketImportable,
    bitbucketManualUrl,
    setBitbucketManualUrl,
    bitbucketManualBranch,
    setBitbucketManualBranch,
    bitbucketManualConnecting,
    azureStatus,
    azureConnected,
    azurePickOpen,
    azurePickLoading,
    azurePickLoaded,
    azurePickRefreshing,
    azureConnecting,
    azureSelected,
    setAzureSelected,
    azureAvailable,
    azureImportable,
    azureManualUrl,
    setAzureManualUrl,
    azureManualBranch,
    setAzureManualBranch,
    azureManualConnecting,
    allConnected,
    filteredConnected,
    stats,
    refreshAll,
    loadDashboard,
    loadAvailable,
    loadBitbucketAvailable,
    loadAzureAvailable,
    connectGithub,
    disconnectGithub,
    importSelected,
    openGithubPicker,
    onPickOpenChange,
    setPickOpen,
    connectManualRepo,
    connectSmartRepoUrl,
    createAdHocGitScan,
    openBitbucketPicker,
    onBitbucketPickOpenChange,
    importBitbucketSelected,
    connectBitbucketManualRepo,
    openAzurePicker,
    onAzurePickOpenChange,
    importAzureSelected,
    connectAzureManualRepo,
    router,
  };
}
