"use client";

import useSWR from "swr";

const fetcher = (url: string) => fetch(url).then((res) => res.json());

export function useScanPolling(scanId: string | null) {
  const { data, error, isLoading } = useSWR(
    scanId ? `/api/scans/${scanId}` : null,
    fetcher,
    {
      refreshInterval: (data) => {
        if (!data) return 3000;
        if (data.status === "QUEUED" || data.status === "RUNNING") return 3000;
        return 0; // stop polling when complete
      },
    }
  );

  return { scan: data, error, isLoading };
}

export function useScans(projectId?: string, page = 1) {
  const params = new URLSearchParams({ page: String(page), limit: "20" });
  if (projectId) params.set("projectId", projectId);

  const { data, error, isLoading, mutate } = useSWR(
    `/api/scans?${params}`,
    fetcher,
    { refreshInterval: 30000 }
  );

  return {
    scans: data?.scans || [],
    pagination: data?.pagination,
    error,
    isLoading,
    refresh: mutate,
  };
}

export function useProjects() {
  const { data, error, isLoading, mutate } = useSWR(
    "/api/projects",
    fetcher,
    { refreshInterval: 60000 }
  );

  return {
    projects: data?.projects || [],
    error,
    isLoading,
    refresh: mutate,
  };
}

export function useFindings(scanId: string, filters?: Record<string, string>, scanStatus?: string) {
  const params = new URLSearchParams({ page: "1", limit: "100", ...filters });
  const isActive = scanStatus === "QUEUED" || scanStatus === "RUNNING";

  const { data, error, isLoading } = useSWR(
    `/api/scans/${scanId}/findings?${params}`,
    fetcher,
    {
      refreshInterval: isActive ? 3000 : 0,
    }
  );

  return {
    findings: data?.findings || [],
    pagination: data?.pagination,
    error,
    isLoading,
  };
}
