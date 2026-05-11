"use client";

import useSWR from "swr";
import { jsonFetcher } from "@/lib/fetcher";

export function useScanPolling(scanId: string | null) {
  const { data, error, isLoading } = useSWR(
    scanId ? `/api/scans/${scanId}` : null,
    jsonFetcher,
    {
      refreshInterval: (data) => {
        if (!data) return 3000;
        if (
          data.status === "QUEUED" ||
          data.status === "RUNNING" ||
          data.status === "PAUSED"
        )
          return 3000;
        return 0; // stop polling when complete
      },
    },
  );

  return { scan: data, error, isLoading };
}

export function useScans(projectId?: string, page = 1) {
  const params = new URLSearchParams({ page: String(page), limit: "20" });
  if (projectId) params.set("projectId", projectId);

  const { data, error, isLoading, mutate } = useSWR(
    `/api/scans?${params}`,
    jsonFetcher,
    { refreshInterval: 30000 },
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
    jsonFetcher,
    {
      refreshInterval: 60000,
    },
  );

  return {
    projects: data?.projects || [],
    error,
    isLoading,
    refresh: mutate,
  };
}

export function useFindings(
  scanId: string,
  filters?: Record<string, string>,
  scanStatus?: string,
) {
  const params = new URLSearchParams({ page: "1", limit: "500", ...filters });
  const isActive =
    scanStatus === "QUEUED" ||
    scanStatus === "RUNNING" ||
    scanStatus === "PAUSED";

  const { data, error, isLoading, mutate } = useSWR(
    `/api/scans/${scanId}/findings?${params}`,
    jsonFetcher,
    {
      refreshInterval: isActive ? 3000 : 0,
    },
  );

  return {
    findings: data?.findings || [],
    pagination: data?.pagination,
    error,
    isLoading,
    refresh: mutate,
  };
}
