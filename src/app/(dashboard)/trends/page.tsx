"use client";

import { useEffect, useState } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
} from "recharts";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

interface TrendsResponse {
  days: number;
  series: {
    date: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    scans: number;
    gateFailed: number;
  }[];
  mttr: Record<string, { count: number; meanHours: number }>;
}

const SEV_COLORS = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
};

export default function TrendsPage() {
  const [days, setDays] = useState(30);
  const [data, setData] = useState<TrendsResponse | null>(null);
  const [loading, setLoading] = useState(true);

  async function load(d: number) {
    setLoading(true);
    try {
      const res = await fetch(`/api/dashboard/trends?days=${d}`);
      if (res.ok) setData((await res.json()) as TrendsResponse);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load(days);
  }, [days]);

  const series = data?.series || [];

  return (
    <div className="space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Trends" },
        ]}
      />
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Trends</h1>
          <p className="text-muted-foreground">
            Severity and gate trends across all projects in this organization.
          </p>
        </div>
        <Select value={String(days)} onValueChange={(v) => setDays(parseInt(v, 10))}>
          <SelectTrigger className="w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="7">Last 7 days</SelectItem>
            <SelectItem value="30">Last 30 days</SelectItem>
            <SelectItem value="90">Last 90 days</SelectItem>
            <SelectItem value="180">Last 180 days</SelectItem>
            <SelectItem value="365">Last year</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Findings by severity</CardTitle>
          <CardDescription>
            Stacked daily severity counts (latest scan per project per day).
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={series}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
                  <XAxis dataKey="date" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Area
                    type="monotone"
                    dataKey="critical"
                    stackId="1"
                    stroke={SEV_COLORS.critical}
                    fill={SEV_COLORS.critical}
                  />
                  <Area
                    type="monotone"
                    dataKey="high"
                    stackId="1"
                    stroke={SEV_COLORS.high}
                    fill={SEV_COLORS.high}
                  />
                  <Area
                    type="monotone"
                    dataKey="medium"
                    stackId="1"
                    stroke={SEV_COLORS.medium}
                    fill={SEV_COLORS.medium}
                  />
                  <Area
                    type="monotone"
                    dataKey="low"
                    stackId="1"
                    stroke={SEV_COLORS.low}
                    fill={SEV_COLORS.low}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Build gate failures</CardTitle>
          <CardDescription>
            Number of scans whose build gate failed each day.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={series}>
                <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
                <XAxis dataKey="date" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Line type="monotone" dataKey="gateFailed" stroke={SEV_COLORS.critical} />
                <Line type="monotone" dataKey="scans" stroke="#94a3b8" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Mean time to resolve</CardTitle>
          <CardDescription>
            How long open findings stay open before being marked resolved.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => {
            const v = data?.mttr[sev];
            return (
              <div key={sev} className="rounded-lg border p-4">
                <div className="text-xs uppercase text-muted-foreground">
                  {sev}
                </div>
                <div className="text-xl font-semibold">
                  {v ? `${v.meanHours.toFixed(1)} h` : "—"}
                </div>
                <div className="text-xs text-muted-foreground">
                  {v ? `${v.count} resolved` : "no data"}
                </div>
              </div>
            );
          })}
        </CardContent>
      </Card>
    </div>
  );
}
