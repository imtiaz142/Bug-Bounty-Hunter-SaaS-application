"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  PlusCircle,
  Target,
  Activity,
} from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import Layout from "@/components/layout/Layout";
import api from "@/lib/api";
import type { Scan } from "@/types";

const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#dc2626",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#06b6d4",
  Info: "#6b7280",
};

export default function DashboardPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [stats, setStats] = useState({
    total_scans: 0,
    running: 0,
    completed: 0,
    total_findings: 0,
    severity_data: [] as { label: string; value: number }[],
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async () => {
    try {
      const scansRes = await api.get("/scans", { params: { per_page: 5 } });
      const scansList: Scan[] = scansRes.data.data.scans;
      setScans(scansList);

      // Aggregate stats from scans
      let running = 0;
      let completed = 0;
      const allSeverity = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
      let totalFindings = 0;

      for (const scan of scansList) {
        if (scan.status === "running" || scan.status === "queued") running++;
        if (scan.status === "completed") completed++;
      }

      // Try to get findings summary from the most recent completed scan
      const completedScans = scansList.filter((s) => s.status === "completed");
      for (const scan of completedScans.slice(0, 3)) {
        try {
          const summaryRes = await api.get(`/scans/${scan.id}/findings/summary`);
          const summary = summaryRes.data.data.summary;
          totalFindings += summary.total;
          allSeverity.Critical += summary.critical;
          allSeverity.High += summary.high;
          allSeverity.Medium += summary.medium;
          allSeverity.Low += summary.low;
          allSeverity.Info += summary.info;
        } catch {
          // Scan may not have findings
        }
      }

      setStats({
        total_scans: scansRes.data.data.total,
        running,
        completed,
        total_findings: totalFindings,
        severity_data: Object.entries(allSeverity).map(([label, value]) => ({
          label,
          value,
        })),
      });
    } catch {
      // Silently fail on dashboard load
    } finally {
      setLoading(false);
    }
  };

  const statusColor = (status: string) => {
    switch (status) {
      case "completed":
        return "text-green-600";
      case "running":
      case "queued":
        return "text-yellow-600";
      case "failed":
        return "text-red-600";
      case "cancelled":
        return "text-gray-400";
      default:
        return "text-gray-400";
    }
  };

  if (loading) {
    return (
      <Layout>
        <div className="flex h-64 items-center justify-center">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-indigo-500 border-t-transparent" />
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      {/* Quick action */}
      <div className="mb-6 flex items-center justify-between">
        <h2 className="text-xl font-semibold text-gray-900">Overview</h2>
        <Link href="/scans/new" className="btn-primary gap-2">
          <PlusCircle className="h-4 w-4" />
          New Scan
        </Link>
      </div>

      {/* Stat cards */}
      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="card flex items-center gap-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-indigo-50">
            <Target className="h-6 w-6 text-indigo-600" />
          </div>
          <div>
            <p className="text-sm text-gray-500">Total Scans</p>
            <p className="text-2xl font-bold text-gray-900">{stats.total_scans}</p>
          </div>
        </div>

        <div className="card flex items-center gap-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-yellow-50">
            <Activity className="h-6 w-6 text-yellow-600" />
          </div>
          <div>
            <p className="text-sm text-gray-500">Active</p>
            <p className="text-2xl font-bold text-gray-900">{stats.running}</p>
          </div>
        </div>

        <div className="card flex items-center gap-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-green-50">
            <CheckCircle className="h-6 w-6 text-green-600" />
          </div>
          <div>
            <p className="text-sm text-gray-500">Completed</p>
            <p className="text-2xl font-bold text-gray-900">{stats.completed}</p>
          </div>
        </div>

        <div className="card flex items-center gap-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-red-50">
            <AlertTriangle className="h-6 w-6 text-red-600" />
          </div>
          <div>
            <p className="text-sm text-gray-500">Findings</p>
            <p className="text-2xl font-bold text-gray-900">{stats.total_findings}</p>
          </div>
        </div>
      </div>

      {/* Charts row */}
      <div className="mb-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Bar chart */}
        <div className="card">
          <h3 className="mb-4 text-sm font-medium text-gray-500">Findings by Severity</h3>
          {stats.severity_data.some((d) => d.value > 0) ? (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={stats.severity_data}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                <XAxis dataKey="label" tick={{ fill: "#6b7280", fontSize: 12 }} />
                <YAxis tick={{ fill: "#6b7280", fontSize: 12 }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#ffffff",
                    border: "1px solid #e5e7eb",
                    borderRadius: 8,
                    color: "#111827",
                  }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {stats.severity_data.map((entry) => (
                    <Cell key={entry.label} fill={SEVERITY_COLORS[entry.label] || "#6b7280"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-[250px] items-center justify-center text-sm text-gray-400">
              No findings data yet. Run a scan to see results.
            </div>
          )}
        </div>

        {/* Pie chart */}
        <div className="card">
          <h3 className="mb-4 text-sm font-medium text-gray-500">Severity Distribution</h3>
          {stats.severity_data.some((d) => d.value > 0) ? (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={stats.severity_data.filter((d) => d.value > 0)}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  dataKey="value"
                  nameKey="label"
                  label={({ label, value }) => `${label}: ${value}`}
                >
                  {stats.severity_data
                    .filter((d) => d.value > 0)
                    .map((entry) => (
                      <Cell key={entry.label} fill={SEVERITY_COLORS[entry.label] || "#6b7280"} />
                    ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#ffffff",
                    border: "1px solid #e5e7eb",
                    borderRadius: 8,
                    color: "#111827",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-[250px] items-center justify-center text-sm text-gray-400">
              No data to display
            </div>
          )}
        </div>
      </div>

      {/* Recent scans */}
      <div className="card">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-sm font-medium text-gray-500">Recent Scans</h3>
          <Link href="/scans/new" className="text-sm text-indigo-600 hover:text-indigo-500">
            View all
          </Link>
        </div>

        {scans.length === 0 ? (
          <div className="py-8 text-center">
            <Shield className="mx-auto mb-3 h-12 w-12 text-gray-300" />
            <p className="text-sm text-gray-500">No scans yet. Start your first scan!</p>
            <Link href="/scans/new" className="btn-primary mt-4 gap-2">
              <PlusCircle className="h-4 w-4" />
              New Scan
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-gray-200 text-gray-500">
                  <th className="pb-3 font-medium">Target</th>
                  <th className="pb-3 font-medium">Type</th>
                  <th className="pb-3 font-medium">Status</th>
                  <th className="pb-3 font-medium">Progress</th>
                  <th className="pb-3 font-medium">Created</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {scans.map((scan) => (
                  <tr key={scan.id} className="group">
                    <td className="py-3">
                      <Link
                        href={`/scans/${scan.id}`}
                        className="text-gray-900 hover:text-indigo-600"
                      >
                        {scan.target_url}
                      </Link>
                    </td>
                    <td className="py-3 capitalize text-gray-600">{scan.scan_type}</td>
                    <td className="py-3">
                      <span className={`capitalize ${statusColor(scan.status)}`}>
                        {scan.status}
                      </span>
                    </td>
                    <td className="py-3">
                      <div className="flex items-center gap-2">
                        <div className="h-2 w-24 overflow-hidden rounded-full bg-gray-200">
                          <div
                            className="h-full rounded-full bg-indigo-500 transition-all"
                            style={{ width: `${scan.progress}%` }}
                          />
                        </div>
                        <span className="text-xs text-gray-500">{scan.progress}%</span>
                      </div>
                    </td>
                    <td className="py-3 text-gray-500">
                      {new Date(scan.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Layout>
  );
}
