"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Search, Filter, CheckCircle, AlertTriangle } from "lucide-react";
import Layout from "@/components/layout/Layout";
import api from "@/lib/api";
import type { Scan, Finding } from "@/types";

const SEVERITY_BADGE: Record<string, string> = {
  critical: "badge-critical",
  high: "badge-high",
  medium: "badge-medium",
  low: "badge-low",
  info: "badge-info",
};

export default function FindingsPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScan, setSelectedScan] = useState<string>("");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [filterSeverity, setFilterSeverity] = useState<string>("");
  const [filterConfirmed, setFilterConfirmed] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);

  useEffect(() => {
    loadScans();
  }, []);

  useEffect(() => {
    if (selectedScan) {
      loadFindings();
    }
  }, [selectedScan, filterSeverity, filterConfirmed]);

  const loadScans = async () => {
    try {
      const res = await api.get("/scans", { params: { per_page: 50, status: "completed" } });
      const scansList: Scan[] = res.data.data.scans;
      setScans(scansList);
      if (scansList.length > 0) {
        setSelectedScan(scansList[0].id);
      }
    } catch {} finally {
      setLoading(false);
    }
  };

  const loadFindings = async () => {
    try {
      const params: Record<string, string> = { per_page: "100" };
      if (filterSeverity) params.severity = filterSeverity;
      if (filterConfirmed) params.confirmed = filterConfirmed;

      const res = await api.get(`/scans/${selectedScan}/findings/`, { params });
      setFindings(res.data.data.findings || []);
      setTotal(res.data.data.total || 0);
    } catch {
      setFindings([]);
    }
  };

  const handleMarkFalsePositive = async (findingId: string, current: boolean) => {
    try {
      await api.patch(`/scans/${selectedScan}/findings/${findingId}`, {
        false_positive: !current,
      });
      loadFindings();
    } catch {}
  };

  const filteredFindings = findings.filter((f) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      f.title.toLowerCase().includes(q) ||
      f.url.toLowerCase().includes(q) ||
      f.type.toLowerCase().includes(q)
    );
  });

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
      <h2 className="mb-6 text-xl font-semibold text-gray-900">Findings</h2>

      {/* Filters */}
      <div className="card mb-6">
        <div className="flex flex-wrap items-end gap-4">
          {/* Scan selector */}
          <div className="min-w-[200px] flex-1">
            <label className="mb-1.5 block text-xs font-medium text-gray-500">Scan</label>
            <select
              value={selectedScan}
              onChange={(e) => setSelectedScan(e.target.value)}
              className="input-field"
            >
              {scans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  {scan.target_url} ({new Date(scan.created_at).toLocaleDateString()})
                </option>
              ))}
            </select>
          </div>

          {/* Severity filter */}
          <div className="w-40">
            <label className="mb-1.5 block text-xs font-medium text-gray-500">Severity</label>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="input-field"
            >
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>

          {/* Confirmed filter */}
          <div className="w-40">
            <label className="mb-1.5 block text-xs font-medium text-gray-500">Status</label>
            <select
              value={filterConfirmed}
              onChange={(e) => setFilterConfirmed(e.target.value)}
              className="input-field"
            >
              <option value="">All</option>
              <option value="true">Confirmed</option>
              <option value="false">Unconfirmed</option>
            </select>
          </div>

          {/* Search */}
          <div className="min-w-[200px] flex-1">
            <label className="mb-1.5 block text-xs font-medium text-gray-500">Search</label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="input-field pl-10"
                placeholder="Search findings..."
              />
            </div>
          </div>
        </div>
      </div>

      {/* Results */}
      {scans.length === 0 ? (
        <div className="card py-12 text-center">
          <AlertTriangle className="mx-auto mb-3 h-10 w-10 text-gray-300" />
          <p className="text-sm text-gray-500">No completed scans yet. Run a scan first.</p>
          <Link href="/scans/new" className="btn-primary mt-4">
            New Scan
          </Link>
        </div>
      ) : (
        <>
          <p className="mb-3 text-sm text-gray-500">
            Showing {filteredFindings.length} of {total} findings
          </p>

          <div className="space-y-3">
            {filteredFindings.map((finding) => (
              <div key={finding.id} className="card">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={SEVERITY_BADGE[finding.severity] || "badge-info"}>
                        {finding.severity.toUpperCase()}
                      </span>
                      {finding.confirmed && (
                        <span className="inline-flex items-center gap-1 rounded-full bg-green-50 px-2 py-0.5 text-xs text-green-700">
                          <CheckCircle className="h-3 w-3" />
                          Confirmed
                        </span>
                      )}
                      {finding.false_positive && (
                        <span className="rounded-full bg-gray-100 px-2 py-0.5 text-xs text-gray-500">
                          False Positive
                        </span>
                      )}
                      {finding.cwe && (
                        <span className="text-xs text-gray-400">{finding.cwe}</span>
                      )}
                    </div>
                    <h4 className="mt-2 font-medium text-gray-900">{finding.title}</h4>
                    <p className="mt-1 text-sm text-gray-500">
                      {finding.type} | {finding.url}
                    </p>
                  </div>

                  <div className="flex items-center gap-2">
                    {finding.cvss_score !== null && (
                      <div className="text-right">
                        <div className="text-lg font-bold text-gray-900">{finding.cvss_score}</div>
                        <div className="text-xs text-gray-500">CVSS</div>
                      </div>
                    )}
                    <button
                      onClick={() => handleMarkFalsePositive(finding.id, finding.false_positive)}
                      className="btn-secondary text-xs"
                      title={finding.false_positive ? "Unmark false positive" : "Mark as false positive"}
                    >
                      {finding.false_positive ? "Restore" : "FP"}
                    </button>
                  </div>
                </div>
              </div>
            ))}

            {filteredFindings.length === 0 && (
              <div className="py-8 text-center text-sm text-gray-500">
                No findings match your filters.
              </div>
            )}
          </div>
        </>
      )}
    </Layout>
  );
}
