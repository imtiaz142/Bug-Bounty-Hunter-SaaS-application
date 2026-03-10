"use client";

import { useEffect, useState } from "react";
import { FileText, Download, Share2, Clock, CheckCircle, XCircle, Loader2 } from "lucide-react";
import Layout from "@/components/layout/Layout";
import api from "@/lib/api";
import type { Scan, Report } from "@/types";

export default function ReportsPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [reports, setReports] = useState<Map<string, Report>>(new Map());
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState<string | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const res = await api.get("/scans", { params: { per_page: 50, status: "completed" } });
      const scansList: Scan[] = res.data.data.scans;
      setScans(scansList);

      // Load report status for each scan
      const reportMap = new Map<string, Report>();
      for (const scan of scansList) {
        try {
          const reportRes = await api.get(`/scans/${scan.id}/report/`);
          reportMap.set(scan.id, reportRes.data.data);
        } catch {
          // No report for this scan
        }
      }
      setReports(reportMap);
    } catch {} finally {
      setLoading(false);
    }
  };

  const handleGenerate = async (scanId: string, reportType: "technical" | "executive") => {
    setGenerating(scanId);
    try {
      await api.post(`/scans/${scanId}/report/`, { report_type: reportType });
      // Reload to get updated report status
      setTimeout(loadData, 2000);
    } catch (err: any) {
      alert(err.response?.data?.detail?.error?.message || "Failed to generate report.");
    } finally {
      setGenerating(null);
    }
  };

  const handleDownload = async (scanId: string) => {
    try {
      const res = await api.get(`/scans/${scanId}/report/download`, {
        responseType: "blob",
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `report_${scanId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch {
      alert("Failed to download report.");
    }
  };

  const handleShare = async (scanId: string) => {
    try {
      const res = await api.post(`/scans/${scanId}/report/share`);
      const { public_url } = res.data.data;
      const fullUrl = `${window.location.origin}${public_url}`;
      await navigator.clipboard.writeText(fullUrl);
      alert("Share link copied to clipboard!");
    } catch {
      alert("Failed to generate share link.");
    }
  };

  const reportStatusIcon = (report: Report) => {
    switch (report.status) {
      case "ready":
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      case "generating":
        return <Loader2 className="h-5 w-5 animate-spin text-yellow-500" />;
      case "failed":
        return <XCircle className="h-5 w-5 text-red-500" />;
      default:
        return <Clock className="h-5 w-5 text-gray-400" />;
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
      <h2 className="mb-6 text-xl font-semibold text-gray-900">Reports</h2>

      {scans.length === 0 ? (
        <div className="card py-12 text-center">
          <FileText className="mx-auto mb-3 h-10 w-10 text-gray-300" />
          <p className="text-sm text-gray-500">
            No completed scans available for report generation.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {scans.map((scan) => {
            const report = reports.get(scan.id);
            return (
              <div key={scan.id} className="card">
                <div className="flex flex-wrap items-center justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-3">
                      {report ? (
                        reportStatusIcon(report)
                      ) : (
                        <FileText className="h-5 w-5 text-gray-400" />
                      )}
                      <div>
                        <h3 className="font-medium text-gray-900">{scan.target_url}</h3>
                        <p className="text-sm text-gray-500">
                          {scan.scan_type} scan | {new Date(scan.created_at).toLocaleDateString()}
                          {report && (
                            <span className="ml-2 capitalize">
                              | {report.report_type} report -{" "}
                              <span
                                className={
                                  report.status === "ready"
                                    ? "text-green-600"
                                    : report.status === "failed"
                                    ? "text-red-600"
                                    : "text-yellow-600"
                                }
                              >
                                {report.status}
                              </span>
                            </span>
                          )}
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {!report && (
                      <>
                        <button
                          onClick={() => handleGenerate(scan.id, "technical")}
                          disabled={generating === scan.id}
                          className="btn-primary gap-1.5 text-sm"
                        >
                          {generating === scan.id ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                          ) : (
                            <FileText className="h-4 w-4" />
                          )}
                          Technical
                        </button>
                        <button
                          onClick={() => handleGenerate(scan.id, "executive")}
                          disabled={generating === scan.id}
                          className="btn-secondary gap-1.5 text-sm"
                        >
                          Executive
                        </button>
                      </>
                    )}

                    {report?.status === "ready" && (
                      <>
                        <button
                          onClick={() => handleDownload(scan.id)}
                          className="btn-primary gap-1.5 text-sm"
                        >
                          <Download className="h-4 w-4" />
                          Download
                        </button>
                        <button
                          onClick={() => handleShare(scan.id)}
                          className="btn-secondary gap-1.5 text-sm"
                        >
                          <Share2 className="h-4 w-4" />
                          Share
                        </button>
                      </>
                    )}

                    {report?.status === "failed" && (
                      <button
                        onClick={() => handleGenerate(scan.id, report.report_type as "technical" | "executive")}
                        disabled={generating === scan.id}
                        className="btn-danger gap-1.5 text-sm"
                      >
                        Retry
                      </button>
                    )}

                    {report?.status === "generating" && (
                      <span className="text-sm text-yellow-600">Generating...</span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </Layout>
  );
}
