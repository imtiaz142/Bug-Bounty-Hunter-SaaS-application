"use client";

import { useEffect, useState, useRef } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  CheckCircle,
  XCircle,
  Clock,
  Pause,
  Play,
  Trash2,
  FileText,
  ExternalLink,
  AlertTriangle,
} from "lucide-react";
import Layout from "@/components/layout/Layout";
import api, { getWsUrl } from "@/lib/api";
import type { Scan, Finding, FindingSummary, AgentLog } from "@/types";

const SEVERITY_BADGE: Record<string, string> = {
  critical: "badge-critical",
  high: "badge-high",
  medium: "badge-medium",
  low: "badge-low",
  info: "badge-info",
};

const AGENT_LABELS: Record<string, string> = {
  recon: "Reconnaissance",
  scanner: "Vulnerability Scanner",
  exploit: "Exploit Verification",
  analyzer: "AI Analysis",
  reporter: "Report Generation",
};

export default function ScanDetailPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.scan_id as string;

  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState<FindingSummary | null>(null);
  const [logs, setLogs] = useState<AgentLog[]>([]);
  const [tab, setTab] = useState<"findings" | "logs">("findings");
  const [loading, setLoading] = useState(true);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    loadScan();
    return () => {
      wsRef.current?.close();
    };
  }, [scanId]);

  useEffect(() => {
    if (scan && (scan.status === "running" || scan.status === "queued")) {
      connectWebSocket();
    }
  }, [scan?.status]);

  const loadScan = async () => {
    try {
      const [scanRes, findingsRes, agentsRes] = await Promise.all([
        api.get(`/scans/${scanId}`),
        api.get(`/scans/${scanId}/findings/`).catch(() => null),
        api.get(`/scans/${scanId}/agents/`).catch(() => null),
      ]);

      setScan(scanRes.data.data);
      if (findingsRes) {
        setFindings(findingsRes.data.data.findings || []);
      }

      // Fetch logs from each agent
      if (agentsRes?.data?.data?.agents) {
        const allLogs: AgentLog[] = [];
        for (const agent of agentsRes.data.data.agents) {
          try {
            const logRes = await api.get(`/scans/${scanId}/agents/${agent.agent_name}/logs`);
            const agentLogs = (logRes.data.data.logs || []).map((l: any) => ({
              ...l,
              scan_id: scanId,
            }));
            allLogs.push(...agentLogs);
          } catch {}
        }
        allLogs.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
        setLogs(allLogs);
      }

      // Try to get summary
      try {
        const summaryRes = await api.get(`/scans/${scanId}/findings/summary`);
        setSummary(summaryRes.data.data.summary);
      } catch {
        // No findings yet
      }
    } catch {
      router.push("/dashboard");
    } finally {
      setLoading(false);
    }
  };

  const connectWebSocket = () => {
    if (wsRef.current) return;
    try {
      const ws = new WebSocket(getWsUrl(scanId));
      wsRef.current = ws;

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.event === "progress") {
          setScan((prev) =>
            prev
              ? { ...prev, progress: data.progress, current_agent: data.agent, status: "running" }
              : prev
          );
        } else if (data.event === "scan_completed") {
          loadScan();
          ws.close();
          wsRef.current = null;
        } else if (data.event === "agent_completed" || data.event === "agent_started") {
          // Refresh scan data including logs
          loadScan();
        }
      };

      ws.onclose = () => {
        wsRef.current = null;
      };
    } catch {
      // WS not available
    }
  };

  const handlePause = async () => {
    try {
      await api.post(`/scans/${scanId}/pause`);
      loadScan();
    } catch {}
  };

  const handleResume = async () => {
    try {
      await api.post(`/scans/${scanId}/resume`);
      loadScan();
    } catch {}
  };

  const handleCancel = async () => {
    if (!confirm("Are you sure you want to cancel this scan?")) return;
    try {
      await api.delete(`/scans/${scanId}`);
      loadScan();
    } catch {}
  };

  const handleGenerateReport = async () => {
    try {
      await api.post(`/scans/${scanId}/report/`, { report_type: "technical" });
      alert("Report generation queued. Check the Reports page.");
    } catch (err: any) {
      alert(err.response?.data?.detail?.error?.message || "Failed to generate report.");
    }
  };

  if (loading || !scan) {
    return (
      <Layout>
        <div className="flex h-64 items-center justify-center">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-indigo-500 border-t-transparent" />
        </div>
      </Layout>
    );
  }

  const isActive = scan.status === "running" || scan.status === "queued";

  return (
    <Layout>
      {/* Header */}
      <div className="mb-6">
        <Link href="/dashboard" className="mb-3 inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-900">
          <ArrowLeft className="h-4 w-4" />
          Back to Dashboard
        </Link>

        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">{scan.target_url}</h2>
            <div className="mt-1 flex items-center gap-3 text-sm text-gray-500">
              <span className="capitalize">{scan.scan_type} scan</span>
              <span>Created {new Date(scan.created_at).toLocaleString()}</span>
              {scan.duration_seconds && <span>Duration: {scan.duration_seconds}s</span>}
            </div>
          </div>

          <div className="flex items-center gap-2">
            {scan.status === "running" && (
              <button onClick={handlePause} className="btn-secondary gap-1.5">
                <Pause className="h-4 w-4" />
                Pause
              </button>
            )}
            {scan.status === "paused" && (
              <button onClick={handleResume} className="btn-primary gap-1.5">
                <Play className="h-4 w-4" />
                Resume
              </button>
            )}
            {isActive && (
              <button onClick={handleCancel} className="btn-danger gap-1.5">
                <Trash2 className="h-4 w-4" />
                Cancel
              </button>
            )}
            {scan.status === "completed" && (
              <button onClick={handleGenerateReport} className="btn-primary gap-1.5">
                <FileText className="h-4 w-4" />
                Generate Report
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Progress */}
      {isActive && (
        <div className="card mb-6">
          <div className="mb-2 flex items-center justify-between text-sm">
            <span className="text-gray-700">
              {scan.current_agent
                ? `Running: ${AGENT_LABELS[scan.current_agent] || scan.current_agent}`
                : "Queued..."}
            </span>
            <span className="text-indigo-600">{scan.progress}%</span>
          </div>
          <div className="h-3 overflow-hidden rounded-full bg-gray-200">
            <div
              className="h-full rounded-full bg-indigo-500 transition-all duration-500"
              style={{ width: `${scan.progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Status badge */}
      <div className="card mb-6">
        <div className="flex items-center gap-3">
          {scan.status === "completed" && <CheckCircle className="h-5 w-5 text-green-500" />}
          {scan.status === "failed" && <XCircle className="h-5 w-5 text-red-500" />}
          {isActive && <Clock className="h-5 w-5 animate-pulse text-yellow-500" />}
          {scan.status === "cancelled" && <XCircle className="h-5 w-5 text-gray-400" />}
          {scan.status === "paused" && <Pause className="h-5 w-5 text-amber-500" />}

          <span className="text-lg font-medium capitalize text-gray-900">{scan.status}</span>

          {summary && (
            <div className="ml-auto flex gap-3">
              {summary.critical > 0 && <span className="badge-critical">{summary.critical} Critical</span>}
              {summary.high > 0 && <span className="badge-high">{summary.high} High</span>}
              {summary.medium > 0 && <span className="badge-medium">{summary.medium} Medium</span>}
              {summary.low > 0 && <span className="badge-low">{summary.low} Low</span>}
              {summary.info > 0 && <span className="badge-info">{summary.info} Info</span>}
            </div>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-4 flex border-b border-gray-200">
        <button
          onClick={() => setTab("findings")}
          className={`px-4 py-2.5 text-sm font-medium transition-colors ${
            tab === "findings"
              ? "border-b-2 border-indigo-500 text-indigo-600"
              : "text-gray-500 hover:text-gray-900"
          }`}
        >
          Findings ({findings.length})
        </button>
        <button
          onClick={() => setTab("logs")}
          className={`px-4 py-2.5 text-sm font-medium transition-colors ${
            tab === "logs"
              ? "border-b-2 border-indigo-500 text-indigo-600"
              : "text-gray-500 hover:text-gray-900"
          }`}
        >
          Agent Logs ({logs.length})
        </button>
      </div>

      {/* Findings tab */}
      {tab === "findings" && (
        <div className="space-y-3">
          {findings.length === 0 ? (
            <div className="card py-12 text-center">
              <AlertTriangle className="mx-auto mb-3 h-10 w-10 text-gray-300" />
              <p className="text-sm text-gray-500">
                {isActive ? "Findings will appear here as the scan progresses." : "No findings discovered."}
              </p>
            </div>
          ) : (
            findings.map((finding) => (
              <div key={finding.id} className="card">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
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
                        <span className="inline-flex items-center rounded-full bg-gray-100 px-2 py-0.5 text-xs text-gray-500">
                          False Positive
                        </span>
                      )}
                    </div>
                    <h4 className="mt-2 font-medium text-gray-900">{finding.title}</h4>
                    <p className="mt-1 text-sm text-gray-500">
                      {finding.type} | {finding.url}
                      {finding.parameter && ` | param: ${finding.parameter}`}
                    </p>
                    {finding.evidence && (
                      <pre className="mt-2 max-h-32 overflow-auto rounded bg-gray-50 p-2 text-xs text-gray-600">
                        {finding.evidence.substring(0, 500)}
                      </pre>
                    )}
                    {finding.fix_recommendation && (
                      <div className="mt-2 rounded bg-green-50 p-2 text-xs text-green-700">
                        <strong>Fix:</strong> {finding.fix_recommendation.substring(0, 300)}
                      </div>
                    )}
                  </div>
                  {finding.cvss_score !== null && (
                    <div className="text-right">
                      <div className="text-lg font-bold text-gray-900">{finding.cvss_score}</div>
                      <div className="text-xs text-gray-500">CVSS</div>
                    </div>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* Logs tab */}
      {tab === "logs" && (
        <div className="card max-h-[600px] overflow-y-auto font-mono text-xs">
          {logs.length === 0 ? (
            <p className="py-8 text-center text-sm text-gray-500">No logs yet.</p>
          ) : (
            <div className="space-y-1">
              {logs.map((log, i) => (
                <div key={i} className="flex gap-2">
                  <span className="shrink-0 text-gray-400">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </span>
                  <span
                    className={`shrink-0 uppercase ${
                      log.level === "error"
                        ? "text-red-600"
                        : log.level === "warning"
                        ? "text-yellow-600"
                        : "text-gray-400"
                    }`}
                  >
                    [{log.level}]
                  </span>
                  <span className="shrink-0 text-indigo-600">[{log.agent_name}]</span>
                  <span className="text-gray-700">{log.message}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </Layout>
  );
}
