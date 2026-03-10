export interface User {
  id: string;
  email: string;
  username: string;
  created_at: string;
}

export interface Scan {
  id: string;
  user_id: string;
  target_url: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled" | "paused";
  scan_type: "quick" | "full";
  progress: number;
  current_agent: string | null;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  created_at: string;
  target_scope_include: string[] | null;
  target_scope_exclude: string[] | null;
  progress_detail?: ScanProgress;
}

export interface ScanProgress {
  scan_id: string;
  progress: number;
  current_agent: string | null;
  status: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cvss_score: number | null;
  cvss_vector: string | null;
  cwe: string | null;
  title: string;
  url: string;
  parameter: string | null;
  method: string | null;
  evidence: string | null;
  confirmed: boolean;
  fix_recommendation: string | null;
  references: string[] | null;
  false_positive: boolean;
  notes: string | null;
  discovered_at: string;
}

export interface FindingSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  confirmed: number;
  false_positives: number;
}

export interface Report {
  id: string;
  scan_id: string;
  report_type: "technical" | "executive";
  status: "generating" | "ready" | "failed";
  file_path: string | null;
  share_token: string | null;
  generated_at: string | null;
  created_at: string;
}

export interface Settings {
  llm_provider: string | null;
  has_api_key: boolean;
  email: string;
  username: string;
}

export interface ApiResponse<T = unknown> {
  success: boolean;
  data: T;
  message: string;
}

export interface AgentLog {
  id: string;
  scan_id: string;
  agent_name: string;
  level: string;
  message: string;
  data: Record<string, unknown> | null;
  timestamp: string;
}
