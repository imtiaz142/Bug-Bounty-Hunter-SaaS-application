/**
 * Mock API adapter – intercepts axios requests and returns mock data
 * when the real backend is unavailable.
 *
 * Enable by setting NEXT_PUBLIC_USE_MOCK=true in .env.local
 */
import type { AxiosInstance, AxiosResponse, InternalAxiosRequestConfig } from "axios";
import {
  mockUser,
  mockScans,
  mockFindings,
  mockSummaries,
  mockReports,
  mockLogs,
  mockSettings,
} from "./mock-data";

// Wrap data in the standard API envelope
function ok<T>(data: T, config: InternalAxiosRequestConfig): AxiosResponse<any> {
  return {
    data: { success: true, data, message: "ok" },
    status: 200,
    statusText: "OK",
    headers: {},
    config,
  };
}

type RouteHandler = (url: string, params: Record<string, string>, body?: any, config?: InternalAxiosRequestConfig) => AxiosResponse<any> | null;

const routes: { pattern: RegExp; method: string; handler: RouteHandler }[] = [
  // ── Auth ──────────────────────────────────────────────────────────
  {
    pattern: /\/auth\/login$/,
    method: "post",
    handler: (_u, _p, _b, c) =>
      ok({ user: mockUser, tokens: { access_token: "mock-access-token", refresh_token: "mock-refresh-token" } }, c!),
  },
  {
    pattern: /\/auth\/register$/,
    method: "post",
    handler: (_u, _p, _b, c) =>
      ok({ user: mockUser, tokens: { access_token: "mock-access-token", refresh_token: "mock-refresh-token" } }, c!),
  },
  {
    pattern: /\/auth\/refresh$/,
    method: "post",
    handler: (_u, _p, _b, c) => ok({ access_token: "mock-access-token-refreshed" }, c!),
  },

  // ── Scans list ────────────────────────────────────────────────────
  {
    pattern: /\/scans$/,
    method: "get",
    handler: (_u, params, _b, c) => {
      let scans = [...mockScans];
      if (params.status) scans = scans.filter((s) => s.status === params.status);
      const perPage = Number(params.per_page) || 20;
      return ok({ scans: scans.slice(0, perPage), total: scans.length }, c!);
    },
  },

  // ── Scan create ───────────────────────────────────────────────────
  {
    pattern: /\/scans\/$/,
    method: "post",
    handler: (_u, _p, body, c) => {
      const newScan = {
        id: `new-${Date.now()}`,
        user_id: mockUser.id,
        target_url: body?.target_url || "https://example.com",
        status: "queued" as const,
        scan_type: body?.scan_type || "quick",
        progress: 0,
        current_agent: null,
        started_at: null,
        completed_at: null,
        duration_seconds: null,
        created_at: new Date().toISOString(),
        target_scope_include: body?.target_scope_include || null,
        target_scope_exclude: body?.target_scope_exclude || null,
      };
      return ok(newScan, c!);
    },
  },

  // ── Scan detail ───────────────────────────────────────────────────
  {
    pattern: /\/scans\/([^/]+)$/,
    method: "get",
    handler: (url, _p, _b, c) => {
      const id = url.match(/\/scans\/([^/]+)$/)?.[1];
      const scan = mockScans.find((s) => s.id === id);
      return ok(scan || mockScans[0], c!);
    },
  },

  // ── Findings summary ──────────────────────────────────────────────
  {
    pattern: /\/scans\/([^/]+)\/findings\/summary$/,
    method: "get",
    handler: (url, _p, _b, c) => {
      const id = url.match(/\/scans\/([^/]+)\/findings/)?.[1] || "";
      return ok({ summary: mockSummaries[id] || { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, confirmed: 0, false_positives: 0 } }, c!);
    },
  },

  // ── Findings list ─────────────────────────────────────────────────
  {
    pattern: /\/scans\/([^/]+)\/findings\/?$/,
    method: "get",
    handler: (url, params, _b, c) => {
      const id = url.match(/\/scans\/([^/]+)\/findings/)?.[1] || "";
      let findings = [...(mockFindings[id] || [])];
      if (params.severity) findings = findings.filter((f) => f.severity === params.severity);
      if (params.confirmed === "true") findings = findings.filter((f) => f.confirmed);
      if (params.confirmed === "false") findings = findings.filter((f) => !f.confirmed);
      return ok({ findings, total: findings.length }, c!);
    },
  },

  // ── Finding update (false positive toggle) ────────────────────────
  {
    pattern: /\/scans\/([^/]+)\/findings\/([^/]+)$/,
    method: "patch",
    handler: (url, _p, body, c) => {
      const scanId = url.match(/\/scans\/([^/]+)\/findings/)?.[1] || "";
      const findingId = url.match(/\/findings\/([^/]+)$/)?.[1] || "";
      const findings = mockFindings[scanId];
      if (findings) {
        const f = findings.find((f) => f.id === findingId);
        if (f && body?.false_positive !== undefined) f.false_positive = body.false_positive;
      }
      return ok({ updated: true }, c!);
    },
  },

  // ── Agents list ───────────────────────────────────────────────────
  {
    pattern: /\/scans\/([^/]+)\/agents\/?$/,
    method: "get",
    handler: (url, _p, _b, c) => {
      const id = url.match(/\/scans\/([^/]+)\/agents/)?.[1] || "";
      const logs = mockLogs[id] || [];
      const agents = Array.from(new Set(logs.map((l) => l.agent_name))).map((name) => ({
        agent_name: name,
        status: "completed",
      }));
      return ok({ agents }, c!);
    },
  },

  // ── Agent logs ────────────────────────────────────────────────────
  {
    pattern: /\/scans\/([^/]+)\/agents\/([^/]+)\/logs$/,
    method: "get",
    handler: (url, _p, _b, c) => {
      const scanId = url.match(/\/scans\/([^/]+)\/agents/)?.[1] || "";
      const agentName = url.match(/\/agents\/([^/]+)\/logs/)?.[1] || "";
      const logs = (mockLogs[scanId] || []).filter((l) => l.agent_name === agentName);
      return ok({ logs }, c!);
    },
  },

  // ── Report download ───────────────────────────────────────────────
  {
    pattern: /\/scans\/([^/]+)\/report\/download$/,
    method: "get",
    handler: (_u, _p, _b, c) => ok("Mock PDF content", c!),
  },

  // ── Report share ──────────────────────────────────────────────────
  {
    pattern: /\/scans\/([^/]+)\/report\/share$/,
    method: "post",
    handler: (_u, _p, _b, c) => ok({ public_url: "/reports/shared/mock-token" }, c!),
  },

  // ── Report get ────────────────────────────────────────────────────
  {
    pattern: /\/scans\/([^/]+)\/report\/?$/,
    method: "get",
    handler: (url, _p, _b, _c) => {
      const id = url.match(/\/scans\/([^/]+)\/report/)?.[1] || "";
      const report = mockReports[id];
      if (!report) return null; // signal 404
      return ok(report, _c!);
    },
  },

  // ── Report create ─────────────────────────────────────────────────
  {
    pattern: /\/scans\/([^/]+)\/report\/?$/,
    method: "post",
    handler: (url, _p, _b, c) => {
      const id = url.match(/\/scans\/([^/]+)\/report/)?.[1] || "";
      return ok({ id: `rpt-${Date.now()}`, scan_id: id, status: "generating", report_type: "technical" }, c!);
    },
  },

  // ── Scan actions (pause/resume) ───────────────────────────────────
  {
    pattern: /\/scans\/([^/]+)\/(pause|resume)$/,
    method: "post",
    handler: (_u, _p, _b, c) => ok({ success: true }, c!),
  },

  // ── Scan cancel ───────────────────────────────────────────────────
  {
    pattern: /\/scans\/([^/]+)$/,
    method: "delete",
    handler: (_u, _p, _b, c) => ok({ success: true }, c!),
  },

  // ── Settings get ──────────────────────────────────────────────────
  {
    pattern: /\/settings\/?$/,
    method: "get",
    handler: (_u, _p, _b, c) => ok({ ...mockSettings }, c!),
  },

  // ── Settings update ───────────────────────────────────────────────
  {
    pattern: /\/settings\/?$/,
    method: "patch",
    handler: (_u, _p, body, c) => {
      if (body?.username) mockSettings.username = body.username;
      if (body?.llm_provider) mockSettings.llm_provider = body.llm_provider;
      if (body?.llm_api_key) mockSettings.has_api_key = true;
      return ok({ ...mockSettings }, c!);
    },
  },

  // ── LLM test ──────────────────────────────────────────────────────
  {
    pattern: /\/settings\/llm\/test$/,
    method: "post",
    handler: (_u, _p, _b, c) => ok({ success: true, message: "Connection successful! (mock)" }, c!),
  },

  // ── Password change ───────────────────────────────────────────────
  {
    pattern: /\/settings\/password$/,
    method: "post",
    handler: (_u, _p, _b, c) => ok({ success: true }, c!),
  },
];

function matchRoute(method: string, url: string) {
  for (const route of routes) {
    if (route.method === method && route.pattern.test(url)) {
      return route;
    }
  }
  return null;
}

/** Install mock adapter on the given axios instance */
export function installMockApi(instance: AxiosInstance) {
  // Use a custom adapter that bypasses real HTTP entirely
  instance.defaults.adapter = (config: InternalAxiosRequestConfig) => {
    return new Promise((resolve, reject) => {
      const method = (config.method || "get").toLowerCase();
      const url = config.url || "";

      const route = matchRoute(method, url);
      if (!route) {
        // No mock route — reject with network error
        reject(new Error(`[Mock] No route for ${method.toUpperCase()} ${url}`));
        return;
      }

      // Parse query params
      const params: Record<string, string> = {};
      if (config.params) {
        for (const [k, v] of Object.entries(config.params)) {
          params[k] = String(v);
        }
      }

      // Parse body
      let body: any = undefined;
      if (config.data) {
        body = typeof config.data === "string" ? JSON.parse(config.data) : config.data;
      }

      // Simulate async delay (30-80ms)
      setTimeout(() => {
        try {
          const result = route.handler(url, params, body, config);
          if (result === null) {
            reject({ response: { status: 404, data: { detail: "Not found" } } });
          } else {
            resolve(result);
          }
        } catch (err) {
          reject(err);
        }
      }, 30 + Math.random() * 50);
    });
  };
}
