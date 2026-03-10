import axios from "axios";
import { getToken, getRefreshToken, setTokens, clearTokens } from "./auth";
import { installMockApi } from "./mock-api";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const USE_MOCK = process.env.NEXT_PUBLIC_USE_MOCK === "true";

const api = axios.create({
  baseURL: `${API_URL}/api/v1`,
  headers: { "Content-Type": "application/json" },
});

// Install mock data interceptor when enabled
if (USE_MOCK) {
  installMockApi(api);
}

// Attach token to every request
api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Auto-refresh on 401
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config;
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true;
      const refresh = getRefreshToken();
      if (refresh) {
        try {
          const res = await axios.post(`${API_URL}/api/v1/auth/refresh`, {
            refresh_token: refresh,
          });
          const newToken = res.data.data.access_token;
          setTokens(newToken, refresh);
          original.headers.Authorization = `Bearer ${newToken}`;
          return api(original);
        } catch {
          clearTokens();
          if (typeof window !== "undefined") {
            window.location.href = "/login";
          }
        }
      } else {
        clearTokens();
        if (typeof window !== "undefined") {
          window.location.href = "/login";
        }
      }
    }
    return Promise.reject(error);
  }
);

export default api;

// WS URL helper
export function getWsUrl(scanId: string): string {
  const wsBase = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000";
  return `${wsBase}/api/v1/scans/${scanId}/live`;
}
