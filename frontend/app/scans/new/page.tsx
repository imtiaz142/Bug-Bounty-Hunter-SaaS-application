"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Search, Shield, AlertCircle, X } from "lucide-react";
import Layout from "@/components/layout/Layout";
import api from "@/lib/api";

export default function NewScanPage() {
  const router = useRouter();
  const [targetUrl, setTargetUrl] = useState("");
  const [scanType, setScanType] = useState<"quick" | "full">("quick");
  const [consent, setConsent] = useState(false);
  const [scopeInclude, setScopeInclude] = useState<string[]>([]);
  const [scopeExclude, setScopeExclude] = useState<string[]>([]);
  const [includeInput, setIncludeInput] = useState("");
  const [excludeInput, setExcludeInput] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const addScope = (type: "include" | "exclude") => {
    const input = type === "include" ? includeInput : excludeInput;
    const value = input.trim();
    if (!value) return;

    if (type === "include") {
      setScopeInclude([...scopeInclude, value]);
      setIncludeInput("");
    } else {
      setScopeExclude([...scopeExclude, value]);
      setExcludeInput("");
    }
  };

  const removeScope = (type: "include" | "exclude", index: number) => {
    if (type === "include") {
      setScopeInclude(scopeInclude.filter((_, i) => i !== index));
    } else {
      setScopeExclude(scopeExclude.filter((_, i) => i !== index));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!consent) {
      setError("You must confirm authorization to scan the target.");
      return;
    }

    setLoading(true);
    try {
      const res = await api.post("/scans/", {
        target_url: targetUrl,
        scan_type: scanType,
        consent: true,
        target_scope_include: scopeInclude,
        target_scope_exclude: scopeExclude,
      });
      const scan = res.data.data;
      router.push(`/scans/${scan.id}`);
    } catch (err: any) {
      const msg =
        err.response?.data?.detail?.error?.message ||
        err.response?.data?.message ||
        "Failed to create scan.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Layout>
      <div className="mx-auto max-w-2xl">
        <h2 className="mb-6 text-xl font-semibold text-gray-900">Launch New Scan</h2>

        {error && (
          <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-600">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Target URL */}
          <div className="card">
            <label className="mb-2 block text-sm font-medium text-gray-700">Target URL</label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
              <input
                type="url"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                className="input-field pl-10"
                placeholder="https://example.com"
                required
              />
            </div>
          </div>

          {/* Scan type */}
          <div className="card">
            <label className="mb-3 block text-sm font-medium text-gray-700">Scan Type</label>
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => setScanType("quick")}
                className={`rounded-lg border p-4 text-left transition-colors ${
                  scanType === "quick"
                    ? "border-indigo-500 bg-indigo-50"
                    : "border-gray-200 hover:border-gray-300"
                }`}
              >
                <p className="font-medium text-gray-900">Quick Scan</p>
                <p className="mt-1 text-xs text-gray-500">
                  Fast reconnaissance and common vulnerability checks
                </p>
              </button>
              <button
                type="button"
                onClick={() => setScanType("full")}
                className={`rounded-lg border p-4 text-left transition-colors ${
                  scanType === "full"
                    ? "border-indigo-500 bg-indigo-50"
                    : "border-gray-200 hover:border-gray-300"
                }`}
              >
                <p className="font-medium text-gray-900">Full Scan</p>
                <p className="mt-1 text-xs text-gray-500">
                  Deep scanning with extended subdomain and active testing
                </p>
              </button>
            </div>
          </div>

          {/* Scope */}
          <div className="card">
            <label className="mb-3 block text-sm font-medium text-gray-700">
              Scope (Optional)
            </label>

            {/* Include */}
            <div className="mb-4">
              <p className="mb-1.5 text-xs text-gray-500">Include patterns</p>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={includeInput}
                  onChange={(e) => setIncludeInput(e.target.value)}
                  className="input-field flex-1"
                  placeholder="*.example.com"
                  onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addScope("include"))}
                />
                <button type="button" onClick={() => addScope("include")} className="btn-secondary">
                  Add
                </button>
              </div>
              {scopeInclude.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-2">
                  {scopeInclude.map((s, i) => (
                    <span
                      key={i}
                      className="inline-flex items-center gap-1 rounded-md bg-green-50 px-2 py-1 text-xs text-green-700"
                    >
                      {s}
                      <button type="button" onClick={() => removeScope("include", i)}>
                        <X className="h-3 w-3" />
                      </button>
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* Exclude */}
            <div>
              <p className="mb-1.5 text-xs text-gray-500">Exclude patterns</p>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={excludeInput}
                  onChange={(e) => setExcludeInput(e.target.value)}
                  className="input-field flex-1"
                  placeholder="admin.example.com"
                  onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addScope("exclude"))}
                />
                <button type="button" onClick={() => addScope("exclude")} className="btn-secondary">
                  Add
                </button>
              </div>
              {scopeExclude.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-2">
                  {scopeExclude.map((s, i) => (
                    <span
                      key={i}
                      className="inline-flex items-center gap-1 rounded-md bg-red-50 px-2 py-1 text-xs text-red-700"
                    >
                      {s}
                      <button type="button" onClick={() => removeScope("exclude", i)}>
                        <X className="h-3 w-3" />
                      </button>
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Authorization consent */}
          <div className="card border-amber-200 bg-amber-50">
            <div className="flex items-start gap-3">
              <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-amber-500" />
              <div className="flex-1">
                <p className="text-sm font-medium text-amber-800">Authorization Required</p>
                <p className="mt-1 text-xs text-gray-600">
                  You must have explicit authorization to scan the target. Unauthorized scanning is
                  illegal and unethical.
                </p>
                <label className="mt-3 flex cursor-pointer items-center gap-2">
                  <input
                    type="checkbox"
                    checked={consent}
                    onChange={(e) => setConsent(e.target.checked)}
                    className="h-4 w-4 rounded border-gray-300 bg-white text-indigo-600 focus:ring-indigo-500"
                  />
                  <span className="text-sm text-gray-700">
                    I confirm I have authorization to scan this target
                  </span>
                </label>
              </div>
            </div>
          </div>

          {/* Submit */}
          <button
            type="submit"
            disabled={loading || !consent}
            className="btn-primary w-full gap-2"
          >
            {loading ? (
              <div className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
            ) : (
              <Shield className="h-4 w-4" />
            )}
            {loading ? "Creating scan..." : "Start Scan"}
          </button>
        </form>
      </div>
    </Layout>
  );
}
