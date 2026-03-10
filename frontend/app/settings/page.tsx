"use client";

import { useEffect, useState } from "react";
import { Save, Eye, EyeOff, CheckCircle, XCircle, Loader2, Key } from "lucide-react";
import Layout from "@/components/layout/Layout";
import api from "@/lib/api";
import type { Settings } from "@/types";

export default function SettingsPage() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [loading, setLoading] = useState(true);

  // LLM settings
  const [provider, setProvider] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [username, setUsername] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState("");

  // Test connection
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  // Password change
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [pwSaving, setPwSaving] = useState(false);
  const [pwMsg, setPwMsg] = useState("");

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      const res = await api.get("/settings/");
      const data: Settings = res.data.data;
      setSettings(data);
      setProvider(data.llm_provider || "");
      setUsername(data.username);
    } catch {} finally {
      setLoading(false);
    }
  };

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSaveMsg("");

    try {
      const payload: Record<string, string> = {};
      if (provider) payload.llm_provider = provider;
      if (apiKey) payload.llm_api_key = apiKey;
      if (username !== settings?.username) payload.username = username;

      await api.patch("/settings/", payload);
      setSaveMsg("Settings saved successfully.");
      setApiKey("");
      loadSettings();
    } catch (err: any) {
      setSaveMsg(err.response?.data?.detail?.error?.message || "Failed to save settings.");
    } finally {
      setSaving(false);
    }
  };

  const handleTestConnection = async () => {
    if (!provider || !apiKey) {
      setTestResult({ success: false, message: "Provider and API key are required." });
      return;
    }
    setTesting(true);
    setTestResult(null);

    try {
      const res = await api.post("/settings/llm/test", {
        provider,
        api_key: apiKey,
      });
      setTestResult(res.data.data);
    } catch (err: any) {
      setTestResult({ success: false, message: "Connection test failed." });
    } finally {
      setTesting(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPwSaving(true);
    setPwMsg("");

    try {
      await api.post("/settings/password", {
        current_password: currentPassword,
        new_password: newPassword,
      });
      setPwMsg("Password changed successfully.");
      setCurrentPassword("");
      setNewPassword("");
    } catch (err: any) {
      setPwMsg(err.response?.data?.detail?.error?.message || "Failed to change password.");
    } finally {
      setPwSaving(false);
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
      <h2 className="mb-6 text-xl font-semibold text-gray-900">Settings</h2>

      <div className="mx-auto max-w-2xl space-y-6">
        {/* LLM Configuration */}
        <form onSubmit={handleSaveSettings} className="card">
          <h3 className="mb-4 text-lg font-medium text-gray-900">AI Provider Configuration</h3>
          <p className="mb-4 text-sm text-gray-500">
            Configure an LLM provider to enable AI-powered analysis and report generation.
          </p>

          <div className="space-y-4">
            <div>
              <label className="mb-1.5 block text-sm font-medium text-gray-700">Provider</label>
              <select
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
                className="input-field"
              >
                <option value="">None (heuristic analysis only)</option>
                <option value="claude">Claude (Anthropic)</option>
                <option value="openai">OpenAI</option>
              </select>
            </div>

            {provider && (
              <div>
                <label className="mb-1.5 block text-sm font-medium text-gray-700">
                  API Key {settings?.has_api_key && "(key already saved)"}
                </label>
                <div className="relative">
                  <Key className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
                  <input
                    type={showKey ? "text" : "password"}
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    className="input-field pl-10 pr-10"
                    placeholder={settings?.has_api_key ? "Enter new key to update" : "Enter your API key"}
                  />
                  <button
                    type="button"
                    onClick={() => setShowKey(!showKey)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                  >
                    {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>
            )}

            {/* Test connection */}
            {provider && (
              <div>
                <button
                  type="button"
                  onClick={handleTestConnection}
                  disabled={testing || !apiKey}
                  className="btn-secondary gap-1.5 text-sm"
                >
                  {testing ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <CheckCircle className="h-4 w-4" />
                  )}
                  Test Connection
                </button>
                {testResult && (
                  <div
                    className={`mt-2 flex items-center gap-2 text-sm ${
                      testResult.success ? "text-green-600" : "text-red-600"
                    }`}
                  >
                    {testResult.success ? (
                      <CheckCircle className="h-4 w-4" />
                    ) : (
                      <XCircle className="h-4 w-4" />
                    )}
                    {testResult.message}
                  </div>
                )}
              </div>
            )}

            {/* Username */}
            <div>
              <label className="mb-1.5 block text-sm font-medium text-gray-700">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="input-field"
                minLength={2}
              />
            </div>
          </div>

          {saveMsg && (
            <div
              className={`mt-4 rounded-lg px-3 py-2 text-sm ${
                saveMsg.includes("success")
                  ? "bg-green-50 text-green-700"
                  : "bg-red-50 text-red-700"
              }`}
            >
              {saveMsg}
            </div>
          )}

          <div className="mt-6 flex justify-end">
            <button type="submit" disabled={saving} className="btn-primary gap-1.5">
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
              Save Settings
            </button>
          </div>
        </form>

        {/* Change password */}
        <form onSubmit={handleChangePassword} className="card">
          <h3 className="mb-4 text-lg font-medium text-gray-900">Change Password</h3>

          <div className="space-y-4">
            <div>
              <label className="mb-1.5 block text-sm font-medium text-gray-700">
                Current Password
              </label>
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="input-field"
                required
              />
            </div>
            <div>
              <label className="mb-1.5 block text-sm font-medium text-gray-700">
                New Password
              </label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="input-field"
                placeholder="Min. 8 characters"
                minLength={8}
                required
              />
            </div>
          </div>

          {pwMsg && (
            <div
              className={`mt-4 rounded-lg px-3 py-2 text-sm ${
                pwMsg.includes("success")
                  ? "bg-green-50 text-green-700"
                  : "bg-red-50 text-red-700"
              }`}
            >
              {pwMsg}
            </div>
          )}

          <div className="mt-6 flex justify-end">
            <button type="submit" disabled={pwSaving} className="btn-primary gap-1.5">
              {pwSaving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
              Change Password
            </button>
          </div>
        </form>

        {/* Account info */}
        <div className="card">
          <h3 className="mb-4 text-lg font-medium text-gray-900">Account Information</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-500">Email</span>
              <span className="text-gray-900">{settings?.email}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">Username</span>
              <span className="text-gray-900">{settings?.username}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">LLM Provider</span>
              <span className="capitalize text-gray-900">
                {settings?.llm_provider || "Not configured"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">API Key</span>
              <span className="text-gray-900">
                {settings?.has_api_key ? "Configured" : "Not set"}
              </span>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
