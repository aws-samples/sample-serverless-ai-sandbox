"use client";
import { useState, useEffect } from "react";
import { getConfig, setConfig } from "@/lib/api";
import { useToast } from "@/components/toast";
import { Settings, Globe, Key, MapPin, Database } from "lucide-react";

export default function SettingsPage() {
  const [apiUrl, setApiUrl] = useState("");
  const [region, setRegion] = useState("us-east-1");
  const [token, setToken] = useState("");
  const [egressTable, setEgressTable] = useState("");
  const { toast } = useToast();

  useEffect(() => {
    const config = getConfig();
    if (config) {
      setApiUrl(config.apiUrl || "");
      setRegion(config.region || "us-east-1");
      setToken(config.token || "");
      setEgressTable(config.egressTable || "");
    }
  }, []);

  const handleSave = () => {
    setConfig({ apiUrl, region, token: token || undefined, egressTable: egressTable || undefined });
    toast("Configuration saved", "success");
  };

  return (
    <div className="max-w-xl">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-[var(--text-primary)]">Settings</h1>
        <p className="text-[var(--text-muted)] text-sm mt-1">Configure your API connection</p>
      </div>

      <div className="bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-2xl p-6 space-y-5">
        <div>
          <label className="flex items-center gap-2 text-sm font-medium text-[var(--text-secondary)] mb-2">
            <Globe className="w-4 h-4" /> API URL
          </label>
          <input type="url" value={apiUrl} onChange={(e) => setApiUrl(e.target.value)}
            placeholder="https://xxx.execute-api.us-east-1.amazonaws.com"
            className="w-full bg-[var(--bg-input)] border border-[var(--border-secondary)] rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-[var(--accent)] focus:ring-1 focus:ring-[var(--accent)]/30 text-[var(--text-primary)] placeholder-[var(--text-muted)] transition-all" />
        </div>

        <div>
          <label className="flex items-center gap-2 text-sm font-medium text-[var(--text-secondary)] mb-2">
            <MapPin className="w-4 h-4" /> Region
          </label>
          <select value={region} onChange={(e) => setRegion(e.target.value)}
            className="w-full bg-[var(--bg-input)] border border-[var(--border-secondary)] rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-[var(--accent)] text-[var(--text-primary)] transition-all">
            <option value="us-east-1">us-east-1 (N. Virginia)</option>
            <option value="us-east-2">us-east-2 (Ohio)</option>
            <option value="us-west-2">us-west-2 (Oregon)</option>
            <option value="ap-northeast-1">ap-northeast-1 (Tokyo)</option>
            <option value="eu-west-1">eu-west-1 (Ireland)</option>
          </select>
        </div>

        <div>
          <label className="flex items-center gap-2 text-sm font-medium text-[var(--text-secondary)] mb-2">
            <Key className="w-4 h-4" /> Bearer Token
          </label>
          <input type="text" value={token} onChange={(e) => setToken(e.target.value)}
            placeholder="demo-token-tenant-a (optional)"
            className="w-full bg-[var(--bg-input)] border border-[var(--border-secondary)] rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-[var(--accent)] focus:ring-1 focus:ring-[var(--accent)]/30 text-[var(--text-primary)] placeholder-[var(--text-muted)] transition-all" />
          <p className="text-xs text-[var(--text-muted)] mt-2">
            For multi-tenant authentication. Leave empty for single-tenant (SigV4 is not supported in browser).
          </p>
        </div>

        <div>
          <label className="flex items-center gap-2 text-sm font-medium text-[var(--text-secondary)] mb-2">
            <Database className="w-4 h-4" /> Egress Policy Table
          </label>
          <input type="text" value={egressTable} onChange={(e) => setEgressTable(e.target.value)}
            placeholder="EgressStack-EgressConfig..."
            className="w-full bg-[var(--bg-input)] border border-[var(--border-secondary)] rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-[var(--accent)] focus:ring-1 focus:ring-[var(--accent)]/30 text-[var(--text-primary)] placeholder-[var(--text-muted)] transition-all" />
          <p className="text-xs text-[var(--text-muted)] mt-2">
            DynamoDB table name from EgressStack. Find it in CloudFormation outputs or run: aws dynamodb list-tables
          </p>
        </div>

        <button onClick={handleSave}
          className="w-full bg-blue-600 hover:bg-blue-500 text-white py-2.5 rounded-xl text-sm font-medium transition-all shadow-lg shadow-blue-600/20 hover:shadow-blue-500/30">
          Save Configuration
        </button>
      </div>
    </div>
  );
}
