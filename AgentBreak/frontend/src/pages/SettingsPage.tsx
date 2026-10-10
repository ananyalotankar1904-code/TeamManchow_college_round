import React, { useState } from 'react';
import { ApiConnectionStatus } from '../types';
import { PageHeader } from '../components/layout/PageHeader';
import {
  Server,
  RefreshCw,
  SlidersHorizontal,
  Check,
  Shield,
  Info,
} from 'lucide-react';
import { useToast } from '../components/common/Toast';

interface SettingsPageProps {
  status: ApiConnectionStatus;
  onUpdateBaseUrl: (url: string) => Promise<ApiConnectionStatus>;
  onToggleDemoMode: () => void;
  onRefreshHealth: () => void;
}

export const SettingsPage: React.FC<SettingsPageProps> = ({
  status,
  onUpdateBaseUrl,
  onToggleDemoMode,
  onRefreshHealth,
}) => {
  const { showSuccess, showError } = useToast();
  const [apiUrl, setApiUrl] = useState(status.endpoint);
  const [isUpdating, setIsUpdating] = useState(false);

  const handleSaveApiUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setIsUpdating(true);
      const res = await onUpdateBaseUrl(apiUrl);
      if (res.connected) {
        showSuccess(`Successfully connected to backend at ${apiUrl} (${res.latencyMs}ms)`);
      } else {
        showSuccess(`Backend URL saved. Backend unreachable, running in Demo Mode.`);
      }
    } catch {
      showError('Failed to verify backend connection');
    } finally {
      setIsUpdating(false);
    }
  };

  return (
    <div className="space-y-6 font-sans">
      <PageHeader
        title="Settings & Lab Environment"
        subtitle="Configure backend API endpoints, sandbox connection health, and adversarial evaluation harness parameters."
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Backend API Configuration */}
        <div className="p-5 rounded border border-[#124A58] bg-[#073642] space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-[#124A58]">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-[#6DBAC6]" />
              <span className="font-sans text-xs font-semibold text-[#E3EEEE]">
                Security Engine Connection
              </span>
            </div>
            <button
              onClick={onRefreshHealth}
              className="p-1 rounded text-[#8CA3A8] hover:text-[#E3EEEE] hover:bg-[#0E4452] transition-colors"
              title="Test connection health"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>

          <form onSubmit={handleSaveApiUrl} className="space-y-3.5">
            <div className="space-y-1.5">
              <label htmlFor="api-base-url" className="block text-xs font-medium text-[#8CA3A8]">
                Backend API Base URL (VITE_API_BASE_URL)
              </label>
              <input
                id="api-base-url"
                type="text"
                value={apiUrl}
                onChange={(e) => setApiUrl(e.target.value)}
                placeholder="http://localhost:8000"
                className="w-full bg-[#002B36] border border-[#124A58] rounded px-3 py-2 text-xs text-[#E3EEEE] font-mono focus:outline-none focus:border-[#2B7F8C]"
              />
            </div>

            <div className="p-3 rounded bg-[#002B36] border border-[#124A58] space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-[#8CA3A8]">Connection State:</span>
                <span className={status.connected ? 'text-[#78B993] font-medium' : 'text-[#E2C98F] font-medium'}>
                  {status.connected ? `Connected (${status.latencyMs} ms)` : 'Demo Mode (Offline Fixtures)'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#8CA3A8]">Last Health Check:</span>
                <span className="text-[#BCD0D3] font-mono">{status.lastChecked.replace('T', ' ').substring(11, 19)} UTC</span>
              </div>
            </div>

            <div className="flex items-center justify-between pt-2">
              <button
                type="button"
                onClick={onToggleDemoMode}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-[#002B36] hover:bg-[#0E4452] text-[#6DBAC6] rounded border border-[#124A58] text-xs font-medium transition-colors"
              >
                <SlidersHorizontal className="w-3 h-3" />
                <span>{status.isDemoMode ? 'Enable Live Mode' : 'Force Demo Data'}</span>
              </button>

              <button
                type="submit"
                disabled={isUpdating}
                className="px-4 py-1.5 bg-[#2B7F8C] hover:bg-[#3596A5] text-[#F2FAFA] rounded text-xs font-medium shadow-subtle flex items-center gap-1.5 transition-colors"
              >
                <Check className="w-3.5 h-3.5" />
                <span>{isUpdating ? 'Saving...' : 'Save & Reconnect'}</span>
              </button>
            </div>
          </form>
        </div>

        {/* Evaluation Engine Specification */}
        <div className="p-5 rounded border border-[#124A58] bg-[#073642] space-y-3.5 text-xs">
          <div className="flex items-center gap-2 pb-2 border-b border-[#124A58]">
            <Shield className="w-4 h-4 text-[#6DBAC6]" />
            <span className="font-sans font-semibold text-[#E3EEEE]">
              Engine Specifications & Policies
            </span>
          </div>

          <div className="space-y-2 text-[#8CA3A8] text-xs">
            <p>
              AgentBreak is configured with active defense policies for in-flight guardrail interception:
            </p>
            <ul className="list-disc list-inside space-y-1 text-[11px] text-[#8CA3A8]">
              <li><span className="font-mono text-[#BCD0D3]">POL-108:</span> Strict Path Boundary Traversal Guard</li>
              <li><span className="font-mono text-[#BCD0D3]">POL-204:</span> Read-Only AST SQL Sanitization Enforcement</li>
              <li><span className="font-mono text-[#BCD0D3]">POL-301:</span> Token Delimiter Collision & Secret Redaction</li>
              <li><span className="font-mono text-[#BCD0D3]">POL-402:</span> Outbound Network Egress CIDR Allowlisting</li>
              <li><span className="font-mono text-[#BCD0D3]">POL-501:</span> High-Consequence Action Confirmation Gate</li>
            </ul>
          </div>

          <div className="p-3 rounded bg-[#002B36] border border-[#124A58] text-[11px] text-[#8CA3A8] space-y-1">
            <div className="font-medium text-[#E3EEEE] flex items-center gap-1">
              <Info className="w-3.5 h-3.5 text-[#6DBAC6]" />
              <span>Production Security Note:</span>
            </div>
            <p className="leading-relaxed">
              In production environments, target AI agents should be deployed inside isolated container networks.
              Do not connect live financial or production infrastructure to non-sandboxed test runners.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
