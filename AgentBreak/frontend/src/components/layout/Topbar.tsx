import React, { useState } from 'react';
import {
  Flame,
  Radio,
  RefreshCw,
  Info,
  SlidersHorizontal,
  ChevronRight,
  Database,
} from 'lucide-react';
import { ApiConnectionStatus } from '../../types';

interface TopbarProps {
  currentTabName: string;
  subTitle?: string;
  status: ApiConnectionStatus;
  onRefreshHealth: () => void;
  onToggleDemoMode: () => void;
  onNewScan: () => void;
  sidebarCollapsed: boolean;
}

export const Topbar: React.FC<TopbarProps> = ({
  currentTabName,
  subTitle,
  status,
  onRefreshHealth,
  onToggleDemoMode,
  onNewScan,
  sidebarCollapsed,
}) => {
  const [showStatusPopover, setShowStatusPopover] = useState(false);

  return (
    <header
      className={`fixed top-0 right-0 z-20 h-14 bg-[#01303C]/95 backdrop-blur border-b border-[#124A58] transition-all duration-200 flex items-center justify-between px-4 select-none ${
        sidebarCollapsed ? 'left-16' : 'left-60'
      }`}
    >
      {/* Left: Breadcrumbs & Context */}
      <div className="flex items-center gap-2 font-sans text-xs">
        <span className="text-[#8CA3A8] font-medium">AgentBreak</span>
        <ChevronRight className="w-3.5 h-3.5 text-[#5F7C82]" />
        <span className="text-[#E3EEEE] font-medium">{currentTabName}</span>
        {subTitle && (
          <>
            <ChevronRight className="w-3.5 h-3.5 text-[#5F7C82]" />
            <span className="text-[#6DBAC6] font-normal truncate max-w-xs">{subTitle}</span>
          </>
        )}
      </div>

      {/* Right: Environment, Connection Pill & Primary Actions */}
      <div className="flex items-center gap-3">
        {/* Environment Tag */}
        <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded border border-[#124A58] bg-[#002B36] text-xs font-sans text-[#8CA3A8]">
          <Database className="w-3 h-3 text-[#5F7C82]" />
          <span>Local Lab</span>
        </div>

        {/* Backend / Demo Data Connection Pill */}
        <div className="relative">
          <button
            onClick={() => setShowStatusPopover(!showStatusPopover)}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded border font-sans text-xs font-medium transition-all ${
              status.connected
                ? 'bg-[#1D3D33] border-[#285547] text-[#A6D6B7] hover:bg-[#254F42]'
                : status.isDemoMode
                ? 'bg-[#332E1E] border-[#4A4228] text-[#E2C98F] hover:bg-[#423C27]'
                : 'bg-[#4A2F31] border-[#5A3A3C] text-[#F0B3AA] hover:bg-[#5C3A3C]'
            }`}
            title="Click to view backend connection details"
          >
            <Radio className={`w-3 h-3 ${status.connected ? 'text-[#78B993] animate-pulse' : ''}`} />
            <span>
              {status.connected
                ? `Connected · ${status.latencyMs || 12} ms`
                : status.isDemoMode
                ? 'Demo Data (Offline)'
                : 'Backend unavailable'}
            </span>
          </button>

          {/* Connection Details Dropdown Popover */}
          {showStatusPopover && (
            <div className="absolute right-0 mt-2 w-80 p-3.5 bg-[#073642] border border-[#124A58] rounded-md shadow-lg z-50 text-xs font-sans">
              <div className="flex items-center justify-between pb-2 border-b border-[#124A58] mb-2.5">
                <span className="font-semibold text-[#E3EEEE] text-xs">
                  Engine Connectivity
                </span>
                <button
                  onClick={onRefreshHealth}
                  className="p-1 rounded text-[#8CA3A8] hover:text-[#E3EEEE] hover:bg-[#0E4452] transition-colors"
                  title="Check health now"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="space-y-2 text-[#8CA3A8] text-xs">
                <div className="flex justify-between">
                  <span className="text-[#5F7C82]">Target Endpoint:</span>
                  <span className="font-mono text-[#BCD0D3] truncate max-w-[170px]">{status.endpoint}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#5F7C82]">Status:</span>
                  <span className={status.connected ? 'text-[#78B993] font-medium' : 'text-[#E2C98F] font-medium'}>
                    {status.connected ? 'Live Backend Connected' : 'Mock Demonstration Mode'}
                  </span>
                </div>
                {status.latencyMs !== undefined && (
                  <div className="flex justify-between">
                    <span className="text-[#5F7C82]">Latency:</span>
                    <span className="font-mono text-[#BCD0D3]">{status.latencyMs} ms</span>
                  </div>
                )}
                <div className="p-2 rounded bg-[#002B36] border border-[#124A58] text-[#8CA3A8] text-[11px] leading-relaxed">
                  <Info className="w-3 h-3 text-[#6DBAC6] inline mr-1 -mt-0.5" />
                  {status.message ||
                    'In demo mode, scans evaluate using offline adversarial cybersecurity scenario fixtures.'}
                </div>
              </div>

              <div className="pt-2.5 mt-2.5 border-t border-[#124A58] flex items-center justify-between">
                <button
                  onClick={onToggleDemoMode}
                  className="flex items-center gap-1.5 text-xs text-[#6DBAC6] hover:text-[#BFE3E8] font-medium"
                >
                  <SlidersHorizontal className="w-3 h-3" />
                  <span>{status.isDemoMode ? 'Switch to Live API' : 'Force Demo Mode'}</span>
                </button>
                <button
                  onClick={() => setShowStatusPopover(false)}
                  className="text-xs text-[#5F7C82] hover:text-[#8CA3A8]"
                >
                  Close
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Primary Action Button */}
        <button
          onClick={onNewScan}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-[#2B7F8C] hover:bg-[#3596A5] active:bg-[#1E6B78] text-[#F2FAFA] border border-[#3596A5] rounded font-medium text-xs transition-colors font-sans shadow-subtle"
        >
          <Flame className="w-3.5 h-3.5 text-[#F2FAFA]" />
          <span>New Scan</span>
        </button>
      </div>
    </header>
  );
};

