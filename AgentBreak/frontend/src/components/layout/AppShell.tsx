import React, { useState } from 'react';
import { Sidebar, NavTab } from './Sidebar';
import { Topbar } from './Topbar';
import { ApiConnectionStatus, Agent, AttackCategory } from '../../types';
import { ScanConfigurationForm } from '../scans/ScanConfigurationForm';
import { X, Flame } from 'lucide-react';

interface AppShellProps {
  children: React.ReactNode;
  activeTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  status: ApiConnectionStatus;
  onRefreshHealth: () => void;
  onToggleDemoMode: () => void;
  agents: Agent[];
  onStartNewScan: (config: {
    agentId: string;
    categories: AttackCategory[];
    mode: 'fast' | 'comprehensive' | 'adversarial';
  }) => Promise<void>;
  criticalFindingsCount?: number;
  subTitle?: string;
}

export const AppShell: React.FC<AppShellProps> = ({
  children,
  activeTab,
  onTabChange,
  status,
  onRefreshHealth,
  onToggleDemoMode,
  agents,
  onStartNewScan,
  criticalFindingsCount = 2,
  subTitle,
}) => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [showScanModal, setShowScanModal] = useState(false);

  const getTabDisplayName = (tab: NavTab): string => {
    switch (tab) {
      case 'dashboard':
        return 'Security Overview';
      case 'agents':
        return 'Target AI Agents';
      case 'scans':
        return 'Security Scans';
      case 'findings':
        return 'Vulnerability Findings';
      case 'traces':
        return 'Attack Traces';
      case 'fixloop':
        return 'FixLoop™ Verification';
      case 'reports':
        return 'Security Reports';
      case 'settings':
        return 'Settings & Lab';
      default:
        return 'Dashboard';
    }
  };

  const handleLaunchScanFromModal = async (config: {
    agentId: string;
    categories: AttackCategory[];
    mode: 'fast' | 'comprehensive' | 'adversarial';
  }) => {
    setShowScanModal(false);
    onTabChange('scans');
    await onStartNewScan(config);
  };

  return (
    <div className="min-h-screen bg-cyber-bg text-cyber-primary flex">
      {/* Persistent Left Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onTabChange={onTabChange}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        criticalCount={criticalFindingsCount}
      />

      {/* Main Container */}
      <div
        className={`flex-1 flex flex-col min-h-screen transition-all duration-200 ${
          sidebarCollapsed ? 'pl-16' : 'pl-60'
        }`}
      >
        {/* Persistent Topbar */}
        <Topbar
          currentTabName={getTabDisplayName(activeTab)}
          subTitle={subTitle}
          status={status}
          onRefreshHealth={onRefreshHealth}
          onToggleDemoMode={onToggleDemoMode}
          onNewScan={() => setShowScanModal(true)}
          sidebarCollapsed={sidebarCollapsed}
        />

        {/* Demo Mode Banner notice if offline or forced demo */}
        {status.isDemoMode && (
          <div className="mt-14 px-4 py-1.5 bg-[#332E1E] border-b border-[#4A4228] text-[11px] font-sans text-[#E2C98F] flex items-center justify-between select-none">
            <div className="flex items-center gap-2 truncate">
              <span className="px-1.5 py-0.5 bg-[#4A4228] border border-[#5E5434] rounded text-[10px] font-medium text-[#F2FAFA] uppercase">
                Demo Mode
              </span>
              <span className="truncate">
                Running in local demonstration mode. Adversarial vectors and FixLoop verifications use deterministic cybersecurity fixtures.
              </span>
            </div>
            <button
              onClick={onToggleDemoMode}
              className="text-[#E2C98F] hover:text-[#F2FAFA] hover:underline text-[10px] shrink-0 font-medium ml-2"
            >
              Switch to Live API
            </button>
          </div>
        )}

        {/* Main Content Area */}
        <main className={`flex-1 p-5 md:p-7 max-w-7xl w-full mx-auto ${status.isDemoMode ? 'mt-0' : 'mt-14'}`}>
          {children}
        </main>
      </div>

      {/* Quick Launch Scan Modal */}
      {showScanModal && (
        <div className="fixed inset-0 z-50 bg-[#002B36]/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-3xl bg-[#073642] border border-[#124A58] rounded-lg shadow-elevated overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#124A58] bg-[#01212A]">
              <div className="flex items-center gap-2">
                <Flame className="w-4 h-4 text-[#D39A5B]" />
                <span className="font-sans text-xs font-semibold text-[#E3EEEE]">
                  Launch Adversarial Security Scan
                </span>
              </div>
              <button
                onClick={() => setShowScanModal(false)}
                className="text-[#8CA3A8] hover:text-[#E3EEEE] p-1 rounded hover:bg-[#073642]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 max-h-[80vh] overflow-y-auto">
              <ScanConfigurationForm
                agents={agents}
                onStartScan={handleLaunchScanFromModal}
                onCancel={() => setShowScanModal(false)}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
