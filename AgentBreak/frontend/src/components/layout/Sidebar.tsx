import React from 'react';
import {
  ShieldAlert,
  LayoutDashboard,
  Bot,
  Flame,
  Search,
  Activity,
  RotateCcw,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
  Shield,
} from 'lucide-react';

export type NavTab =
  | 'dashboard'
  | 'agents'
  | 'scans'
  | 'findings'
  | 'traces'
  | 'fixloop'
  | 'reports'
  | 'settings';

interface SidebarProps {
  activeTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  criticalCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  collapsed,
  onToggleCollapse,
  criticalCount = 2,
}) => {
  const navItems: Array<{
    id: NavTab;
    label: string;
    icon: React.ElementType;
    badge?: string | number;
    badgeColor?: string;
  }> = [
    { id: 'dashboard', label: 'Security Overview', icon: LayoutDashboard },
    { id: 'agents', label: 'Target Agents', icon: Bot },
    { id: 'scans', label: 'Security Scans', icon: Flame },
    {
      id: 'findings',
      label: 'Findings',
      icon: Search,
      badge: criticalCount > 0 ? criticalCount : undefined,
      badgeColor: 'bg-[#4A2F31] text-[#F0B3AA] border-[#5A3A3C]',
    },
    { id: 'traces', label: 'Attack Traces', icon: Activity },
    {
      id: 'fixloop',
      label: 'FixLoop Verification',
      icon: RotateCcw,
    },
    { id: 'reports', label: 'Security Reports', icon: FileText },
    { id: 'settings', label: 'Settings & Lab', icon: Settings },
  ];

  return (
    <aside
      className={`fixed top-0 left-0 bottom-0 z-30 flex flex-col bg-[#01212A] border-r border-[#124A58] transition-all duration-200 select-none ${
        collapsed ? 'w-16' : 'w-60'
      }`}
    >
      {/* Brand Header */}
      <div className="h-14 flex items-center justify-between px-3.5 border-b border-[#124A58] bg-[#01212A]">
        <div
          className="flex items-center gap-2.5 cursor-pointer overflow-hidden"
          onClick={() => onTabChange('dashboard')}
        >
          <div className="w-8 h-8 rounded bg-[#073642] border border-[#124A58] flex items-center justify-center shrink-0 group hover:border-[#2B7F8C] transition-colors">
            <ShieldAlert className="w-4 h-4 text-[#2B7F8C]" />
          </div>
          {!collapsed && (
            <div className="flex flex-col">
              <span className="font-semibold text-sm text-[#E3EEEE] flex items-center gap-1 font-sans">
                Agent<span className="text-[#6DBAC6]">Break</span>
              </span>
              <span className="text-[11px] text-[#8CA3A8] font-sans">Security Console</span>
            </div>
          )}
        </div>

        {!collapsed && (
          <button
            onClick={onToggleCollapse}
            className="p-1 rounded text-[#5F7C82] hover:text-[#E3EEEE] hover:bg-[#073642] transition-colors"
            title="Collapse sidebar"
            aria-label="Collapse sidebar"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Nav List */}
      <nav className="flex-1 py-3 px-2 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;

          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={`w-full flex items-center gap-3 px-2.5 py-2 rounded text-xs font-medium font-sans transition-all ${
                isActive
                  ? 'bg-[#0E4452] text-[#BFE3E8] border border-[#124A58]'
                  : 'text-[#8CA3A8] hover:text-[#E3EEEE] hover:bg-[#073642] border border-transparent'
              }`}
              title={collapsed ? item.label : undefined}
            >
              <Icon
                className={`w-4 h-4 shrink-0 transition-colors ${
                  isActive ? 'text-[#6DBAC6]' : 'text-[#5F7C82] group-hover:text-[#8CA3A8]'
                }`}
              />
              {!collapsed && (
                <span className="flex-1 text-left truncate">{item.label}</span>
              )}
              {!collapsed && item.badge !== undefined && (
                <span
                  className={`px-1.5 py-0.2 rounded border font-mono text-[10px] font-semibold ${
                    item.badgeColor || 'bg-[#002B36] text-[#BCD0D3] border-[#124A58]'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Bottom Footer Info */}
      <div className="p-3 border-t border-[#124A58] bg-[#01212A] text-xs font-sans">
        {collapsed ? (
          <button
            onClick={onToggleCollapse}
            className="w-full py-1.5 flex justify-center text-[#5F7C82] hover:text-[#E3EEEE]"
            title="Expand sidebar"
            aria-label="Expand sidebar"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        ) : (
          <div className="flex items-center justify-between text-[#8CA3A8] text-[11px]">
            <span className="flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-[#6DBAC6]" />
              <span>AgentBreak v2.4</span>
            </span>
            <span className="text-[#5F7C82]">Local Lab</span>
          </div>
        )}
      </div>
    </aside>
  );
};

