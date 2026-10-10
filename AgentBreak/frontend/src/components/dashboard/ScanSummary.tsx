import React from 'react';
import { Bot, ShieldAlert, AlertTriangle, Activity } from 'lucide-react';

interface ScanSummaryProps {
  agentsCount: number;
  scansCount: number;
  criticalCount: number;
  reviewRequiredCount: number;
  blockedCount: number;
}

export const ScanSummary: React.FC<ScanSummaryProps> = ({
  agentsCount,
  scansCount,
  criticalCount,
  reviewRequiredCount,
  blockedCount,
}) => {
  const metrics = [
    {
      id: 'agents',
      label: 'Agents Configured',
      value: agentsCount,
      subtext: 'Registered targets under evaluation',
      icon: Bot,
      color: 'text-[#6DBAC6]',
      numColor: 'text-[#E3EEEE]',
      border: 'border-[#124A58]',
      bg: 'bg-[#073642]',
    },
    {
      id: 'scans',
      label: 'Scans Completed',
      value: scansCount,
      subtext: `${blockedCount} attacks verified blocked`,
      icon: Activity,
      color: 'text-[#78B993]',
      numColor: 'text-[#78B993]',
      border: 'border-[#124A58]',
      bg: 'bg-[#073642]',
    },
    {
      id: 'critical',
      label: 'Critical Findings',
      value: criticalCount,
      subtext: 'Exploitable vulnerability criteria met',
      icon: ShieldAlert,
      color: 'text-[#E08A7E]',
      numColor: 'text-[#E08A7E]',
      labelColor: 'text-[#E3A39A]',
      border: criticalCount > 0 ? 'border-[#5A3A3C]' : 'border-[#124A58]',
      bg: criticalCount > 0 ? 'bg-[#2E2C32]' : 'bg-[#073642]',
    },
    {
      id: 'review',
      label: 'Requiring Review',
      value: reviewRequiredCount,
      subtext: 'Open findings & pending FixLoop tests',
      icon: AlertTriangle,
      color: 'text-[#D39A5B]',
      numColor: 'text-[#D9A468]',
      border: 'border-[#124A58]',
      bg: 'bg-[#073642]',
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
      {metrics.map((m) => {
        const Icon = m.icon;
        return (
          <div
            key={m.id}
            className={`p-4 rounded border ${m.border} ${m.bg} transition-all duration-150 flex flex-col justify-between`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className={`text-xs font-sans font-medium ${m.labelColor || 'text-[#8CA3A8]'}`}>
                {m.label}
              </span>
              <Icon className={`w-4 h-4 ${m.color}`} />
            </div>
            <div className="flex items-baseline gap-2">
              <span className={`text-2xl font-bold font-mono tracking-tight ${m.numColor || m.color}`}>
                {m.value}
              </span>
            </div>
            <div className="text-xs text-[#5F7C82] font-sans mt-1.5 truncate">{m.subtext}</div>
          </div>
        );
      })}
    </div>
  );
};

