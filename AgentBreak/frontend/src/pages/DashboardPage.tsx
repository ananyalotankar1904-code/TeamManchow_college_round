import React from 'react';
import { Agent, SecurityScan, SecurityFinding, FixLoopSession } from '../types';
import { PageHeader } from '../components/layout/PageHeader';
import { ScanSummary } from '../components/dashboard/ScanSummary';
import { SeveritySummary } from '../components/dashboard/SeveritySummary';
import { RecentScansTable } from '../components/dashboard/RecentScansTable';
import { VulnerabilityDistribution } from '../components/dashboard/VulnerabilityDistribution';
import { IdBadge } from '../components/common/IdBadge';
import { SeverityBadge } from '../components/findings/SeverityBadge';
import { OutcomeBadge } from '../components/common/OutcomeBadge';
import { Flame, ShieldAlert, RotateCcw, ChevronRight, ArrowUpRight } from 'lucide-react';

interface DashboardPageProps {
  agents: Agent[];
  scans: SecurityScan[];
  findings: SecurityFinding[];
  fixLoopSession?: FixLoopSession;
  onNavigateTab: (tab: any) => void;
  onSelectScan: (scanId: string) => void;
  onSelectFinding: (findingId: string) => void;
  onNewScan: () => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  agents,
  scans,
  findings,
  onNavigateTab,
  onSelectScan,
  onSelectFinding,
  onNewScan,
}) => {
  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;
  const mediumCount = findings.filter((f) => f.severity === 'medium').length;
  const lowCount = findings.filter((f) => f.severity === 'low').length;
  const infoCount = findings.filter((f) => f.severity === 'info').length;

  const totalBlocked = scans.reduce((acc, s) => acc + (s.blockedAttacks || 0), 0);
  const openFindingsCount = findings.filter((f) => f.status === 'open' || f.status === 'under_review').length;

  const latestCriticalFindings = findings
    .filter((f) => f.severity === 'critical' || f.severity === 'high')
    .slice(0, 3);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="Security Overview"
        subtitle="Assessment activity, findings, and agent risk across local evaluation suites."
        actions={
          <button
            onClick={onNewScan}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-[#2B7F8C] hover:bg-[#3596A5] text-[#F2FAFA] border border-[#3596A5] rounded text-xs font-sans font-medium transition-colors shadow-subtle"
          >
            <Flame className="w-3.5 h-3.5 text-[#F2FAFA]" />
            <span>Run Security Scan</span>
          </button>
        }
      />

      {/* Top Metrics Cards */}
      <ScanSummary
        agentsCount={agents.length}
        scansCount={scans.length}
        criticalCount={criticalCount}
        reviewRequiredCount={openFindingsCount}
        blockedCount={totalBlocked}
      />

      {/* Practical 2-Column Dashboard Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Column (7 cols): Severity breakdown & Recent Scans Table */}
        <div className="lg:col-span-7 space-y-5">
          <SeveritySummary
            critical={criticalCount}
            high={highCount}
            medium={mediumCount}
            low={lowCount}
            info={infoCount}
            blocked={totalBlocked}
          />

          <RecentScansTable
            scans={scans}
            onSelectScan={onSelectScan}
            onViewAllScans={() => onNavigateTab('scans')}
          />
        </div>

        {/* Right Column (5 cols): Latest critical findings, category matrix & FixLoop widget */}
        <div className="lg:col-span-5 space-y-5">
          {/* Latest Critical / High Findings Card */}
          <div className="rounded border border-[#124A58] bg-[#073642] overflow-hidden">
            <div className="px-4 py-2.5 border-b border-[#124A58] flex items-center justify-between bg-[#01212A]">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-[#D9776B]" />
                <span className="text-xs font-sans font-semibold text-[#E3EEEE]">
                  Priority Findings
                </span>
              </div>
              <button
                onClick={() => onNavigateTab('findings')}
                className="text-xs font-sans text-[#6DBAC6] hover:text-[#BFE3E8] flex items-center gap-1 font-medium"
              >
                <span>All findings</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="p-3 space-y-2">
              {latestCriticalFindings.map((f) => (
                <div
                  key={f.id}
                  onClick={() => onSelectFinding(f.id)}
                  className="p-2.5 rounded bg-[#002B36] border border-[#124A58] hover:border-[#2B7F8C] cursor-pointer transition-all space-y-1.5 group"
                >
                  <div className="flex items-center justify-between">
                    <IdBadge id={f.id} />
                    <SeverityBadge severity={f.severity} size="sm" />
                  </div>
                  <div className="font-medium text-xs text-[#E3EEEE] group-hover:text-[#6DBAC6] transition-colors line-clamp-1 font-sans">
                    {f.title}
                  </div>
                  <div className="flex items-center justify-between text-xs text-[#5F7C82] pt-1 border-t border-[#124A58] font-sans">
                    <span className="text-[11px] text-[#8CA3A8]">Agent: {f.agentName}</span>
                    <OutcomeBadge outcome={f.outcome} size="sm" />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Vulnerability Distribution */}
          <VulnerabilityDistribution categoryCounts={{}} />

          {/* FixLoop Remediation Verification Widget */}
          <div className="p-4 rounded border border-[#124A58] bg-[#073642] space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-[#124A58]">
              <div className="flex items-center gap-2">
                <RotateCcw className="w-4 h-4 text-[#6DBAC6]" />
                <span className="text-xs font-sans font-semibold text-[#E3EEEE]">
                  FixLoop Remediation Status
                </span>
              </div>
              <span className="px-2 py-0.5 rounded bg-[#1D3D33] border border-[#285547] text-[#A6D6B7] font-sans text-[11px] font-medium">
                Active
              </span>
            </div>

            <div className="text-xs text-[#8CA3A8] leading-relaxed font-sans">
              Remediation verification workflow for <span className="text-[#BCD0D3] font-mono">FND-2026-0891</span>:
              Dual-context prompt isolation verified with 12/12 benign regression passes.
            </div>

            <button
              onClick={() => onNavigateTab('fixloop')}
              className="w-full py-2 bg-[#0E4452] hover:bg-[#2B7F8C] text-[#BFE3E8] hover:text-[#F2FAFA] rounded border border-[#124A58] hover:border-[#3596A5] text-xs font-sans font-medium flex items-center justify-center gap-1.5 transition-all"
            >
              <span>Open FixLoop Verification Console</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

