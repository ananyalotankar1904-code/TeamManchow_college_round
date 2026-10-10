import React from 'react';
import { SecurityScan } from '../../types';
import { IdBadge } from '../common/IdBadge';
import { StatusBadge } from '../common/StatusBadge';
import { ChevronRight, Clock } from 'lucide-react';

interface RecentScansTableProps {
  scans: SecurityScan[];
  onSelectScan: (scanId: string) => void;
  onViewAllScans: () => void;
}

export const RecentScansTable: React.FC<RecentScansTableProps> = ({
  scans,
  onSelectScan,
  onViewAllScans,
}) => {
  return (
    <div className="rounded border border-[#124A58] bg-[#073642] overflow-hidden flex flex-col">
      {/* Header */}
      <div className="px-4 py-2.5 border-b border-[#124A58] flex items-center justify-between bg-[#01212A]">
        <div className="flex items-center gap-2">
          <span className="text-xs font-sans font-semibold text-[#E3EEEE]">
            Recent Security Scans
          </span>
          <span className="text-xs font-sans text-[#5F7C82]">({scans.length} Recorded)</span>
        </div>
        <button
          onClick={onViewAllScans}
          className="text-xs font-sans text-[#6DBAC6] hover:text-[#BFE3E8] flex items-center gap-1 transition-colors font-medium"
        >
          <span>View all scans</span>
          <ChevronRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b border-[#124A58] bg-[#002B36] font-sans text-xs text-[#8CA3A8] font-medium select-none">
              <th className="py-2 px-3">Scan ID</th>
              <th className="py-2 px-3">Target Agent & Mode</th>
              <th className="py-2 px-3">Timestamp (UTC)</th>
              <th className="py-2 px-3">Status</th>
              <th className="py-2 px-3">Findings</th>
              <th className="py-2 px-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#124A58]">
            {scans.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-[#5F7C82] font-sans text-xs">
                  No security scans executed yet. Run a scan to evaluate agent vulnerabilities.
                </td>
              </tr>
            ) : (
              scans.map((scan) => {
                const modeLabel =
                  scan.mode === 'adversarial'
                    ? 'Adversarial'
                    : scan.mode === 'comprehensive'
                    ? 'Comprehensive'
                    : 'Fast';

                return (
                  <tr
                    key={scan.id}
                    onClick={() => onSelectScan(scan.id)}
                    className="hover:bg-[#0A3F4D] cursor-pointer transition-colors group font-sans h-10"
                  >
                    <td className="py-2 px-3 font-mono">
                      <IdBadge id={scan.id} truncateLength={12} />
                    </td>
                    <td className="py-2 px-3">
                      <div className="flex items-center gap-1.5 text-xs">
                        <span className="font-medium text-[#E3EEEE] group-hover:text-[#6DBAC6] transition-colors">
                          {scan.agentName}
                        </span>
                        <span className="text-[#5F7C82]">·</span>
                        <span className="text-[#8CA3A8] text-[11px] font-sans">
                          {modeLabel}
                        </span>
                      </div>
                    </td>
                    <td className="py-2 px-3 font-mono text-[11px] text-[#BCD0D3] whitespace-nowrap">
                      <div className="flex items-center gap-1.5 text-[#BCD0D3]">
                        <Clock className="w-3 h-3 text-[#5F7C82] shrink-0" />
                        <span>{scan.createdAt.replace('T', ' ').substring(0, 19)}Z</span>
                      </div>
                    </td>
                    <td className="py-2 px-3">
                      <StatusBadge status={scan.status} size="sm" />
                    </td>
                    <td className="py-2 px-3">
                      <div className="flex items-center gap-1.5 text-xs">
                        {scan.confirmedFindings > 0 ? (
                          <span className="text-[#E08A7E] font-medium">
                            {scan.confirmedFindings} Vuln
                          </span>
                        ) : (
                          <span className="text-[#78B993] font-medium">
                            0 Vuln
                          </span>
                        )}
                        <span className="text-[#5F7C82]">/</span>
                        <span className="text-[#8CA3A8] text-[11px]">
                          {scan.blockedAttacks} Blocked
                        </span>
                      </div>
                    </td>
                    <td className="py-2 px-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectScan(scan.id);
                        }}
                        className="px-2 py-0.5 bg-[#0E4452] hover:bg-[#2B7F8C] hover:text-[#F2FAFA] text-[#BFE3E8] rounded text-xs font-sans transition-colors"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

