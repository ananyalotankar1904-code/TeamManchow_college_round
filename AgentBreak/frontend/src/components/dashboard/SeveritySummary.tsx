import React from 'react';

interface SeveritySummaryProps {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  blocked: number;
}

export const SeveritySummary: React.FC<SeveritySummaryProps> = ({
  critical,
  high,
  medium,
  low,
  info,
  blocked,
}) => {
  const total = critical + high + medium + low + info;
  const criticalPct = total > 0 ? (critical / total) * 100 : 0;
  const highPct = total > 0 ? (high / total) * 100 : 0;
  const mediumPct = total > 0 ? (medium / total) * 100 : 0;
  const lowPct = total > 0 ? (low / total) * 100 : 0;
  const infoPct = total > 0 ? (info / total) * 100 : 0;

  return (
    <div className="p-4 rounded border border-[#124A58] bg-[#073642] space-y-3.5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-xs font-sans font-semibold text-[#E3EEEE]">
            Severity Breakdown
          </span>
          <span className="text-xs text-[#5F7C82] font-sans">({total} Confirmed Findings)</span>
        </div>
        <div className="text-xs font-sans text-[#A6D6B7] bg-[#1D3D33] border border-[#285547] px-2 py-0.5 rounded">
          {blocked} Attacks Blocked by Policy
        </div>
      </div>

      {/* Proportional Stacked Bar */}
      <div className="h-2.5 w-full bg-[#002B36] border border-[#124A58] rounded-sm overflow-hidden flex">
        {criticalPct > 0 && (
          <div
            style={{ width: `${criticalPct}%` }}
            className="bg-[#D9776B] h-full"
            title={`Critical: ${critical} (${Math.round(criticalPct)}%)`}
          />
        )}
        {highPct > 0 && (
          <div
            style={{ width: `${highPct}%` }}
            className="bg-[#D39A5B] h-full"
            title={`High: ${high} (${Math.round(highPct)}%)`}
          />
        )}
        {mediumPct > 0 && (
          <div
            style={{ width: `${mediumPct}%` }}
            className="bg-[#C8AE5A] h-full"
            title={`Medium: ${medium} (${Math.round(mediumPct)}%)`}
          />
        )}
        {lowPct > 0 && (
          <div
            style={{ width: `${lowPct}%` }}
            className="bg-[#8CA3A8] h-full"
            title={`Low: ${low} (${Math.round(lowPct)}%)`}
          />
        )}
        {infoPct > 0 && (
          <div
            style={{ width: `${infoPct}%` }}
            className="bg-[#5F7C82] h-full"
            title={`Info: ${info} (${Math.round(infoPct)}%)`}
          />
        )}
        {total === 0 && (
          <div className="w-full bg-[#1D3D33] h-full flex items-center justify-center text-[10px] font-sans text-[#A6D6B7]">
            Clean — No Active Findings
          </div>
        )}
      </div>

      {/* Badges Legend */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-1 font-sans">
        <div className="flex items-center justify-between p-2 rounded bg-[#002B36] border border-[#124A58]">
          <span className="text-xs text-[#8CA3A8]">Critical</span>
          <span className="font-mono font-bold text-xs text-[#E08A7E]">{critical}</span>
        </div>
        <div className="flex items-center justify-between p-2 rounded bg-[#002B36] border border-[#124A58]">
          <span className="text-xs text-[#8CA3A8]">High</span>
          <span className="font-mono font-bold text-xs text-[#D9A468]">{high}</span>
        </div>
        <div className="flex items-center justify-between p-2 rounded bg-[#002B36] border border-[#124A58]">
          <span className="text-xs text-[#8CA3A8]">Medium</span>
          <span className="font-mono font-bold text-xs text-[#CDB866]">{medium}</span>
        </div>
        <div className="flex items-center justify-between p-2 rounded bg-[#002B36] border border-[#124A58]">
          <span className="text-xs text-[#8CA3A8]">Low</span>
          <span className="font-mono font-bold text-xs text-[#8CA3A8]">{low}</span>
        </div>
        <div className="flex items-center justify-between p-2 rounded bg-[#002B36] border border-[#124A58]">
          <span className="text-xs text-[#8CA3A8]">Blocked</span>
          <span className="font-mono font-bold text-xs text-[#78B993]">{blocked}</span>
        </div>
      </div>
    </div>
  );
};

