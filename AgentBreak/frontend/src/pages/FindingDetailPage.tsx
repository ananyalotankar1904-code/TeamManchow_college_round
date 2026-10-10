import React from 'react';
import { SecurityFinding } from '../types';
import { FindingDetailPanel } from '../components/findings/FindingDetailPanel';

interface FindingDetailPageProps {
  findingId?: string;
  findings: SecurityFinding[];
  onBack: () => void;
  onSelectFinding: (id: string) => void;
  onJumpToTrace: (traceId: string) => void;
  onOpenFixLoop: (findingId: string) => void;
  onViewReport: (scanId: string) => void;
}

export const FindingDetailPage: React.FC<FindingDetailPageProps> = ({
  findingId,
  findings,
  onBack,
  onJumpToTrace,
  onOpenFixLoop,
  onViewReport,
}) => {
  const currentFinding = findings.find((f) => f.id === findingId) || findings[0];

  if (!currentFinding) {
    return (
      <div className="p-8 text-center space-y-3 font-sans">
        <div className="text-[#8CA3A8] text-sm">No finding selected or finding ID not found.</div>
        <button
          onClick={onBack}
          className="px-4 py-2 bg-[#2B7F8C] hover:bg-[#3596A5] text-[#F2FAFA] rounded text-xs transition-colors"
        >
          Return to Findings
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <FindingDetailPanel
        finding={currentFinding}
        onBack={onBack}
        onJumpToTrace={onJumpToTrace}
        onOpenFixLoop={onOpenFixLoop}
        onViewReport={onViewReport}
      />
    </div>
  );
};
