import React, { useState, useEffect } from 'react';
import { SecurityFinding } from '../types';
import { FindingDetailPanel } from '../components/findings/FindingDetailPanel';
import { api } from '../services/api';
import { Loader2 } from 'lucide-react';

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
  const [asyncFinding, setAsyncFinding] = useState<SecurityFinding | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);

  // Synchronous lookup from passed findings array
  const propFinding = findings.find(
    (f) => f.id === findingId || (f as any).testId === findingId || (f as any).test_id === findingId
  ) || (findingId ? undefined : findings[0]);

  // Current active finding (props take precedence, followed by asynchronously fetched finding)
  const currentFinding = propFinding || asyncFinding;

  // Asynchronous fallback if not present in findings prop
  useEffect(() => {
    let isMounted = true;
    if (!propFinding && findingId) {
      setIsLoading(true);
      api
        .getFinding(findingId)
        .then((fetched) => {
          if (isMounted && fetched) {
            setAsyncFinding(fetched);
          }
        })
        .catch((err) => {
          console.warn('Could not load finding details:', err);
        })
        .finally(() => {
          if (isMounted) setIsLoading(false);
        });
    }
    return () => {
      isMounted = false;
    };
  }, [findingId, propFinding]);

  if (isLoading && !currentFinding) {
    return (
      <div className="p-12 text-center flex flex-col items-center justify-center space-y-3 font-sans">
        <Loader2 className="w-5 h-5 text-[#6DBAC6] animate-spin" />
        <div className="text-[#8CA3A8] text-xs">Loading finding dossier from security engine...</div>
      </div>
    );
  }

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
