import React from 'react';
import { FixLoopSession, SecurityFinding } from '../types';
import { PageHeader } from '../components/layout/PageHeader';
import { FixLoopPanel } from '../components/fixloop/FixLoopPanel';

interface FixLoopPageProps {
  session: FixLoopSession;
  allFindings: SecurityFinding[];
  onSelectFinding: (findingId: string) => void;
  onApplyMitigation: (findingId: string, customPatch?: string) => Promise<void>;
  onRunRetest: (findingId: string) => Promise<void>;
  onRunRegressionSuite: (findingId: string) => Promise<void>;
}

export const FixLoopPage: React.FC<FixLoopPageProps> = ({
  session,
  allFindings,
  onSelectFinding,
  onApplyMitigation,
  onRunRetest,
  onRunRegressionSuite,
}) => {
  return (
    <div className="space-y-6">
      <PageHeader
        title="FixLoop™ Remediation & Regression Verification"
        subtitle="5-stage engineering workflow to review mitigation patches, rerun targeted adversarial vectors, and evaluate benign regressions."
        badge={
          <span className="px-2 py-0.5 rounded border border-[#2B7F8C] bg-[#0E4452] text-[#BFE3E8] font-sans text-xs font-medium">
            Verification Engine
          </span>
        }
      />

      <FixLoopPanel
        session={session}
        allFindings={allFindings}
        onSelectFinding={onSelectFinding}
        onApplyMitigation={onApplyMitigation}
        onRunRetest={onRunRetest}
        onRunRegressionSuite={onRunRegressionSuite}
      />
    </div>
  );
};
