import React from 'react';
import { AssessmentReport, SecurityScan } from '../types';
import { PageHeader } from '../components/layout/PageHeader';
import { ReportPreview } from '../components/reports/ReportPreview';

interface ReportPageProps {
  report: AssessmentReport;
  scans: SecurityScan[];
  onSelectScanForReport: (scanId: string) => void;
}

export const ReportPage: React.FC<ReportPageProps> = ({
  report,
  scans,
  onSelectScanForReport,
}) => {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Assessment Reports"
        subtitle="Audit-grade reports detailing adversarial evaluation scope, vulnerability dossiers, reproduction steps, and verified mitigations."
      />

      {/* Scan Report Switcher */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1">
        <span className="text-xs font-medium text-[#8CA3A8] shrink-0 pr-1">
          Scan Report:
        </span>
        {scans.map((s) => {
          const isSelected = s.id === report.scanId;
          return (
            <button
              key={s.id}
              onClick={() => onSelectScanForReport(s.id)}
              className={`flex items-center gap-2 px-3 py-1.5 rounded border text-xs font-sans whitespace-nowrap transition-colors ${
                isSelected
                  ? 'bg-[#0E4452] border-[#2B7F8C] text-[#BFE3E8] font-medium'
                  : 'bg-[#002B36] border-[#124A58] text-[#8CA3A8] hover:text-[#E3EEEE] hover:bg-[#073642]'
              }`}
            >
              <span>{s.agentName}</span>
              <span className="font-mono text-[#BCD0D3]">({s.id.substring(0, 10)}…)</span>
            </button>
          );
        })}
      </div>

      <ReportPreview report={report} />
    </div>
  );
};
