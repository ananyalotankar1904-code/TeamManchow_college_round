import React from 'react';
import { SecurityFinding } from '../../types';
import { IdBadge } from '../common/IdBadge';
import { SeverityBadge } from '../findings/SeverityBadge';
import { OutcomeBadge } from '../common/OutcomeBadge';
import { ChevronRight } from 'lucide-react';

interface ScanResultsTableProps {
  findings: SecurityFinding[];
  onSelectFinding: (findingId: string) => void;
  onOpenFixLoop?: (findingId: string) => void;
}

export const ScanResultsTable: React.FC<ScanResultsTableProps> = ({
  findings,
  onSelectFinding,
  onOpenFixLoop,
}) => {
  const getCategoryLabel = (cat: string) => {
    switch (cat) {
      case 'indirect_rag_injection':
        return 'Indirect RAG Injection';
      case 'direct_prompt_injection':
        return 'Direct Prompt Injection';
      case 'unauthorized_tool_execution':
        return 'Unauthorized Tool Exec';
      case 'sensitive_data_leakage':
        return 'Sensitive Data Leakage';
      case 'permission_policy_violation':
        return 'Policy Boundary Violation';
      case 'unsafe_action_execution':
        return 'Unsafe Action Execution';
      default:
        return cat.replace(/_/g, ' ');
    }
  };

  return (
    <div className="rounded border border-[#124A58] bg-[#073642] overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b border-[#124A58] bg-[#002B36] font-sans text-xs text-[#8CA3A8] font-medium select-none">
              <th className="py-2.5 px-3">Finding ID</th>
              <th className="py-2.5 px-3">Severity</th>
              <th className="py-2.5 px-3">Attack Category</th>
              <th className="py-2.5 px-3">Finding Title</th>
              <th className="py-2.5 px-3">Observed Outcome</th>
              <th className="py-2.5 px-3">Affected Tool / Target</th>
              <th className="py-2.5 px-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#124A58]">
            {findings.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-[#5F7C82] font-sans text-xs">
                  No findings match the selected filters.
                </td>
              </tr>
            ) : (
              findings.map((finding) => {
                return (
                  <tr
                    key={finding.id}
                    onClick={() => onSelectFinding(finding.id)}
                    className="hover:bg-[#0A3F4D] cursor-pointer transition-colors group font-sans h-10"
                  >
                    <td className="py-2 px-3 font-mono">
                      <IdBadge id={finding.id} truncateLength={12} />
                    </td>
                    <td className="py-2 px-3">
                      <SeverityBadge severity={finding.severity} size="sm" />
                    </td>
                    <td className="py-2 px-3 font-sans text-xs text-[#8CA3A8]">
                      <span className="px-2 py-0.5 rounded bg-[#002B36] border border-[#124A58] text-[11px]">
                        {getCategoryLabel(finding.category)}
                      </span>
                    </td>
                    <td className="py-2 px-3 max-w-sm">
                      <div className="font-medium text-[#E3EEEE] group-hover:text-[#6DBAC6] transition-colors truncate">
                        {finding.title}
                      </div>
                      <div className="text-[11px] text-[#5F7C82] truncate">
                        Agent: {finding.agentName}
                      </div>
                    </td>
                    <td className="py-2 px-3">
                      <OutcomeBadge outcome={finding.outcome} size="sm" />
                    </td>
                    <td className="py-2 px-3 font-mono text-[11px] text-[#8CA3A8]">
                      {finding.affectedTool ? (
                        <span className="text-[#6DBAC6]">{finding.affectedTool}</span>
                      ) : (
                        <span className="text-[#5F7C82] font-sans">None</span>
                      )}
                    </td>
                    <td className="py-2 px-3 text-right">
                      <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                        {onOpenFixLoop && finding.outcome === 'confirmed_vulnerable' && (
                          <button
                            onClick={() => onOpenFixLoop(finding.id)}
                            className="px-2 py-0.5 bg-[#0E4452] hover:bg-[#2B7F8C] border border-[#124A58] text-[#BFE3E8] hover:text-[#F2FAFA] rounded text-xs font-sans font-medium transition-colors"
                            title="Verify remediation in FixLoop"
                          >
                            FixLoop
                          </button>
                        )}
                        <button
                          onClick={() => onSelectFinding(finding.id)}
                          className="p-1 text-[#8CA3A8] hover:text-[#E3EEEE] hover:bg-[#0E4452] rounded transition-colors"
                          title="View finding investigation details"
                        >
                          <ChevronRight className="w-4 h-4" />
                        </button>
                      </div>
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

