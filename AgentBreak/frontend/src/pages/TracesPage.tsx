import React, { useState } from 'react';
import { SecurityFinding } from '../types';
import { PageHeader } from '../components/layout/PageHeader';
import { TraceTimeline } from '../components/traces/TraceTimeline';
import {
  MOCK_TRACE_EVENTS_RAG,
  MOCK_TRACE_EVENTS_SQL,
  MOCK_TRACE_EVENTS_BLOCKED_PATH,
} from '../mocks/scanData';

interface TracesPageProps {
  initialTraceId?: string;
  findings: SecurityFinding[];
  onSelectFinding: (findingId: string) => void;
}

export const TracesPage: React.FC<TracesPageProps> = ({
  initialTraceId = 'tr_rag_exfil_01',
  onSelectFinding,
}) => {
  const [selectedTraceId, setSelectedTraceId] = useState<string>(initialTraceId);

  const traceOptions = [
    {
      id: 'tr_rag_exfil_01',
      label: 'RAG Indirect Injection & Credential Egress',
      findingId: 'FND-2026-0891',
      events: MOCK_TRACE_EVENTS_RAG,
      agent: 'Financial Intel Copilot',
      status: 'VIOLATION',
    },
    {
      id: 'tr_sql_inj_02',
      label: 'Stacked Multi-turn SQL DROP TABLE Injection',
      findingId: 'FND-2026-0892',
      events: MOCK_TRACE_EVENTS_SQL,
      agent: 'Financial Intel Copilot',
      status: 'VIOLATION',
    },
    {
      id: 'tr_blocked_path_04',
      label: 'Directory Traversal Attempt (Interception)',
      findingId: 'FND-2026-0894',
      events: MOCK_TRACE_EVENTS_BLOCKED_PATH,
      agent: 'Financial Intel Copilot',
      status: 'BLOCKED',
    },
  ];

  const currentTrace =
    traceOptions.find((t) => t.id === selectedTraceId) || traceOptions[0];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Attack Execution Traces"
        subtitle="Chronological audit logs of vector prompts, model decisions, tool calls, and in-flight policy interventions."
      />

      {/* Trace Selection Switcher */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1">
        <span className="text-xs font-medium text-[#8CA3A8] shrink-0 pr-1">
          Select Trace Stream:
        </span>
        {traceOptions.map((trace) => {
          const isSelected = trace.id === currentTrace.id;
          return (
            <button
              key={trace.id}
              onClick={() => setSelectedTraceId(trace.id)}
              className={`flex items-center gap-2 px-3 py-1.5 rounded border text-xs font-sans whitespace-nowrap transition-colors ${
                isSelected
                  ? 'bg-[#0E4452] border-[#2B7F8C] text-[#BFE3E8] font-medium'
                  : 'bg-[#002B36] border-[#124A58] text-[#8CA3A8] hover:text-[#E3EEEE] hover:border-[#185B6C]'
              }`}
            >
              <span>{trace.label}</span>
              {trace.status === 'VIOLATION' ? (
                <span className="px-1.5 py-0.5 rounded bg-[#4A2F31] border border-[#5A3A3C] text-[#F0B3AA] text-[10px] font-medium">
                  Violation
                </span>
              ) : (
                <span className="px-1.5 py-0.5 rounded bg-[#1D3D33] border border-[#285547] text-[#A6D6B7] text-[10px] font-medium">
                  Blocked
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Trace Timeline View */}
      <TraceTimeline
        events={currentTrace.events}
        traceId={currentTrace.id}
        findingTitle={currentTrace.label}
        onJumpToFinding={(id) => onSelectFinding(id)}
      />
    </div>
  );
};
