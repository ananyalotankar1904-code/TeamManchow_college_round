import React, { useState, useEffect } from 'react';
import { SecurityFinding, TraceEvent } from '../types';
import { PageHeader } from '../components/layout/PageHeader';
import { TraceTimeline } from '../components/traces/TraceTimeline';
import { api, ApiError } from '../services/api';
import {
  MOCK_TRACE_EVENTS_RAG,
  MOCK_TRACE_EVENTS_SQL,
  MOCK_TRACE_EVENTS_BLOCKED_PATH,
} from '../mocks/scanData';
import { Loader2, AlertTriangle, Info } from 'lucide-react';

interface TracesPageProps {
  initialTraceId?: string;
  findings: SecurityFinding[];
  onSelectFinding: (findingId: string) => void;
}

const DEMO_TRACE_OPTIONS = [
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

export const TracesPage: React.FC<TracesPageProps> = ({
  initialTraceId = 'tr_rag_exfil_01',
  findings,
  onSelectFinding,
}) => {
  const apiStatus = api.getStatus();
  const isLiveMode = !apiStatus.isDemoMode && apiStatus.connected;

  // ── Demo mode: fixed mock trace list ────────────────────────────────────────
  const [selectedDemoTraceId, setSelectedDemoTraceId] = useState<string>(initialTraceId);

  // ── Live mode: derive trace list from findings that have a trace_id ──────────
  const liveTraceOptions = React.useMemo(() => {
    return findings
      .filter((f) => (f as any).traceId || (f as any).trace_id)
      .map((f) => ({
        id: (f as any).traceId || (f as any).trace_id,
        label: f.title || `Trace for ${f.id.substring(0, 8)}`,
        findingId: f.id,
        agent: f.agentName,
        status: f.outcome === 'blocked' ? 'BLOCKED' : 'VIOLATION',
      }));
  }, [findings]);

  const [selectedLiveTraceId, setSelectedLiveTraceId] = useState<string | null>(null);
  const [liveEvents, setLiveEvents] = useState<TraceEvent[] | null>(null);
  const [isLoadingTrace, setIsLoadingTrace] = useState(false);
  const [traceError, setTraceError] = useState<string | null>(null);

  // When live mode initialTraceId changes (e.g. user navigates from finding detail), select it
  useEffect(() => {
    if (isLiveMode) {
      // If initialTraceId looks like a UUID (live) select it; else pick first available
      const isUuid = /^[0-9a-f-]{30,}$/i.test(initialTraceId);
      if (isUuid) {
        setSelectedLiveTraceId(initialTraceId);
      } else if (liveTraceOptions.length > 0) {
        setSelectedLiveTraceId(liveTraceOptions[0].id);
      }
    }
  }, [isLiveMode, initialTraceId, liveTraceOptions]);

  // Fetch live trace events when selectedLiveTraceId changes
  useEffect(() => {
    if (!isLiveMode || !selectedLiveTraceId) return;

    let cancelled = false;
    setIsLoadingTrace(true);
    setTraceError(null);
    setLiveEvents(null);

    api
      .getTraceEvents(selectedLiveTraceId)
      .then((events) => {
        if (!cancelled) setLiveEvents(events);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          const status = err instanceof ApiError ? err.status : 0;
          if (status === 404) {
            setTraceError('Trace not found. The security engine did not record detailed step-by-step events for this test case.');
          } else {
            setTraceError(`Could not load trace: ${err instanceof Error ? err.message : 'Backend error'}`);
          }
        }
      })
      .finally(() => {
        if (!cancelled) setIsLoadingTrace(false);
      });

    return () => { cancelled = true; };
  }, [isLiveMode, selectedLiveTraceId]);

  // ── Demo mode render ─────────────────────────────────────────────────────────
  if (!isLiveMode) {
    const currentTrace =
      DEMO_TRACE_OPTIONS.find((t) => t.id === selectedDemoTraceId) || DEMO_TRACE_OPTIONS[0];

    return (
      <div className="space-y-6">
        <PageHeader
          title="Attack Execution Traces"
          subtitle="Chronological audit logs of vector prompts, model decisions, tool calls, and in-flight policy interventions."
        />

        <div className="flex items-center gap-2 overflow-x-auto pb-1">
          <span className="text-xs font-medium text-[#8CA3A8] shrink-0 pr-1">Select Trace Stream:</span>
          {DEMO_TRACE_OPTIONS.map((trace) => {
            const isSelected = trace.id === currentTrace.id;
            return (
              <button
                key={trace.id}
                onClick={() => setSelectedDemoTraceId(trace.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded border text-xs font-sans whitespace-nowrap transition-colors ${
                  isSelected
                    ? 'bg-[#0E4452] border-[#2B7F8C] text-[#BFE3E8] font-medium'
                    : 'bg-[#002B36] border-[#124A58] text-[#8CA3A8] hover:text-[#E3EEEE] hover:border-[#185B6C]'
                }`}
              >
                <span>{trace.label}</span>
                {trace.status === 'VIOLATION' ? (
                  <span className="px-1.5 py-0.5 rounded bg-[#4A2F31] border border-[#5A3A3C] text-[#F0B3AA] text-[10px] font-medium">Violation</span>
                ) : (
                  <span className="px-1.5 py-0.5 rounded bg-[#1D3D33] border border-[#285547] text-[#A6D6B7] text-[10px] font-medium">Blocked</span>
                )}
              </button>
            );
          })}
        </div>

        <TraceTimeline
          events={currentTrace.events}
          traceId={currentTrace.id}
          findingTitle={currentTrace.label}
          onJumpToFinding={(id) => onSelectFinding(id)}
        />
      </div>
    );
  }

  // ── Live mode render ─────────────────────────────────────────────────────────
  const currentLiveOption = liveTraceOptions.find((t) => t.id === selectedLiveTraceId) || liveTraceOptions[0];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Attack Execution Traces"
        subtitle="Live trace events fetched from the backend security engine for completed scan findings."
      />

      {/* Live mode badge */}
      <div className="flex items-center gap-2 px-3 py-2 rounded border border-[#2B7F8C] bg-[#062830] text-[#6DBAC6] text-xs font-sans">
        <Info className="w-3.5 h-3.5 shrink-0" />
        <span>Live mode — trace events are loaded from the backend. Only findings with a recorded <code className="font-mono text-[#BFE3E8]">trace_id</code> appear below.</span>
      </div>

      {liveTraceOptions.length === 0 ? (
        /* No traces at all */
        <div className="p-8 rounded border border-[#124A58] bg-[#073642] text-center space-y-2">
          <AlertTriangle className="w-5 h-5 text-[#E2C98F] mx-auto" />
          <p className="text-[#8CA3A8] text-sm font-sans">No trace events available.</p>
          <p className="text-[#5F7C82] text-xs font-sans">The current scan findings do not have associated trace IDs. The mock security engine does not emit detailed step-by-step traces.</p>
        </div>
      ) : (
        <>
          {/* Trace selector */}
          <div className="flex items-center gap-2 overflow-x-auto pb-1">
            <span className="text-xs font-medium text-[#8CA3A8] shrink-0 pr-1">Select Trace:</span>
            {liveTraceOptions.map((trace) => {
              const isSelected = trace.id === selectedLiveTraceId;
              return (
                <button
                  key={trace.id}
                  onClick={() => setSelectedLiveTraceId(trace.id)}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded border text-xs font-sans whitespace-nowrap transition-colors ${
                    isSelected
                      ? 'bg-[#0E4452] border-[#2B7F8C] text-[#BFE3E8] font-medium'
                      : 'bg-[#002B36] border-[#124A58] text-[#8CA3A8] hover:text-[#E3EEEE] hover:border-[#185B6C]'
                  }`}
                >
                  <span className="font-mono text-[10px] text-[#6DBAC6]">{trace.id.substring(0, 8)}…</span>
                  <span>{trace.label.substring(0, 40)}{trace.label.length > 40 ? '…' : ''}</span>
                  {trace.status === 'VIOLATION' ? (
                    <span className="px-1.5 py-0.5 rounded bg-[#4A2F31] border border-[#5A3A3C] text-[#F0B3AA] text-[10px] font-medium">Violation</span>
                  ) : (
                    <span className="px-1.5 py-0.5 rounded bg-[#1D3D33] border border-[#285547] text-[#A6D6B7] text-[10px] font-medium">Blocked</span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Trace content */}
          {isLoadingTrace && (
            <div className="p-8 text-center flex flex-col items-center gap-3">
              <Loader2 className="w-5 h-5 text-[#6DBAC6] animate-spin" />
              <span className="text-[#8CA3A8] text-xs font-sans">Fetching trace events from backend…</span>
            </div>
          )}

          {!isLoadingTrace && traceError && (
            <div className="p-5 rounded border border-[#4A3B1A] bg-[#2A1E0A] space-y-2">
              <div className="flex items-center gap-2 text-[#E2C98F] text-xs font-sans font-medium">
                <AlertTriangle className="w-4 h-4" />
                <span>Trace Unavailable</span>
              </div>
              <p className="text-[#8CA3A8] text-xs font-sans">{traceError}</p>
              <p className="text-[#5F7C82] text-[11px] font-sans">
                Trace ID: <code className="font-mono text-[#BCD0D3]">{selectedLiveTraceId}</code>
              </p>
            </div>
          )}

          {!isLoadingTrace && !traceError && liveEvents !== null && liveEvents.length === 0 && (
            <div className="p-5 rounded border border-[#124A58] bg-[#073642] text-center space-y-2">
              <AlertTriangle className="w-4 h-4 text-[#8CA3A8] mx-auto" />
              <p className="text-[#8CA3A8] text-sm font-sans">Trace found but contains no events.</p>
              <p className="text-[#5F7C82] text-xs font-sans">The backend trace record exists but the events array is empty. This is expected for mock/stub engine runs.</p>
            </div>
          )}

          {!isLoadingTrace && !traceError && liveEvents !== null && liveEvents.length > 0 && (
            <TraceTimeline
              events={liveEvents}
              traceId={selectedLiveTraceId || ''}
              findingTitle={currentLiveOption?.label || 'Live Trace'}
              onJumpToFinding={(id) => onSelectFinding(id)}
            />
          )}
        </>
      )}
    </div>
  );
};
