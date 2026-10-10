import React, { useState } from 'react';
import { TraceEvent } from '../../types';
import { TraceEventRow } from './TraceEventRow';
import { IdBadge } from '../common/IdBadge';
import { CodeBlock } from '../common/CodeBlock';
import {
  Activity,
  ShieldAlert,
  ShieldCheck,
  Layers,
  Info,
} from 'lucide-react';

interface TraceTimelineProps {
  events: TraceEvent[];
  traceId?: string;
  findingTitle?: string;
  onJumpToFinding?: (findingId: string) => void;
}

export const TraceTimeline: React.FC<TraceTimelineProps> = ({
  events,
  traceId = 'tr_rag_exfil_01',
  findingTitle,
  onJumpToFinding,
}) => {
  const [selectedEvent, setSelectedEvent] = useState<TraceEvent | null>(
    events.find((e) => e.isViolation || e.isPolicyBlock) || events[0] || null
  );

  const violationCount = events.filter((e) => e.isViolation).length;
  const blockedCount = events.filter((e) => e.isPolicyBlock).length;

  return (
    <div className="space-y-4">
      {/* Trace Header Summary Bar */}
      <div className="p-3.5 rounded border border-[#124A58] bg-[#073642] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded bg-[#002B36] border border-[#124A58] text-[#6DBAC6]">
            <Activity className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-[#E3EEEE] font-sans">Attack Execution Trace</span>
              <IdBadge id={traceId} prefix="TRACE" />
            </div>
            {findingTitle && <div className="text-[11px] text-[#8CA3A8] font-sans mt-0.5">{findingTitle}</div>}
          </div>
        </div>

        <div className="flex items-center gap-2">
          {violationCount > 0 && (
            <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-[#4A2F31] border border-[#5A3A3C] text-[#F0B3AA] font-medium text-[11px] font-sans">
              <ShieldAlert className="w-3 h-3" />
              <span>{violationCount} Unsafe Actions</span>
            </span>
          )}
          {blockedCount > 0 && (
            <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-[#1D3D33] border border-[#285547] text-[#A6D6B7] font-medium text-[11px] font-sans">
              <ShieldCheck className="w-3 h-3" />
              <span>{blockedCount} Policy Blocks</span>
            </span>
          )}
          <span className="text-[#8CA3A8] text-[11px] font-sans">({events.length} Timeline Nodes)</span>
        </div>
      </div>

      {/* Main 2-Column Inspector Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: Vertical Timeline Event Stream (7 cols) */}
        <div className="lg:col-span-7 space-y-2.5">
          <div className="text-xs font-semibold text-[#8CA3A8] flex items-center gap-1.5 pb-1 font-sans">
            <Layers className="w-3.5 h-3.5 text-[#6DBAC6]" />
            <span>Event Sequence (Chronological)</span>
          </div>

          <div className="space-y-2">
            {events.map((evt, idx) => {
              const isSelected = selectedEvent?.id === evt.id;

              return (
                <div key={evt.id} className="relative">
                  {/* Timeline Connecting Line */}
                  {idx < events.length - 1 && (
                    <div className="absolute left-6 top-10 bottom-0 w-0.5 bg-[#124A58] -mb-2 z-0" />
                  )}
                  <div className="relative z-10">
                    <TraceEventRow
                      event={evt}
                      defaultExpanded={false}
                      isSelected={isSelected}
                      onSelectEvent={(e) => setSelectedEvent(e)}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Contextual Event Payload Inspector Panel (5 cols) */}
        <div className="lg:col-span-5">
          <div className="sticky top-20 rounded border border-[#124A58] bg-[#073642] p-4 space-y-3.5 text-xs font-sans">
            <div className="flex items-center justify-between pb-2 border-b border-[#124A58]">
              <span className="font-semibold text-[#E3EEEE] text-xs flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5 text-[#6DBAC6]" />
                <span>Node Payload Inspector</span>
              </span>
              {selectedEvent && <IdBadge id={selectedEvent.id} truncateLength={10} />}
            </div>

            {selectedEvent ? (
              <div className="space-y-3">
                <div className="space-y-1">
                  <div className="text-[11px] text-[#8CA3A8] font-medium">Event Type / Actor</div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[#E3EEEE] text-xs font-medium">{selectedEvent.eventType}</span>
                    <span className="text-[#5F7C82] font-mono">·</span>
                    <span className="text-[#8CA3A8] font-sans text-xs">{selectedEvent.actor}</span>
                  </div>
                </div>

                {selectedEvent.isViolation && (
                  <div className="p-2.5 rounded bg-[#4A2F31] border border-[#5A3A3C] text-[#F0B3AA] text-[11px] leading-relaxed">
                    <div className="font-medium text-[#F0B3AA] flex items-center gap-1 mb-1">
                      <ShieldAlert className="w-3.5 h-3.5" />
                      <span>Security Violation Detected</span>
                    </div>
                    {selectedEvent.details ||
                      'Action breached security policy bounds and triggered critical finding criteria.'}
                  </div>
                )}

                {selectedEvent.isPolicyBlock && (
                  <div className="p-2.5 rounded bg-[#1D3D33] border border-[#285547] text-[#A6D6B7] text-[11px] leading-relaxed">
                    <div className="font-medium text-[#A6D6B7] flex items-center gap-1 mb-1">
                      <ShieldCheck className="w-3.5 h-3.5" />
                      <span>Policy Intervention: Attack Blocked</span>
                    </div>
                    {selectedEvent.details ||
                      'Security guardrail halted execution before external side-effects occurred.'}
                  </div>
                )}

                {selectedEvent.input && (
                  <div className="space-y-1">
                    <div className="text-[11px] text-[#8CA3A8] font-medium">Input Payload:</div>
                    <CodeBlock
                      code={
                        typeof selectedEvent.input === 'string'
                          ? selectedEvent.input
                          : JSON.stringify(selectedEvent.input, null, 2)
                      }
                      language={typeof selectedEvent.input === 'string' ? 'text' : 'json'}
                      showLineNumbers={false}
                      maxHeight="160px"
                    />
                  </div>
                )}

                {selectedEvent.arguments && (
                  <div className="space-y-1">
                    <div className="text-[11px] text-[#8CA3A8] font-medium">Tool Arguments:</div>
                    <CodeBlock
                      code={JSON.stringify(selectedEvent.arguments, null, 2)}
                      language="json"
                      showLineNumbers={false}
                      maxHeight="160px"
                    />
                  </div>
                )}

                {selectedEvent.output && (
                  <div className="space-y-1">
                    <div className="text-[11px] text-[#8CA3A8] font-medium">Output / Return:</div>
                    <CodeBlock
                      code={
                        typeof selectedEvent.output === 'string'
                          ? selectedEvent.output
                          : JSON.stringify(selectedEvent.output, null, 2)
                      }
                      language={typeof selectedEvent.output === 'string' ? 'text' : 'json'}
                      showLineNumbers={false}
                      maxHeight="160px"
                    />
                  </div>
                )}

                <div className="pt-2 border-t border-[#124A58] space-y-1 text-[11px] text-[#8CA3A8]">
                  <div className="flex justify-between">
                    <span className="text-[#8CA3A8]">Timestamp:</span>
                    <span className="font-mono text-[#BCD0D3]">{selectedEvent.timestamp}</span>
                  </div>
                  {selectedEvent.correlationId && (
                    <div className="flex justify-between">
                      <span className="text-[#8CA3A8]">Correlation ID:</span>
                      <span className="font-mono text-[#BCD0D3]">{selectedEvent.correlationId}</span>
                    </div>
                  )}
                  {selectedEvent.relatedFindingId && onJumpToFinding && (
                    <div className="pt-2">
                      <button
                        onClick={() => onJumpToFinding(selectedEvent.relatedFindingId!)}
                        className="w-full py-1.5 bg-[#0E4452] hover:bg-[#2B7F8C] text-[#BFE3E8] hover:text-[#F2FAFA] rounded border border-[#2B7F8C] text-xs font-medium transition-colors"
                      >
                        Inspect Associated Finding ({selectedEvent.relatedFindingId})
                      </button>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="py-12 text-center text-[#8CA3A8] text-xs">
                Select an event node in the timeline to inspect its full payload and recorded decision.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
