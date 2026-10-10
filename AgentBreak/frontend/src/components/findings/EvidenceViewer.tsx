import React, { useState } from 'react';
import { EvidenceData } from '../../types';
import { CodeBlock } from '../common/CodeBlock';
import { TraceEventRow } from '../traces/TraceEventRow';
import { Activity, ShieldCheck, Wrench, FileCode } from 'lucide-react';

interface EvidenceViewerProps {
  evidence: EvidenceData;
  onSelectEvent?: (eventId: string) => void;
}

export const EvidenceViewer: React.FC<EvidenceViewerProps> = ({ evidence }) => {
  const [activeTab, setActiveTab] = useState<'events' | 'payload' | 'toolCalls' | 'policies'>('events');

  return (
    <div className="rounded border border-[#124A58] bg-[#073642] overflow-hidden">
      {/* Evidence Sub-Tabs */}
      <div className="flex items-center justify-between px-3 py-2 bg-[#01212A] border-b border-[#124A58] text-xs font-sans select-none">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('events')}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded transition-colors font-medium ${
              activeTab === 'events'
                ? 'bg-[#0E4452] text-[#E3EEEE] border border-[#2B7F8C]'
                : 'text-[#8CA3A8] hover:text-[#E3EEEE]'
            }`}
          >
            <Activity className="w-3.5 h-3.5 text-[#6DBAC6]" />
            <span>Trace Events ({evidence.traceEvents ? evidence.traceEvents.length : 0})</span>
          </button>

          <button
            onClick={() => setActiveTab('toolCalls')}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded transition-colors font-medium ${
              activeTab === 'toolCalls'
                ? 'bg-[#0E4452] text-[#E3EEEE] border border-[#2B7F8C]'
                : 'text-[#8CA3A8] hover:text-[#E3EEEE]'
            }`}
          >
            <Wrench className="w-3.5 h-3.5 text-[#6DBAC6]" />
            <span>Tool Invocations ({evidence.toolCalls ? evidence.toolCalls.length : 0})</span>
          </button>

          <button
            onClick={() => setActiveTab('policies')}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded transition-colors font-medium ${
              activeTab === 'policies'
                ? 'bg-[#0E4452] text-[#E3EEEE] border border-[#2B7F8C]'
                : 'text-[#8CA3A8] hover:text-[#E3EEEE]'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5 text-[#78B993]" />
            <span>Policy Interventions ({evidence.policyDecisions ? evidence.policyDecisions.length : 0})</span>
          </button>

          <button
            onClick={() => setActiveTab('payload')}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded transition-colors font-medium ${
              activeTab === 'payload'
                ? 'bg-[#0E4452] text-[#E3EEEE] border border-[#2B7F8C]'
                : 'text-[#8CA3A8] hover:text-[#E3EEEE]'
            }`}
          >
            <FileCode className="w-3.5 h-3.5 text-[#D9A468]" />
            <span>Raw Captured Payload</span>
          </button>
        </div>
      </div>

      {/* Tab Content */}
      <div className="p-4">
        {activeTab === 'events' && (
          <div className="space-y-3">
            {evidence.traceEvents && evidence.traceEvents.length > 0 ? (
              <div className="space-y-2">
                {evidence.traceEvents.map((evt) => (
                  <TraceEventRow key={evt.id} event={evt} defaultExpanded={evt.isViolation || evt.isPolicyBlock} />
                ))}
              </div>
            ) : (
              <div className="py-6 text-center text-[#5F7C82] font-sans text-xs">
                No discrete trace events recorded for this vector execution.
              </div>
            )}
          </div>
        )}

        {activeTab === 'toolCalls' && (
          <div className="space-y-3">
            {evidence.toolCalls && evidence.toolCalls.length > 0 ? (
              evidence.toolCalls.map((tc, idx) => (
                <div key={idx} className="p-3 rounded bg-[#002B36] border border-[#124A58] space-y-2">
                  <div className="flex items-center justify-between font-sans text-xs">
                    <span className="text-[#6DBAC6] font-mono font-medium">Tool: {tc.name}</span>
                    <span className="text-[#5F7C82] text-[11px] font-mono">{tc.timestamp}</span>
                  </div>
                  <div className="text-xs text-[#8CA3A8] font-sans font-medium">Arguments:</div>
                  <CodeBlock
                    code={JSON.stringify(tc.arguments, null, 2)}
                    language="json"
                    showLineNumbers={false}
                    maxHeight="200px"
                  />
                  {tc.response !== undefined && (
                    <>
                      <div className="text-xs text-[#8CA3A8] font-sans font-medium pt-1">Return Output:</div>
                      <CodeBlock
                        code={typeof tc.response === 'string' ? tc.response : JSON.stringify(tc.response, null, 2)}
                        language="json"
                        showLineNumbers={false}
                        maxHeight="200px"
                      />
                    </>
                  )}
                </div>
              ))
            ) : (
              <div className="py-6 text-center text-[#5F7C82] font-sans text-xs">
                No tool calls were invoked during this test sequence.
              </div>
            )}
          </div>
        )}

        {activeTab === 'policies' && (
          <div className="space-y-2">
            {evidence.policyDecisions && evidence.policyDecisions.length > 0 ? (
              evidence.policyDecisions.map((pol, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded bg-[#002B36] border border-[#124A58] text-xs text-[#E3EEEE] flex items-start gap-2.5 font-sans"
                >
                  <ShieldCheck className="w-4 h-4 text-[#78B993] mt-0.5 shrink-0" />
                  <div className="leading-relaxed">{pol}</div>
                </div>
              ))
            ) : (
              <div className="py-6 text-center text-[#5F7C82] font-sans text-xs">
                No policy rules triggered during evaluation.
              </div>
            )}
          </div>
        )}

        {activeTab === 'payload' && (
          <div className="space-y-2 font-sans">
            <div className="text-xs text-[#8CA3A8] font-medium">
              Raw network transcript / captured input-output stream:
            </div>
            <CodeBlock
              code={evidence.rawPayload || '// No raw payload captured'}
              language="http"
              showLineNumbers={true}
              maxHeight="300px"
            />
          </div>
        )}
      </div>
    </div>
  );
};

