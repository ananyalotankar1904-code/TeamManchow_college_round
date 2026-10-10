import React from 'react';
import { Agent } from '../../types';
import { IdBadge } from '../common/IdBadge';
import { Bot, Wrench, Shield, Flame } from 'lucide-react';

interface AgentConfigurationSummaryProps {
  agents: Agent[];
  onSelectAgentForScan: (agent: Agent) => void;
  onAddNewAgent: () => void;
}

export const AgentConfigurationSummary: React.FC<AgentConfigurationSummaryProps> = ({
  agents,
  onSelectAgentForScan,
  onAddNewAgent,
}) => {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-[#E3EEEE] font-sans">
            Registered Target Agents
          </span>
          <span className="text-[11px] font-sans text-[#8CA3A8]">({agents.length} Active Targets)</span>
        </div>
        <button
          onClick={onAddNewAgent}
          className="px-3 py-1.5 bg-[#2B7F8C] hover:bg-[#3596A5] text-[#F2FAFA] rounded text-xs font-medium flex items-center gap-1.5 transition-colors shadow-subtle"
        >
          <span>Register New Agent</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {agents.map((agent) => {
          return (
            <div
              key={agent.id}
              className="p-4 rounded border border-[#124A58] bg-[#073642] space-y-3.5 hover:border-[#185B6C] transition-colors shadow-subtle flex flex-col justify-between"
            >
              {/* Header */}
              <div className="flex items-start justify-between gap-2">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <div className="p-1.5 rounded bg-[#002B36] border border-[#124A58] text-[#6DBAC6]">
                      <Bot className="w-4 h-4" />
                    </div>
                    <span className="font-semibold text-sm text-[#E3EEEE] font-sans">{agent.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <IdBadge id={agent.identifier} prefix="URN" truncateLength={22} />
                    <span className="px-1.5 py-0.5 rounded border border-[#124A58] bg-[#002B36] text-[10px] font-sans text-[#8CA3A8] font-medium">
                      {agent.framework}
                    </span>
                  </div>
                </div>

                <div className="flex flex-col items-end gap-1">
                  <span className="px-2 py-0.5 rounded border border-[#285547] bg-[#1D3D33] text-[#A6D6B7] font-sans text-[10px] font-medium uppercase">
                    {agent.environment.replace('_', ' ')}
                  </span>
                  {agent.criticalCount > 0 ? (
                    <span className="text-[11px] font-sans text-[#D9776B] font-medium">
                      <span className="font-mono text-[#E08A7E]">{agent.criticalCount}</span> Critical Vuln
                    </span>
                  ) : (
                    <span className="text-[11px] font-sans text-[#78B993] font-medium">
                      0 Active Critical
                    </span>
                  )}
                </div>
              </div>

              {/* Description */}
              <p className="text-xs text-[#8CA3A8] leading-relaxed font-sans">{agent.description}</p>

              {/* Tools Matrix */}
              <div className="space-y-1.5 pt-1 border-t border-[#124A58]">
                <div className="text-[11px] font-sans text-[#8CA3A8] font-medium flex items-center gap-1">
                  <Wrench className="w-3 h-3 text-[#5F7C82]" />
                  <span>Bound Tools ({agent.tools.length}):</span>
                </div>
                <div className="flex flex-wrap gap-1">
                  {agent.tools.map((tool) => (
                    <span
                      key={tool}
                      className="px-1.5 py-0.5 rounded bg-[#002B36] border border-[#124A58] font-mono text-[11px] text-[#6DBAC6]"
                    >
                      {tool}
                    </span>
                  ))}
                </div>
              </div>

              {/* Permissions Matrix */}
              <div className="space-y-1.5">
                <div className="text-[11px] font-sans text-[#8CA3A8] font-medium flex items-center gap-1">
                  <Shield className="w-3 h-3 text-[#5F7C82]" />
                  <span>Permissions ({agent.permissions.length}):</span>
                </div>
                <div className="flex flex-wrap gap-1">
                  {agent.permissions.map((perm) => (
                    <span
                      key={perm}
                      className="px-1.5 py-0.5 rounded bg-[#002B36] border border-[#124A58] font-mono text-[11px] text-[#78B993]"
                    >
                      {perm}
                    </span>
                  ))}
                </div>
              </div>

              {/* Card Footer Actions */}
              <div className="pt-3 border-t border-[#124A58] flex items-center justify-between">
                <div className="text-[11px] font-sans text-[#8CA3A8]">
                  Scans Run: <span className="text-[#BCD0D3] font-mono font-medium">{agent.scansCount}</span>
                </div>
                <button
                  onClick={() => onSelectAgentForScan(agent)}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-[#0E4452] hover:bg-[#2B7F8C] text-[#BFE3E8] hover:text-[#F2FAFA] rounded border border-[#2B7F8C] text-xs font-medium transition-all"
                >
                  <Flame className="w-3.5 h-3.5 text-[#D9A468]" />
                  <span>Launch Red-Team Scan</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
