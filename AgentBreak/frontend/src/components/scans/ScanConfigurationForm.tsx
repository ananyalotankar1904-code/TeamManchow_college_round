import React, { useState } from 'react';
import { Agent, AttackCategory } from '../../types';
import { Flame, ShieldCheck, Cpu, Lock, FileText, AlertCircle, Shield, CheckSquare, Square } from 'lucide-react';

interface ScanConfigurationFormProps {
  agents: Agent[];
  selectedAgentId?: string;
  onStartScan: (config: {
    agentId: string;
    categories: AttackCategory[];
    mode: 'fast' | 'comprehensive' | 'adversarial';
  }) => void;
  onCancel?: () => void;
}

export const ScanConfigurationForm: React.FC<ScanConfigurationFormProps> = ({
  agents,
  selectedAgentId,
  onStartScan,
  onCancel,
}) => {
  const [agentId, setAgentId] = useState<string>(
    selectedAgentId || (agents.length > 0 ? agents[0].id : '')
  );
  const [mode, setMode] = useState<'fast' | 'comprehensive' | 'adversarial'>('adversarial');

  const attackCategories: Array<{
    id: AttackCategory;
    title: string;
    description: string;
    icon: React.ElementType;
    supported: boolean;
  }> = [
    {
      id: 'indirect_rag_injection',
      title: 'Indirect RAG Document Injection',
      description: 'Inject adversarial override instructions via retrieved PDFs, web snippets, and vector context chunks.',
      icon: FileText,
      supported: true,
    },
    {
      id: 'direct_prompt_injection',
      title: 'Direct Jailbreak & Delimiter Injection',
      description: 'Evaluate refusal boundaries, role-play escape payloads, and system prompt delimiter manipulations.',
      icon: Shield,
      supported: true,
    },
    {
      id: 'unauthorized_tool_execution',
      title: 'Unauthorized Tool & Parameter Misuse',
      description: 'Audit SQL injection in tool arguments, unsanitized bash commands, and unauthorized API dispatches.',
      icon: Cpu,
      supported: true,
    },
    {
      id: 'sensitive_data_leakage',
      title: 'Sensitive Data & Credential Exfiltration',
      description: 'Test whether model will dump system instructions, hardcoded API secrets, or sandbox environment keys.',
      icon: Lock,
      supported: true,
    },
    {
      id: 'permission_policy_violation',
      title: 'Permission Boundary & Traversal Violations',
      description: 'Verify strict directory boundaries, path normalization, and role escalation barriers.',
      icon: ShieldCheck,
      supported: true,
    },
    {
      id: 'unsafe_action_execution',
      title: 'Excessive Agency & Unsafe Side-effects',
      description: 'Verify that destructive operations require secondary human-in-the-loop confirmation before firing.',
      icon: AlertCircle,
      supported: true,
    },
  ];

  const [selectedCategories, setSelectedCategories] = useState<AttackCategory[]>([
    'indirect_rag_injection',
    'direct_prompt_injection',
    'unauthorized_tool_execution',
    'sensitive_data_leakage',
    'permission_policy_violation',
    'unsafe_action_execution',
  ]);

  const toggleCategory = (catId: AttackCategory) => {
    if (selectedCategories.includes(catId)) {
      if (selectedCategories.length > 1) {
        setSelectedCategories(selectedCategories.filter((c) => c !== catId));
      }
    } else {
      setSelectedCategories([...selectedCategories, catId]);
    }
  };

  const selectAllCategories = () => {
    setSelectedCategories(attackCategories.filter((c) => c.supported).map((c) => c.id));
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!agentId) return;
    onStartScan({
      agentId,
      categories: selectedCategories,
      mode,
    });
  };

  const selectedAgent = agents.find((a) => a.id === agentId);

  return (
    <form onSubmit={handleSubmit} className="space-y-5 font-sans">
      {/* Target Agent Selection */}
      <div className="space-y-1.5">
        <label htmlFor="target-agent-select" className="block text-xs font-medium text-[#E3EEEE]">
          Select Target AI Agent <span className="text-[#D9776B]">*</span>
        </label>
        <select
          id="target-agent-select"
          value={agentId}
          onChange={(e) => setAgentId(e.target.value)}
          className="w-full bg-[#002B36] border border-[#124A58] text-[#E3EEEE] rounded px-3 py-2 text-xs focus:outline-none focus:border-[#2B7F8C] font-sans"
        >
          {agents.map((agent) => (
            <option key={agent.id} value={agent.id} className="bg-[#002B36] text-[#E3EEEE]">
              {agent.name} ({agent.identifier}) — {agent.framework} [{agent.environment}]
            </option>
          ))}
        </select>

        {selectedAgent && (
          <div className="p-2.5 rounded bg-[#002B36] border border-[#124A58] text-xs text-[#8CA3A8] flex flex-wrap items-center justify-between gap-2">
            <div>
              <span className="text-[#5F7C82]">Bound Tools:</span>{' '}
              <span className="font-mono text-[#BCD0D3]">{selectedAgent.tools.join(', ')}</span>
            </div>
            <div>
              <span className="text-[#5F7C82]">Framework:</span>{' '}
              <span className="text-[#6DBAC6] font-medium">{selectedAgent.framework}</span>
            </div>
          </div>
        )}
      </div>

      {/* Evaluation Depth & Mode */}
      <div className="space-y-2">
        <label className="block text-xs font-medium text-[#E3EEEE]">
          Evaluation Scope & Adversarial Depth
        </label>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
          <div
            onClick={() => setMode('fast')}
            className={`p-3 rounded border cursor-pointer transition-all ${
              mode === 'fast'
                ? 'bg-[#0E4452] border-[#2B7F8C] text-[#E3EEEE]'
                : 'bg-[#002B36] border-[#124A58] text-[#8CA3A8] hover:border-[#185B6C]'
            }`}
          >
            <div className="font-semibold text-xs text-[#6DBAC6]">Fast Baseline</div>
            <div className="text-[11px] text-[#8CA3A8] mt-1 leading-relaxed">
              10 targeted probes · Delimiter escapes & known baseline signatures (~30s).
            </div>
          </div>

          <div
            onClick={() => setMode('comprehensive')}
            className={`p-3 rounded border cursor-pointer transition-all ${
              mode === 'comprehensive'
                ? 'bg-[#0E4452] border-[#2B7F8C] text-[#E3EEEE]'
                : 'bg-[#002B36] border-[#124A58] text-[#8CA3A8] hover:border-[#185B6C]'
            }`}
          >
            <div className="font-semibold text-xs text-[#6DBAC6]">Comprehensive</div>
            <div className="text-[11px] text-[#8CA3A8] mt-1 leading-relaxed">
              20 multi-turn test vectors · Full tool parameter mutation suite (~1m).
            </div>
          </div>

          <div
            onClick={() => setMode('adversarial')}
            className={`p-3 rounded border cursor-pointer transition-all ${
              mode === 'adversarial'
                ? 'bg-[#4A3A25] border-[#D39A5B] text-[#E3EEEE]'
                : 'bg-[#002B36] border-[#124A58] text-[#8CA3A8] hover:border-[#185B6C]'
            }`}
          >
            <div className="font-semibold text-xs text-[#D9A468]">Adversarial Red-Team</div>
            <div className="text-[11px] text-[#8CA3A8] mt-1 leading-relaxed">
              35 adversarial attack chains · Indirect RAG poisoning + DDL tool execution (~2m).
            </div>
          </div>
        </div>
      </div>

      {/* Attack Category Checkboxes */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <label className="block text-xs font-medium text-[#E3EEEE]">
            Select Attack Vector Suites
          </label>
          <button
            type="button"
            onClick={selectAllCategories}
            className="text-xs text-[#6DBAC6] hover:text-[#BFE3E8] font-medium"
          >
            Select All Supported
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {attackCategories.map((cat) => {
            const isSelected = selectedCategories.includes(cat.id);
            const Icon = cat.icon;

            return (
              <div
                key={cat.id}
                onClick={() => cat.supported && toggleCategory(cat.id)}
                className={`p-3 rounded border cursor-pointer transition-all flex items-start gap-3 ${
                  isSelected
                    ? 'bg-[#0E4452] border-[#2B7F8C] text-[#E3EEEE]'
                    : 'bg-[#002B36] border-[#124A58] text-[#8CA3A8] hover:border-[#185B6C]'
                } ${!cat.supported ? 'opacity-40 cursor-not-allowed' : ''}`}
              >
                <div className="mt-0.5 shrink-0">
                  {isSelected ? (
                    <CheckSquare className="w-4 h-4 text-[#6DBAC6]" />
                  ) : (
                    <Square className="w-4 h-4 text-[#5F7C82]" />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5">
                    <Icon className="w-3.5 h-3.5 text-[#8CA3A8]" />
                    <span className="font-semibold text-xs font-sans text-[#E3EEEE]">{cat.title}</span>
                  </div>
                  <p className="text-[11px] text-[#8CA3A8] mt-0.5 leading-relaxed">{cat.description}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Actions */}
      <div className="flex items-center justify-end gap-3 pt-3 border-t border-[#124A58]">
        {onCancel && (
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 bg-[#002B36] hover:bg-[#0A3F4D] border border-[#124A58] text-[#E3EEEE] rounded text-xs font-medium transition-colors"
          >
            Cancel
          </button>
        )}
        <button
          type="submit"
          disabled={!agentId || selectedCategories.length === 0}
          className="px-4 py-2 bg-[#2B7F8C] hover:bg-[#3596A5] disabled:opacity-50 text-[#F2FAFA] rounded text-xs font-medium flex items-center gap-2 transition-colors"
        >
          <Flame className="w-3.5 h-3.5 text-[#F2FAFA]" />
          <span>Run Security Scan</span>
        </button>
      </div>
    </form>
  );
};

