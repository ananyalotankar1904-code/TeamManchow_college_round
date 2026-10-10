import React, { useState } from 'react';
import { Agent } from '../types';
import { PageHeader } from '../components/layout/PageHeader';
import { AgentSetupForm } from '../components/agents/AgentSetupForm';
import { AgentConfigurationSummary } from '../components/agents/AgentConfigurationSummary';
import { Plus, ArrowLeft } from 'lucide-react';

interface AgentSetupPageProps {
  agents: Agent[];
  onRegisterAgent: (agentData: Omit<Agent, 'id' | 'createdAt' | 'scansCount' | 'criticalCount'>) => Promise<void>;
  onSelectAgentForScan: (agent: Agent) => void;
  isBackendConnected: boolean;
}

export const AgentSetupPage: React.FC<AgentSetupPageProps> = ({
  agents,
  onRegisterAgent,
  onSelectAgentForScan,
  isBackendConnected,
}) => {
  const [showAddForm, setShowAddForm] = useState(false);

  return (
    <div className="space-y-6">
      <PageHeader
        title={showAddForm ? 'Register Target AI Agent' : 'Target AI Agents'}
        subtitle={
          showAddForm
            ? 'Configure agent adapter, execution endpoint, and tool permissions for security evaluation.'
            : 'Inventory of target AI agents, framework architectures, bound tools, and risk scores.'
        }
        actions={
          showAddForm ? (
            <button
              onClick={() => setShowAddForm(false)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#002B36] hover:bg-[#0A3F4D] text-[#E3EEEE] rounded border border-[#124A58] text-xs font-medium transition-colors"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Agent Inventory</span>
            </button>
          ) : (
            <button
              onClick={() => setShowAddForm(true)}
              className="flex items-center gap-1.5 px-3.5 py-1.5 bg-[#2B7F8C] hover:bg-[#3596A5] text-[#F2FAFA] rounded text-xs font-medium shadow-subtle transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Register New Agent</span>
            </button>
          )
        }
      />

      {showAddForm ? (
        <div className="p-5 rounded border border-[#124A58] bg-[#073642] max-w-4xl">
          <AgentSetupForm
            onSubmit={async (data) => {
              await onRegisterAgent(data);
              setShowAddForm(false);
            }}
            onCancel={() => setShowAddForm(false)}
            isBackendConnected={isBackendConnected}
          />
        </div>
      ) : (
        <AgentConfigurationSummary
          agents={agents}
          onSelectAgentForScan={onSelectAgentForScan}
          onAddNewAgent={() => setShowAddForm(true)}
        />
      )}
    </div>
  );
};
