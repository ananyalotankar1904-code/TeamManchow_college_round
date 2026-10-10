import React, { useState } from 'react';
import { Agent, AgentFramework } from '../../types';
import { Shield, Plus, Info, Wrench } from 'lucide-react';
import { useToast } from '../common/Toast';

interface AgentSetupFormProps {
  onSubmit: (agentData: Omit<Agent, 'id' | 'createdAt' | 'scansCount' | 'criticalCount'>) => Promise<void>;
  onCancel: () => void;
  isBackendConnected: boolean;
}

export const AgentSetupForm: React.FC<AgentSetupFormProps> = ({
  onSubmit,
  onCancel,
  isBackendConnected,
}) => {
  const { showSuccess, showError } = useToast();
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Form fields
  const [name, setName] = useState('');
  const [identifier, setIdentifier] = useState('');
  const [framework, setFramework] = useState<AgentFramework>('LangGraph');
  const [executionMethod, setExecutionMethod] = useState<'local_adapter' | 'http_endpoint' | 'subagent_runner'>('local_adapter');
  const [baseUrl, setBaseUrl] = useState('http://localhost:8000/agents/');
  const [description, setDescription] = useState('');
  const [environment, setEnvironment] = useState<'local_lab' | 'staging_sandbox' | 'isolated_vm'>('local_lab');

  // Tools & Permissions tags
  const [tools, setTools] = useState<string[]>(['fetch_document', 'execute_query', 'send_notification']);
  const [newTool, setNewTool] = useState('');
  const [permissions, setPermissions] = useState<string[]>(['read:filings', 'query:database']);
  const [newPermission, setNewPermission] = useState('');

  const handleAddTool = () => {
    if (newTool.trim() && !tools.includes(newTool.trim())) {
      setTools([...tools, newTool.trim()]);
      setNewTool('');
    }
  };

  const handleRemoveTool = (toolToRemove: string) => {
    setTools(tools.filter((t) => t !== toolToRemove));
  };

  const handleAddPermission = () => {
    if (newPermission.trim() && !permissions.includes(newPermission.trim())) {
      setPermissions([...permissions, newPermission.trim()]);
      setNewPermission('');
    }
  };

  const handleRemovePermission = (permToRemove: string) => {
    setPermissions(permissions.filter((p) => p !== permToRemove));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      showError('Agent name is required');
      return;
    }
    if (!identifier.trim()) {
      showError('Agent identifier is required');
      return;
    }

    try {
      setIsSubmitting(true);
      await onSubmit({
        name: name.trim(),
        identifier: identifier.trim(),
        framework,
        executionMethod,
        baseUrl: executionMethod === 'http_endpoint' ? baseUrl.trim() : undefined,
        description: description.trim(),
        tools,
        permissions,
        environment,
        status: 'active',
        riskScore: 15,
      });
      showSuccess(`Target Agent "${name}" registered successfully`);
    } catch (err: unknown) {
      showError(err instanceof Error ? err.message : 'Failed to register target agent');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {/* Security & Sandbox Guidance Banner */}
      <div className="p-3.5 rounded border border-[#124A58] bg-[#002B36] text-xs space-y-1.5">
        <div className="flex items-center gap-2 font-sans text-[#E3EEEE] font-medium">
          <Shield className="w-4 h-4 text-[#6DBAC6]" />
          <span>Agent Registration & Sandbox Isolation</span>
        </div>
        <p className="text-[#8CA3A8] leading-relaxed text-[11px]">
          AgentBreak evaluates target agents via local adapters or sandboxed HTTP endpoints.
          Never supply production API keys or raw master credentials in registration forms.
        </p>
        {!isBackendConnected && (
          <div className="flex items-center gap-1.5 text-[#E2C98F] font-sans text-[11px] pt-1">
            <Info className="w-3.5 h-3.5 shrink-0" />
            <span>Note: Backend is currently in Demo Mode. Agent will be registered in local state.</span>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Agent Name */}
        <div className="space-y-1.5">
          <label htmlFor="agent-name" className="block text-xs font-medium text-[#E3EEEE]">
            Agent Display Name <span className="text-[#D9776B]">*</span>
          </label>
          <input
            id="agent-name"
            type="text"
            required
            value={name}
            onChange={(e) => {
              setName(e.target.value);
              if (!identifier) {
                setIdentifier(
                  `agent.${e.target.value.toLowerCase().replace(/[^a-z0-9]+/g, '.')}.v1`
                );
              }
            }}
            placeholder="e.g. Financial Intel Copilot"
            className="w-full bg-[#002B36] border border-[#124A58] rounded px-3 py-2 text-xs text-[#E3EEEE] placeholder-[#5F7C82] focus:outline-none focus:border-[#2B7F8C] font-sans"
          />
        </div>

        {/* Agent Identifier */}
        <div className="space-y-1.5">
          <label htmlFor="agent-identifier" className="block text-xs font-medium text-[#E3EEEE]">
            Agent Identifier (URN) <span className="text-[#D9776B]">*</span>
          </label>
          <input
            id="agent-identifier"
            type="text"
            required
            value={identifier}
            onChange={(e) => setIdentifier(e.target.value)}
            placeholder="e.g. agent.finance.rag.v2.4"
            className="w-full bg-[#002B36] border border-[#124A58] rounded px-3 py-2 text-xs text-[#BCD0D3] placeholder-[#5F7C82] focus:outline-none focus:border-[#2B7F8C] font-mono"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Framework */}
        <div className="space-y-1.5">
          <label htmlFor="agent-framework" className="block text-xs font-medium text-[#E3EEEE]">
            Target Framework
          </label>
          <select
            id="agent-framework"
            value={framework}
            onChange={(e) => setFramework(e.target.value as AgentFramework)}
            className="w-full bg-[#002B36] border border-[#124A58] rounded px-3 py-2 text-xs text-[#E3EEEE] focus:outline-none focus:border-[#2B7F8C] font-sans"
          >
            <option value="LangGraph" className="bg-[#002B36]">LangGraph (StateGraph)</option>
            <option value="LlamaIndex" className="bg-[#002B36]">LlamaIndex (Workflow/Router)</option>
            <option value="CrewAI" className="bg-[#002B36]">CrewAI (Multi-Agent)</option>
            <option value="AutoGen" className="bg-[#002B36]">AutoGen (ConversableAgent)</option>
            <option value="Custom Adapter" className="bg-[#002B36]">Custom Local Adapter</option>
            <option value="Direct API / OpenAI" className="bg-[#002B36]">OpenAI Assistants API</option>
            <option value="Anthropic Tool-Calling" className="bg-[#002B36]">Anthropic Tool Use</option>
          </select>
        </div>

        {/* Execution Method */}
        <div className="space-y-1.5">
          <label htmlFor="agent-exec-method" className="block text-xs font-medium text-[#E3EEEE]">
            Execution Method
          </label>
          <select
            id="agent-exec-method"
            value={executionMethod}
            onChange={(e) =>
              setExecutionMethod(
                e.target.value as 'local_adapter' | 'http_endpoint' | 'subagent_runner'
              )
            }
            className="w-full bg-[#002B36] border border-[#124A58] rounded px-3 py-2 text-xs text-[#E3EEEE] focus:outline-none focus:border-[#2B7F8C] font-sans"
          >
            <option value="local_adapter" className="bg-[#002B36]">Local Python/TS Adapter</option>
            <option value="http_endpoint" className="bg-[#002B36]">HTTP / REST Webhook</option>
            <option value="subagent_runner" className="bg-[#002B36]">Isolated Subagent Runner</option>
          </select>
        </div>

        {/* Environment */}
        <div className="space-y-1.5">
          <label htmlFor="agent-environment" className="block text-xs font-medium text-[#E3EEEE]">
            Test Environment
          </label>
          <select
            id="agent-environment"
            value={environment}
            onChange={(e) =>
              setEnvironment(e.target.value as 'local_lab' | 'staging_sandbox' | 'isolated_vm')
            }
            className="w-full bg-[#002B36] border border-[#124A58] rounded px-3 py-2 text-xs text-[#E3EEEE] focus:outline-none focus:border-[#2B7F8C] font-sans"
          >
            <option value="local_lab" className="bg-[#002B36]">Local Lab (Default)</option>
            <option value="staging_sandbox" className="bg-[#002B36]">Staging Sandbox</option>
            <option value="isolated_vm" className="bg-[#002B36]">Isolated Container VM</option>
          </select>
        </div>
      </div>

      {/* Base URL (if HTTP Endpoint) */}
      {executionMethod === 'http_endpoint' && (
        <div className="space-y-1.5">
          <label htmlFor="agent-endpoint-url" className="block text-xs font-medium text-[#E3EEEE]">
            Agent HTTP Endpoint URL
          </label>
          <input
            id="agent-endpoint-url"
            type="url"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="http://localhost:8000/agents/my-copilot"
            className="w-full bg-[#002B36] border border-[#124A58] rounded px-3 py-2 text-xs text-[#E3EEEE] font-mono focus:outline-none focus:border-[#2B7F8C]"
          />
        </div>
      )}

      {/* Description */}
      <div className="space-y-1.5">
        <label htmlFor="agent-description" className="block text-xs font-medium text-[#E3EEEE]">
          Agent System Role & Mission
        </label>
        <textarea
          id="agent-description"
          rows={2}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Brief description of the agent's intended business logic, user scope, and operational autonomy..."
          className="w-full bg-[#002B36] border border-[#124A58] rounded px-3 py-2 text-xs text-[#E3EEEE] placeholder-[#5F7C82] focus:outline-none focus:border-[#2B7F8C] font-sans"
        />
      </div>

      {/* Tools tags */}
      <div className="space-y-2">
        <label htmlFor="new-tool-input" className="block text-xs font-medium text-[#E3EEEE]">
          Available Tools Exposed to Agent
        </label>
        <div className="flex flex-wrap gap-1.5 mb-2">
          {tools.map((tool) => (
            <span
              key={tool}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[#002B36] border border-[#124A58] font-mono text-xs text-[#6DBAC6]"
            >
              <Wrench className="w-3 h-3 text-[#5F7C82]" />
              <span>{tool}</span>
              <button
                type="button"
                onClick={() => handleRemoveTool(tool)}
                className="text-[#5F7C82] hover:text-[#D9776B] ml-1"
                aria-label={`Remove tool ${tool}`}
              >
                ×
              </button>
            </span>
          ))}
        </div>
        <div className="flex gap-2">
          <input
            id="new-tool-input"
            type="text"
            value={newTool}
            onChange={(e) => setNewTool(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                handleAddTool();
              }
            }}
            placeholder="Add tool name (e.g. execute_sql, http_request)..."
            className="flex-1 bg-[#002B36] border border-[#124A58] rounded px-3 py-1.5 text-xs text-[#E3EEEE] font-mono focus:outline-none focus:border-[#2B7F8C]"
          />
          <button
            type="button"
            onClick={handleAddTool}
            className="px-3 py-1.5 bg-[#002B36] hover:bg-[#0A3F4D] border border-[#124A58] text-[#E3EEEE] rounded text-xs font-medium transition-colors"
          >
            Add Tool
          </button>
        </div>
      </div>

      {/* Permissions tags */}
      <div className="space-y-2">
        <label htmlFor="new-permission-input" className="block text-xs font-medium text-[#E3EEEE]">
          Agent Permission Scopes
        </label>
        <div className="flex flex-wrap gap-1.5 mb-2">
          {permissions.map((perm) => (
            <span
              key={perm}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[#1D3D33] border border-[#285547] font-mono text-xs text-[#A6D6B7]"
            >
              <span>{perm}</span>
              <button
                type="button"
                onClick={() => handleRemovePermission(perm)}
                className="text-[#5F7C82] hover:text-[#D9776B] ml-1"
                aria-label={`Remove permission ${perm}`}
              >
                ×
              </button>
            </span>
          ))}
        </div>
        <div className="flex gap-2">
          <input
            id="new-permission-input"
            type="text"
            value={newPermission}
            onChange={(e) => setNewPermission(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                handleAddPermission();
              }
            }}
            placeholder="Add permission scope (e.g. read:db, write:refunds)..."
            className="flex-1 bg-[#002B36] border border-[#124A58] rounded px-3 py-1.5 text-xs text-[#E3EEEE] font-mono focus:outline-none focus:border-[#2B7F8C]"
          />
          <button
            type="button"
            onClick={handleAddPermission}
            className="px-3 py-1.5 bg-[#002B36] hover:bg-[#0A3F4D] border border-[#124A58] text-[#E3EEEE] rounded text-xs font-medium transition-colors"
          >
            Add Scope
          </button>
        </div>
      </div>

      {/* Submit Buttons */}
      <div className="flex items-center justify-end gap-3 pt-3 border-t border-[#124A58]">
        <button
          type="button"
          onClick={onCancel}
          className="px-4 py-2 bg-[#002B36] hover:bg-[#0A3F4D] border border-[#124A58] text-[#E3EEEE] rounded text-xs font-medium transition-colors"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={isSubmitting}
          className="px-5 py-2 bg-[#2B7F8C] hover:bg-[#3596A5] text-[#F2FAFA] rounded text-xs font-medium flex items-center gap-1.5 transition-colors"
        >
          {isSubmitting ? (
            <span>Registering...</span>
          ) : (
            <>
              <Plus className="w-3.5 h-3.5" />
              <span>Register Target Agent</span>
            </>
          )}
        </button>
      </div>
    </form>
  );
};
