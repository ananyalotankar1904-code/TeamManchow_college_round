import React, { useState, useMemo } from 'react';
import { SecurityScan, FilterState, Agent, AttackCategory, SecurityFinding } from '../types';
import { PageHeader } from '../components/layout/PageHeader';
import { ScanResultsTable } from '../components/scans/ScanResultsTable';
import { ScanConfigurationForm } from '../components/scans/ScanConfigurationForm';
import { ScanProgress } from '../components/scans/ScanProgress';
import { FilterBar } from '../components/common/FilterBar';
import { IdBadge } from '../components/common/IdBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import {
  ShieldAlert,
  ShieldCheck,
  HelpCircle,
  Clock,
  Plus,
  ArrowLeft,
  Layers,
} from 'lucide-react';

interface ScanResultsPageProps {
  scans: SecurityScan[];
  findings?: SecurityFinding[];
  activeScanId?: string;
  agents: Agent[];
  onSelectScan: (scanId: string) => void;
  onSelectFinding: (findingId: string) => void;
  onOpenFixLoop?: (findingId: string) => void;
  onStartNewScan: (config: {
    agentId: string;
    categories: AttackCategory[];
    mode: 'fast' | 'comprehensive' | 'adversarial';
  }) => Promise<void>;
}

export const ScanResultsPage: React.FC<ScanResultsPageProps> = ({
  scans,
  findings,
  activeScanId,
  agents,
  onSelectScan,
  onSelectFinding,
  onOpenFixLoop,
  onStartNewScan,
}) => {
  const [showConfigForm, setShowConfigForm] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [activeRunningScan, setActiveRunningScan] = useState<SecurityScan | null>(null);

  // Selected scan or first available
  const currentScan = useMemo(() => {
    if (activeScanId) {
      return scans.find((s) => s.id === activeScanId) || scans[0];
    }
    return scans[0];
  }, [activeScanId, scans]);

  const [filterState, setFilterState] = useState<FilterState>({
    severity: 'all',
    category: 'all',
    outcome: 'all',
    searchQuery: '',
  });

  const scanFindings = useMemo(() => {
    if (!currentScan) return [];
    if (currentScan.findings && currentScan.findings.length > 0) {
      return currentScan.findings;
    }
    if (findings && findings.length > 0) {
      return findings.filter((f) => f.scanId === currentScan.id);
    }
    return [];
  }, [currentScan, findings]);

  const filteredFindings = useMemo(() => {
    return scanFindings.filter((f) => {
      // Severity filter
      if (filterState.severity !== 'all' && f.severity !== filterState.severity) {
        return false;
      }
      // Category filter
      if (filterState.category !== 'all' && f.category !== filterState.category) {
        return false;
      }
      // Outcome filter
      if (filterState.outcome !== 'all' && f.outcome !== filterState.outcome) {
        return false;
      }
      // Search query
      if (filterState.searchQuery.trim() !== '') {
        const q = filterState.searchQuery.toLowerCase();
        const matchTitle = f.title.toLowerCase().includes(q);
        const matchId = f.id.toLowerCase().includes(q);
        const matchAgent = f.agentName.toLowerCase().includes(q);
        const matchTool = (f.affectedTool || '').toLowerCase().includes(q);
        if (!matchTitle && !matchId && !matchAgent && !matchTool) {
          return false;
        }
      }
      return true;
    });
  }, [scanFindings, filterState]);

  const handleStartScan = async (config: {
    agentId: string;
    categories: AttackCategory[];
    mode: 'fast' | 'comprehensive' | 'adversarial';
  }) => {
    setShowConfigForm(false);
    setIsScanning(true);
    const tempScan: SecurityScan = {
      id: `scan_${Date.now().toString(36)}`,
      agentId: config.agentId,
      agentName: agents.find((a) => a.id === config.agentId)?.name || 'Target Agent',
      createdAt: new Date().toISOString(),
      status: 'running',
      mode: config.mode,
      categoriesTested: config.categories,
      totalTests: config.categories.length * 3,
      confirmedFindings: 0,
      blockedAttacks: 0,
      inconclusiveTests: 0,
      findings: [],
    };
    setActiveRunningScan(tempScan);
    await onStartNewScan(config);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title={showConfigForm ? 'Configure Security Scan' : 'Security Scan Results'}
        subtitle={
          showConfigForm
            ? 'Select target AI agent, adversarial attack suites, and evaluation depth profile.'
            : 'Adversarial evaluation results, observed outcomes, and confirmed vulnerability records.'
        }
        actions={
          showConfigForm ? (
            <button
              onClick={() => setShowConfigForm(false)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#002B36] hover:bg-[#0A3F4D] text-[#E3EEEE] rounded border border-[#124A58] text-xs font-medium transition-colors"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Results</span>
            </button>
          ) : (
            <button
              onClick={() => setShowConfigForm(true)}
              className="flex items-center gap-1.5 px-3.5 py-1.5 bg-[#2B7F8C] hover:bg-[#3596A5] text-[#F2FAFA] rounded text-xs font-medium transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Run New Scan</span>
            </button>
          )
        }
      />

      {/* Show active running scan progress if triggered */}
      {isScanning && activeRunningScan && (
        <ScanProgress
          scan={activeRunningScan}
          onComplete={() => {
            setIsScanning(false);
            setActiveRunningScan(null);
          }}
          onCancel={() => {
            setIsScanning(false);
            setActiveRunningScan(null);
          }}
        />
      )}

      {showConfigForm ? (
        <div className="p-5 rounded border border-[#124A58] bg-[#073642] max-w-4xl">
          <ScanConfigurationForm
            agents={agents}
            onStartScan={handleStartScan}
            onCancel={() => setShowConfigForm(false)}
          />
        </div>
      ) : (
        currentScan && (
          <div className="space-y-5">
            {/* Scan Selection Switcher Bar */}
            <div className="flex items-center gap-2 overflow-x-auto pb-1">
              <span className="text-xs font-medium text-[#8CA3A8] shrink-0 pr-1">
                Scan Session:
              </span>
              {scans.map((s) => {
                const isSelected = s.id === currentScan.id;
                return (
                  <button
                    key={s.id}
                    onClick={() => onSelectScan(s.id)}
                    className={`flex items-center gap-2 px-3 py-1.5 rounded border text-xs font-sans whitespace-nowrap transition-colors ${
                      isSelected
                        ? 'bg-[#0E4452] border-[#2B7F8C] text-[#BFE3E8] font-medium'
                        : 'bg-[#002B36] border-[#124A58] text-[#8CA3A8] hover:text-[#E3EEEE] hover:border-[#185B6C]'
                    }`}
                  >
                    <span className="font-mono text-[#BCD0D3]">{s.id.substring(0, 14)}…</span>
                    <span className="text-[#8CA3A8] font-normal">({s.agentName})</span>
                    <StatusBadge status={s.status} size="sm" />
                  </button>
                );
              })}
            </div>

            {/* Scan Metadata & Metrics Banner */}
            <div className="p-4 rounded border border-[#124A58] bg-[#073642] space-y-3">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-[#124A58]">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-[#E3EEEE] text-sm font-sans">{currentScan.agentName}</span>
                    <span className="text-[#5F7C82] font-mono">·</span>
                    <IdBadge id={currentScan.id} prefix="SCAN" />
                    <span className="px-2 py-0.5 rounded bg-[#332E1E] border border-[#4A4228] font-sans text-[10px] text-[#E2C98F] font-medium uppercase">
                      {currentScan.mode} Evaluation
                    </span>
                  </div>
                  <div className="text-[11px] font-sans text-[#8CA3A8] flex items-center gap-2">
                    <Clock className="w-3.5 h-3.5 text-[#5F7C82]" />
                    <span>Executed: <span className="font-mono text-[#BCD0D3]">{currentScan.createdAt.replace('T', ' ').substring(0, 19)} UTC</span></span>
                    {currentScan.durationMs && (
                      <span className="text-[#5F7C82]">({Math.round(currentScan.durationMs / 1000)}s duration)</span>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <StatusBadge status={currentScan.status} />
                </div>
              </div>

              {/* 4 Outcome Metrics */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-xs">
                <div className="p-2.5 rounded bg-[#002B36] border border-[#124A58] flex items-center justify-between">
                  <div className="flex items-center gap-1.5 text-[#8CA3A8] text-[11px]">
                    <Layers className="w-3.5 h-3.5 text-[#6DBAC6]" />
                    <span>Test Cases:</span>
                  </div>
                  <span className="font-mono font-medium text-[#E3EEEE]">{currentScan.totalTests}</span>
                </div>

                <div className="p-2.5 rounded bg-[#002B36] border border-[#124A58] flex items-center justify-between">
                  <div className="flex items-center gap-1.5 text-[#D9776B] text-[11px]">
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>Confirmed Vulns:</span>
                  </div>
                  <span className="font-mono font-medium text-[#E08A7E]">{currentScan.confirmedFindings}</span>
                </div>

                <div className="p-2.5 rounded bg-[#002B36] border border-[#124A58] flex items-center justify-between">
                  <div className="flex items-center gap-1.5 text-[#78B993] text-[11px]">
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Attacks Blocked:</span>
                  </div>
                  <span className="font-mono font-medium text-[#78B993]">{currentScan.blockedAttacks}</span>
                </div>

                <div className="p-2.5 rounded bg-[#002B36] border border-[#124A58] flex items-center justify-between">
                  <div className="flex items-center gap-1.5 text-[#8CA3A8] text-[11px]">
                    <HelpCircle className="w-3.5 h-3.5 text-[#5F7C82]" />
                    <span>Inconclusive:</span>
                  </div>
                  <span className="font-mono font-medium text-[#BCD0D3]">{currentScan.inconclusiveTests}</span>
                </div>
              </div>
            </div>

            {/* Filter Bar */}
            <FilterBar
              filterState={filterState}
              onFilterChange={setFilterState}
              totalCount={scanFindings.length}
              filteredCount={filteredFindings.length}
            />

            {/* Results Table */}
            <ScanResultsTable
              findings={filteredFindings}
              onSelectFinding={onSelectFinding}
              onOpenFixLoop={onOpenFixLoop}
            />
          </div>
        )
      )}
    </div>
  );
};
