import React, { useState, useEffect, useCallback } from 'react';
import {
  Agent,
  SecurityScan,
  SecurityFinding,
  FixLoopSession,
  AssessmentReport,
  ApiConnectionStatus,
  AttackCategory,
} from './types';
import { api } from './services/api';
import { ToastProvider, useToast } from './components/common/Toast';
import { AppShell } from './components/layout/AppShell';
import { NavTab } from './components/layout/Sidebar';
import { DashboardPage } from './pages/DashboardPage';
import { AgentSetupPage } from './pages/AgentSetupPage';
import { ScanResultsPage } from './pages/ScanResultsPage';
import { FindingDetailPage } from './pages/FindingDetailPage';
import { TracesPage } from './pages/TracesPage';
import { FixLoopPage } from './pages/FixLoopPage';
import { ReportPage } from './pages/ReportPage';
import { SettingsPage } from './pages/SettingsPage';
import { Loader2 } from 'lucide-react';

const AgentBreakApp: React.FC = () => {
  const { showError, showSuccess, showInfo } = useToast();

  const [activeTab, setActiveTab] = useState<NavTab>('dashboard');
  const [agents, setAgents] = useState<Agent[]>([]);
  const [scans, setScans] = useState<SecurityScan[]>([]);
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [fixLoopSession, setFixLoopSession] = useState<FixLoopSession | null>(null);
  const [report, setReport] = useState<AssessmentReport | null>(null);
  const [apiStatus, setApiStatus] = useState<ApiConnectionStatus>(api.getStatus());

  const [selectedScanId, setSelectedScanId] = useState<string>('scan_94f81a7b');
  const [selectedFindingId, setSelectedFindingId] = useState<string>('FND-2026-0891');
  const [selectedTraceId, setSelectedTraceId] = useState<string>('tr_rag_exfil_01');
  const [isLoading, setIsLoading] = useState(true);

  // Load initial dataset

  const loadData = useCallback(async () => {
    try {
      setIsLoading(true);
      const [fetchedAgents, fetchedScans, fetchedFindings] = await Promise.all([
        api.getAgents(),
        api.getScans(),
        api.getFindings(),
      ]);

      const scansWithFindings = fetchedScans.map((s) => ({
        ...s,
        findings: s.findings && s.findings.length > 0 ? s.findings : fetchedFindings.filter((f) => f.scanId === s.id),
      }));

      setAgents(fetchedAgents);
      setScans(scansWithFindings);
      setFindings(fetchedFindings);

      if (fetchedFindings.length > 0) {
        setSelectedFindingId((prev) => (prev === 'FND-2026-0891' && !api.getStatus().isDemoMode ? fetchedFindings[0].id : prev));
        const session = await api.getFixLoopSession(fetchedFindings[0].id);
        setFixLoopSession(session);
      }

      if (fetchedScans.length > 0) {
        setSelectedScanId((prev) => (prev === 'scan_94f81a7b' && !api.getStatus().isDemoMode ? fetchedScans[0].id : prev));
        const rep = await api.getReport(fetchedScans[0].id);
        setReport(rep);
      }

      const status = await api.checkHealth();
      setApiStatus(status);
    } catch (err) {
      console.error('Initial data load error:', err);
      const status = api.getStatus();
      setApiStatus(status);
      if (!status.isDemoMode && status.connected) {
        showError(err instanceof Error ? err.message : 'Failed to load backend security data');
      }
    } finally {
      setIsLoading(false);
    }
  }, [showError]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Handlers
  const handleSelectScan = (scanId: string) => {
    setSelectedScanId(scanId);
    setActiveTab('scans');
  };

  const handleSelectFinding = (findingId: string) => {
    setSelectedFindingId(findingId);
    setActiveTab('findings');
  };

  const handleJumpToTrace = (traceId: string) => {
    setSelectedTraceId(traceId);
    setActiveTab('traces');
  };

  const handleOpenFixLoop = async (findingId: string) => {
    setSelectedFindingId(findingId);
    try {
      const session = await api.getFixLoopSession(findingId);
      setFixLoopSession(session);
      setActiveTab('fixloop');
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Failed to open FixLoop session');
    }
  };

  const handleViewReport = async (scanId: string) => {
    setSelectedScanId(scanId);
    try {
      const rep = await api.getReport(scanId);
      setReport(rep);
      setActiveTab('reports');
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Failed to load scan report');
    }
  };

  const handleRegisterAgent = async (
    agentData: Omit<Agent, 'id' | 'createdAt' | 'scansCount' | 'criticalCount'>
  ) => {
    try {
      const newAgent = await api.registerAgent(agentData);
      setAgents((prev) => [newAgent, ...prev]);
      showSuccess(`Registered target agent "${newAgent.name}"`);
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Failed to register agent on backend');
      throw err;
    }
  };

  const handleStartNewScan = async (config: {
    agentId: string;
    categories: AttackCategory[];
    mode: 'fast' | 'comprehensive' | 'adversarial';
  }) => {
    try {
      const newScan = await api.startScan(config);
      setScans((prev) => [newScan, ...prev.filter((s) => s.id !== newScan.id)]);
      setSelectedScanId(newScan.id);
      showInfo(`Initiated ${config.mode} security assessment against agent`);

      // If connected in live mode, poll scan until completion
      if (!apiStatus.isDemoMode && apiStatus.connected) {
        api.pollScanUntilDone(newScan.id, (updatedScan) => {
          setScans((prev) => [updatedScan, ...prev.filter((s) => s.id !== updatedScan.id)]);
        })
          .then(async (completedScan) => {
            const freshFindings = await api.getFindings(completedScan.id);
            setFindings((prev) => [...freshFindings, ...prev.filter((f) => f.scanId !== completedScan.id)]);
            setScans((prev) =>
              prev.map((s) => (s.id === completedScan.id ? { ...s, findings: freshFindings } : s))
            );
            if (freshFindings.length > 0) {
              setSelectedFindingId(freshFindings[0].id);
            }
            showSuccess(`Security scan ${completedScan.id.substring(0, 10)} finished (${freshFindings.length} findings)`);
          })
          .catch((pollErr) => {
            showError(pollErr instanceof Error ? pollErr.message : 'Scan execution monitoring failed');
          });
      }
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Failed to initiate security scan');
    }
  };

  const handleApplyMitigation = async (findingId: string, customPatch?: string) => {
    try {
      const updated = await api.applyMitigation(findingId, customPatch);
      setFixLoopSession(updated);
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Failed to apply mitigation');
    }
  };

  const handleRunRetest = async (findingId: string) => {
    try {
      const updated = await api.runFixLoopRetest(findingId);
      setFixLoopSession(updated);
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Adversarial retest failed');
    }
  };

  const handleRunRegressionSuite = async (findingId: string) => {
    try {
      const updated = await api.runRegressionSuite(findingId);
      setFixLoopSession(updated);
      const freshFindings = await api.getFindings();
      setFindings(freshFindings);
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Regression test suite failed');
    }
  };

  const handleUpdateBaseUrl = async (url: string) => {
    const res = await api.setBaseUrl(url);
    setApiStatus(res);
    return res;
  };

  const handleToggleDemoMode = () => {
    const nextMode = !apiStatus.isDemoMode;
    api.setDemoMode(nextMode);
    setApiStatus(api.getStatus());
    if (nextMode) {
      showInfo('Demo data mode active');
    } else {
      showInfo('Checking live API backend...');
    }
  };

  const handleRefreshHealth = async () => {
    const res = await api.checkHealth();
    setApiStatus(res);
    if (res.connected) {
      showSuccess(`Backend connected (${res.latencyMs}ms)`);
    } else {
      showInfo('Backend offline · Demo mode active');
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#002B36] flex items-center justify-center font-sans text-xs text-[#8CA3A8] gap-2">
        <Loader2 className="w-5 h-5 text-[#6DBAC6] animate-spin" />
        <span>Initializing AgentBreak Security System...</span>
      </div>
    );
  }

  const criticalFindingsCount = findings.filter((f) => f.severity === 'critical').length;

  return (
    <AppShell
      activeTab={activeTab}
      onTabChange={setActiveTab}
      status={apiStatus}
      onRefreshHealth={handleRefreshHealth}
      onToggleDemoMode={handleToggleDemoMode}
      agents={agents}
      onStartNewScan={handleStartNewScan}
      criticalFindingsCount={criticalFindingsCount}
    >
      {activeTab === 'dashboard' && (
        <DashboardPage
          agents={agents}
          scans={scans}
          findings={findings}
          fixLoopSession={fixLoopSession || undefined}
          onNavigateTab={setActiveTab}
          onSelectScan={handleSelectScan}
          onSelectFinding={handleSelectFinding}
          onNewScan={() => setActiveTab('scans')}
        />
      )}

      {activeTab === 'agents' && (
        <AgentSetupPage
          agents={agents}
          onRegisterAgent={handleRegisterAgent}
          onSelectAgentForScan={(ag) => {
            setSelectedScanId(ag.id);
            setActiveTab('scans');
          }}
          isBackendConnected={apiStatus.connected}
        />
      )}

      {activeTab === 'scans' && (
        <ScanResultsPage
          scans={scans}
          findings={findings}
          activeScanId={selectedScanId}
          agents={agents}
          onSelectScan={handleSelectScan}
          onSelectFinding={handleSelectFinding}
          onOpenFixLoop={handleOpenFixLoop}
          onStartNewScan={handleStartNewScan}
        />
      )}

      {activeTab === 'findings' && (
        <FindingDetailPage
          findingId={selectedFindingId}
          findings={findings}
          onBack={() => setActiveTab('scans')}
          onSelectFinding={handleSelectFinding}
          onJumpToTrace={handleJumpToTrace}
          onOpenFixLoop={handleOpenFixLoop}
          onViewReport={handleViewReport}
        />
      )}

      {activeTab === 'traces' && (
        <TracesPage
          initialTraceId={selectedTraceId}
          findings={findings}
          onSelectFinding={handleSelectFinding}
        />
      )}

      {activeTab === 'fixloop' && fixLoopSession && (
        <FixLoopPage
          session={fixLoopSession}
          allFindings={findings.filter((f) => f.outcome === 'confirmed_vulnerable')}
          onSelectFinding={handleOpenFixLoop}
          onApplyMitigation={handleApplyMitigation}
          onRunRetest={handleRunRetest}
          onRunRegressionSuite={handleRunRegressionSuite}
        />
      )}

      {activeTab === 'reports' && report && (
        <ReportPage
          report={report}
          scans={scans}
          onSelectScanForReport={handleViewReport}
        />
      )}

      {activeTab === 'settings' && (
        <SettingsPage
          status={apiStatus}
          onUpdateBaseUrl={handleUpdateBaseUrl}
          onToggleDemoMode={handleToggleDemoMode}
          onRefreshHealth={handleRefreshHealth}
        />
      )}
    </AppShell>
  );
};

export default function App() {
  return (
    <ToastProvider>
      <AgentBreakApp />
    </ToastProvider>
  );
}
