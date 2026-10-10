# AgentBreak Frontend — AI Agent Cybersecurity Dashboard

AgentBreak is a production-quality cybersecurity platform engineered to evaluate AI agents (built on LangGraph, LlamaIndex, CrewAI, AutoGen, or custom adapters) for critical vulnerabilities such as:
- **Indirect Prompt Injection** via poisoned retrieved documents (RAG)
- **Direct Prompt Injection** and delimiter escaping
- **Unauthorized Tool Execution** and unsanitized parameters (SQL injection, shell execution)
- **Sensitive Data & Credential Exfiltration**
- **Permission & Policy Boundary Violations** (path traversal, unauthorized egress)
- **Excessive Agency & Unsafe Side-effects**

The platform includes **FixLoop™**, an engineering verification workflow that allows red-team operators to apply proposed mitigations, re-execute targeted attack vectors, and run benign functional regression suites to verify fixes.

---

## Technical Stack & Design System

- **Framework**: React 18 + TypeScript + Vite
- **Styling**: Tailwind CSS with custom restrained cybersecurity dark tokens
  - Main Background: `#0B0D10` (Charcoal)
  - Sidebar: `#111419`
  - Panels: `#15191F`
  - Subtle Borders: `#282E37`
  - Monospace Font: JetBrains Mono / Fira Code / ui-monospace
  - Exact Severity Palette:
    - Critical: `#3B1219` / `#7A1D2E` / `#FF6B72`
    - High: `#361F12` / `#6E381A` / `#FF9E66`
    - Medium: `#302A12` / `#61521A` / `#FFD166`
    - Low / Info: `#122436` / `#1A436E` / `#66B2FF`
    - Blocked / Passed: `#0E2A1C` / `#185834` / `#4ADE80`
- **Icons**: Lucide Icons
- **State & Routing**: Responsive AppShell with contextual tab state, full breadcrumbs, and live telemetry

---

## Directory Architecture

```
frontend/
├── public/
├── src/
│   ├── components/
│   │   ├── common/
│   │   │   ├── CodeBlock.tsx         # Syntax-highlighted code diffs with copy & line numbers
│   │   │   ├── FilterBar.tsx         # Multi-parameter combinable filter bar
│   │   │   ├── IdBadge.tsx           # Monospaced clickable copy ID badges
│   │   │   ├── OutcomeBadge.tsx      # Attempted, Blocked, Executed, Confirmed Vuln, Inconclusive
│   │   │   ├── StatusBadge.tsx       # Scan lifecycle state badges
│   │   │   └── Toast.tsx             # Accessible toast notification context & feedback
│   │   ├── layout/
│   │   │   ├── AppShell.tsx          # Persistent sidebar, topbar, modal runner, demo banner
│   │   │   ├── PageHeader.tsx        # Title, subtitle, actions
│   │   │   ├── Sidebar.tsx           # AgentBreak shield wordmark, collapsible navigation
│   │   │   └── Topbar.tsx            # Honest connection pill, latency indicator, quick scan CTA
│   │   ├── dashboard/
│   │   │   ├── RecentScansTable.tsx  # High-density recent scans listing
│   │   │   ├── ScanSummary.tsx       # 4 top-level KPI metric cards
│   │   │   ├── SeveritySummary.tsx   # Proportional severity distribution bar
│   │   │   └── VulnerabilityDistribution.tsx # Category coverage breakdown
│   │   ├── agents/
│   │   │   ├── AgentConfigurationSummary.tsx # Target agent inventory & tool matrices
│   │   │   └── AgentSetupForm.tsx    # Comprehensive agent registration form
│   │   ├── scans/
│   │   │   ├── ScanConfigurationForm.tsx # Vector selection & depth profiles
│   │   │   ├── ScanProgress.tsx      # Real-time evaluation progress stream & counters
│   │   │   └── ScanResultsTable.tsx  # Full vulnerability results table with filters
│   │   ├── findings/
│   │   │   ├── EvidenceViewer.tsx    # Trace logs, captured tool arguments, policy interventions
│   │   │   ├── FindingDetailPanel.tsx# Complete vulnerability dossier & reproduction
│   │   │   ├── RemediationPanel.tsx  # Copyable proposed patches & guardrail diffs
│   │   │   └── SeverityBadge.tsx     # Exact cybersecurity severity badges
│   │   ├── traces/
│   │   │   ├── ToolCallDetails.tsx   # Detailed tool arguments & outputs inspector
│   │   │   ├── TraceEventRow.tsx     # Expandable trace node with violation markers
│   │   │   └── TraceTimeline.tsx     # Vertical chronological event timeline & side inspector
│   │   ├── fixloop/
│   │   │   ├── FixLoopPanel.tsx      # 5-stage verification stepper
│   │   │   └── RegressionResults.tsx # 12/12 benign functional task regression suite
│   │   └── reports/
│   │       └── ReportPreview.tsx     # Audit-grade assessment report preview & export
│   ├── pages/
│   │   ├── AgentSetupPage.tsx
│   │   ├── DashboardPage.tsx
│   │   ├── FindingDetailPage.tsx
│   │   ├── FixLoopPage.tsx
│   │   ├── ReportPage.tsx
│   │   ├── ScanResultsPage.tsx
│   │   ├── SettingsPage.tsx
│   │   └── TracesPage.tsx
│   ├── services/
│   │   └── api.ts                    # Central API client with honest health & mock adapter
│   ├── mocks/
│   │   └── scanData.ts               # Realistic adversarial security test scenarios
│   ├── types/
│   │   └── index.ts                  # Domain models (Agent, Scan, Finding, TraceEvent, FixLoop)
│   ├── App.tsx
│   ├── index.css
│   └── main.tsx
├── package.json
├── tsconfig.json
├── vite.config.ts
└── tailwind.config.js
```

---

## Getting Started

### Prerequisites
- Node.js 18+ or 20+ LTS
- npm or pnpm

### Installation
```bash
cd frontend
npm install
```

### Run Local Development Server
```bash
npm run dev
```
The application will start on `http://localhost:5173`.

### Production Build & Typecheck
```bash
npm run build
npm run typecheck
```

---

## Live Engine vs Demo Mode

AgentBreak includes an honest connection status indicator in the top navigation bar:
- **Live Connected Mode**: When a backend API is reachable at `VITE_API_BASE_URL` (default: `http://localhost:8000`), the topbar displays `Connected · <latency> ms` and performs live REST calls against endpoints (`/api/agents`, `/api/scans`, `/api/findings`, `/api/traces`, `/api/fixloop`, `/api/reports`).
- **Demo Data Mode**: When the backend is offline or when manually toggled, the application shows `DEMO DATA (Offline)` with a visible banner. Scans and verifications operate deterministically against realistic cybersecurity red-team fixtures without fabricating remote responses.
