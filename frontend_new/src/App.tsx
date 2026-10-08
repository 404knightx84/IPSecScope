import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  Activity,
  RefreshCw,
  Award,
  Settings,
  AlertTriangle,
  XCircle
} from 'lucide-react';
import type { AnalysisResponse, SamplePcap } from './types/ipsec';
import { fetchHealth, fetchScenarios, analyzePcap, createSession, startSession, stopSession, openSessionSocket, adaptResult, toConfidencePoints, toTimelineEvents } from './api';
import type { ConfidencePoint, TimelineEvent } from './types/ipsec';
import { ConfidenceChart } from './components/ConfidenceChart';
import { EventLog } from './components/EventLog';
import { SourceSelector } from './components/SourceSelector';
import { SummaryHeader } from './components/SummaryHeader';
import { ObservedCard } from './components/ObservedCard';
import { InferredCard } from './components/InferredCard';
import { NotDeterminableCard } from './components/NotDeterminableCard';
import { TrafficChart } from './components/TrafficChart';
import { SecurityScoreGauge } from './components/SecurityScoreGauge';
import { FindingsTable } from './components/FindingsTable';
import { ThreatMatrix } from './components/ThreatMatrix';
import { ReportButtons } from './components/ReportButtons';
import { EvaluationPage } from './components/EvaluationPage';
import { ApiSettingsModal } from './components/ApiSettingsModal';

export const App: React.FC = () => {
  const [activeNav, setActiveNav] = useState<'dashboard' | 'evaluation'>('dashboard');
  const [samples, setSamples] = useState<SamplePcap[]>([]);
  const [samplesError, setSamplesError] = useState<string | null>(null);
  const [analysisData, setAnalysisData] = useState<AnalysisResponse | null>(null);
  const [currentScenarioId, setCurrentScenarioId] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [uploadProgress, setUploadProgress] = useState<number>(0);
  const [backendStatus, setBackendStatus] = useState<'connected' | 'offline' | 'checking'>('checking');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isSettingsOpen, setIsSettingsOpen] = useState<boolean>(false);
  const [replayRunning, setReplayRunning] = useState<boolean>(false);
  const [history, setHistory] = useState<ConfidencePoint[]>([]);
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const sessionRef = useRef<{ id: string; ws: WebSocket } | null>(null);

  const handleStop = async () => {
    const cur = sessionRef.current;
    sessionRef.current = null;
    if (cur) { cur.ws.close(); await stopSession(cur.id); }
    setReplayRunning(false);
  };

  const handlePlay = async (scenarioId: string, speed: number) => {
    setErrorMessage(null);
    setHistory([]); setEvents([]); setAnalysisData(null);
    setCurrentScenarioId(scenarioId);
    try {
      const id = await createSession(scenarioId, speed);
      const ws = openSessionSocket(id, (m) => {
        if (m.type === 'update' && m.result) {
          setAnalysisData(adaptResult(m.result, scenarioId));
          setHistory(toConfidencePoints(m.history || []));
          setEvents(toTimelineEvents(m.events || []) as TimelineEvent[]);
        }
        if (m.type === 'state' && m.state !== 'running') setReplayRunning(false);
        if (m.type === 'update' && m.final) setReplayRunning(false);
      }, () => setReplayRunning(false));
      sessionRef.current = { id, ws };
      setReplayRunning(true);
      await startSession(id);
    } catch (e: unknown) {
      setReplayRunning(false);
      setErrorMessage(`Replay failed: ${e instanceof Error ? e.message : 'unknown error'}`);
    }
  };

  useEffect(() => () => { sessionRef.current?.ws.close(); }, []);

  // Check the backend and load the scenario list on mount
  useEffect(() => {
    async function init() {
      await refreshBackendStatus();
      try {
        setSamples(await fetchScenarios());
        setSamplesError(null);
      } catch (e: unknown) {
        setSamplesError(e instanceof Error ? e.message : 'unknown error');
      }
    }
    init();
  }, []);

  const refreshBackendStatus = async () => {
    setBackendStatus('checking');
    const health = await fetchHealth();
    setBackendStatus(health.status === 'healthy' ? 'connected' : 'offline');
  };

  const handleAnalyze = async (file: File | null, sampleId?: string) => {
    setIsLoading(true);
    setUploadProgress(0);
    setErrorMessage(null);
    setCurrentScenarioId(sampleId || '');
    try {
      const result = await analyzePcap(file, sampleId, (pct) => setUploadProgress(pct));
      setAnalysisData(result);
    } catch (err: unknown) {
      console.error('Analysis failed:', err);
      const msg = err instanceof Error ? err.message : 'Analysis failed.';
      setErrorMessage(`Analysis failed: ${msg}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-sky-500 selection:text-slate-950">
      {/* Top Navbar */}
      <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-50 shadow-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          {/* Logo & Platform Info */}
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gradient-to-tr from-sky-500 to-indigo-600 rounded-lg text-white shadow-lg shadow-sky-500/20">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-lg tracking-tight text-white">IPsecScope</span>
                <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 rounded bg-sky-950 text-sky-400 border border-sky-800 font-mono">
                  v2.4
                </span>
                <span className="hidden sm:inline text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  SIH26160
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Passive IPsec Network Telemetry & Cryptographic Inference Platform
              </p>
            </div>
          </div>

          {/* Navigation Tabs (Dashboard vs Evaluation) */}
          <div className="flex items-center bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs font-semibold">
            <button
              onClick={() => setActiveNav('dashboard')}
              className={`px-3.5 py-1.5 rounded-md flex items-center gap-2 transition-all ${
                activeNav === 'dashboard'
                  ? 'bg-sky-500 text-white shadow-md shadow-sky-500/20'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              <span>Analyzer Dashboard</span>
            </button>

            <button
              onClick={() => setActiveNav('evaluation')}
              className={`px-3.5 py-1.5 rounded-md flex items-center gap-2 transition-all ${
                activeNav === 'evaluation'
                  ? 'bg-sky-500 text-white shadow-md shadow-sky-500/20'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Award className="w-3.5 h-3.5" />
              <span>Evaluation & Benchmarks</span>
              <span className="px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-400 text-[10px] font-mono border border-emerald-800">
                make eval
              </span>
            </button>
          </div>

          {/* Right Action Icons (Status / Settings / Reset) */}
          <div className="flex items-center gap-2 sm:gap-3">
            {/* Backend Status Indicator */}
            <div
              onClick={() => setIsSettingsOpen(true)}
              className="cursor-pointer flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-800/90 hover:bg-slate-800 border border-slate-700 text-xs transition-colors"
              title="Click to configure API settings"
            >
              <span
                className={`w-2 h-2 rounded-full ${
                  backendStatus === 'connected'
                    ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]'
                    : backendStatus === 'checking'
                    ? 'bg-amber-400 animate-ping'
                    : 'bg-amber-400'
                }`}
              />
              <span className="text-slate-300 font-medium hidden md:inline">
                {backendStatus === 'connected' ? 'FastAPI Connected' : 'Backend offline'}
              </span>
            </div>

            {/* API Settings Button */}
            <button
              onClick={() => setIsSettingsOpen(true)}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
              title="API Base URL and CORS Configuration"
            >
              <Settings className="w-4 h-4" />
            </button>

            {/* Reset Demo Baseline */}
            <button
              onClick={() => { setAnalysisData(null); setErrorMessage(null); setCurrentScenarioId(''); }}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs flex items-center gap-1.5 transition-all"
              title="Clear results"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span className="hidden lg:inline">Reset</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Error Notification Banner */}
        {errorMessage && (
          <div className="mb-6 p-4 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-200 flex items-center justify-between gap-3 animate-fadeIn">
            <div className="flex items-center gap-2.5">
              <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
              <span className="text-xs font-semibold">{errorMessage}</span>
            </div>
            <button
              onClick={() => setErrorMessage(null)}
              className="p-1 rounded hover:bg-rose-900/60 text-rose-300"
            >
              <XCircle className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* View 1: Evaluation Page (make eval) */}
        {activeNav === 'evaluation' && (
          <EvaluationPage />
        )}

        {/* View 2: Analyzer Dashboard */}
        {activeNav === 'dashboard' && (
          <div className="space-y-8">
            {/* 1. Source Selector (Demo, Upload, Live) */}
            <SourceSelector
              samples={samples}
              samplesError={samplesError}
              onAnalyze={handleAnalyze}
              isLoading={isLoading}
              uploadProgress={uploadProgress}
              currentScenarioId={currentScenarioId}
              onPlay={handlePlay}
              onStop={handleStop}
              replayRunning={replayRunning}
            />

            {/* 2. Analysis Results Section */}
            {analysisData && (
              <div className="space-y-8 animate-fadeIn">
                {/* 2.1 Summary Header */}
                <SummaryHeader summary={analysisData.summary} />

                {/* 2.2 Tri-Tier Cryptographic Parameter Audit */}
                <div>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
                    <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                      <Activity className="w-4 h-4 text-sky-400" />
                      Tri-Tier Cryptographic Parameter Audit
                    </h2>
                    <span className="text-xs text-slate-400">
                      Judicial Separation: Cleartext Evidence vs. Statistical Heuristics vs. Non-Observable Limits
                    </span>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Definitively Observed Card (Emerald) */}
                    <ObservedCard data={analysisData.observed} />

                    {/* Statistically Inferred Card (Amber) */}
                    <InferredCard data={analysisData.inferred} />

                    {/* Cryptographically Not Determinable Card (Slate with Advisor Note) */}
                    <NotDeterminableCard data={analysisData.not_determinable} />
                  </div>
                </div>

                {/* 2.3 Analytics & Traffic Classification Row */}
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                  {/* Security Score Gauge with Range (e.g. 82 to 88) */}
                  <div className="lg:col-span-5 flex flex-col">
                    <SecurityScoreGauge
                      score={analysisData.score_range.min}
                      riskLevel={analysisData.risk_level}
                      scoreRange={analysisData.score_range}
                    />
                    {(analysisData.floor_applied || (analysisData.best_case_risk && analysisData.best_case_risk !== analysisData.risk_level)) && (
                      <div className="mt-3 text-[11px] text-slate-300 bg-slate-900 border border-slate-800 rounded-lg p-3">
                        {analysisData.floor_applied && (
                          <p>Severity floor applied: a serious finding sets the minimum risk level whatever the numeric score.</p>
                        )}
                        {analysisData.best_case_risk && analysisData.best_case_risk !== analysisData.risk_level && (
                          <p>Best case, if every undetermined item turned out fine: {analysisData.best_case_risk}.</p>
                        )}
                      </div>
                    )}
                  </div>
                  {/* Traffic Probability Distribution */}
                  <div className="lg:col-span-7 flex flex-col">
                    <TrafficChart traffic={analysisData.traffic} />
                  </div>
                </div>

                {/* 2.4 Replay views: confidence over time and event log */}
                {(history.length > 0 || events.length > 0) && (
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <ConfidenceChart data={history} />
                    <EventLog events={events} />
                  </div>
                )}

                {/* 2.5  */}
                <ThreatMatrix threats={analysisData.threat_matrix} />

                {/* 2.6 Vulnerability Findings & Fixes Table */}
                <FindingsTable findings={analysisData.findings} />

                {/* 2.7 Export Reports & Downloads */}
                <ReportButtons
                  analysisData={analysisData}
                />
              </div>
            )}
          </div>
        )}
      </main>

      {/* API Settings Modal */}
      <ApiSettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        onSaved={async () => {
          await refreshBackendStatus();
        }}
      />

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <span>IPsecScope &bull; Passive Cryptographic Analysis & Security Assessment Framework</span>
          <div className="flex items-center gap-4 font-mono text-[11px] text-slate-400">
            <span>RFC 7296 (IKEv2)</span>
            <span>RFC 4303 (ESP)</span>
            <span>SIH26160 NTRO Specification</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
