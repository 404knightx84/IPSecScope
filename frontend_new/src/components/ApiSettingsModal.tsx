import React, { useState } from 'react';
import { Settings, X, CheckCircle2, AlertTriangle, RefreshCw, Server } from 'lucide-react';
import { getApiBaseUrl, setApiBaseUrl, testConnection, type ConnectionTestResult } from '../api';

interface ApiSettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSaved: (newUrl: string) => void;
}

export const ApiSettingsModal: React.FC<ApiSettingsModalProps> = ({ isOpen, onClose, onSaved }) => {
  const [apiUrl, setApiUrl] = useState<string>(getApiBaseUrl());
  const [isTesting, setIsTesting] = useState<boolean>(false);
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(null);

  if (!isOpen) return null;

  const handleTest = async () => {
    setIsTesting(true);
    setTestResult(null);
    try {
      const res = await testConnection(apiUrl);
      setTestResult(res);
    } catch {
      setTestResult({
        healthy: false,
        status: 'offline',
        latencyMs: 0,
        corsOk: false,
        error: 'Network connection failed'
      });
    } finally {
      setIsTesting(false);
    }
  };

  const handleSave = () => {
    setApiBaseUrl(apiUrl);
    onSaved(apiUrl);
    onClose();
  };

  const handleResetDefault = () => {
    const def = 'http://localhost:8000/api';
    setApiUrl(def);
    setTestResult(null);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn">
      <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl max-w-md w-full overflow-hidden">
        {/* Modal Header */}
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
              <Settings className="w-4 h-4" />
            </div>
            <h3 className="text-sm font-bold text-white">Backend API & CORS Configuration</h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
              FastAPI Endpoint Base URL
            </label>
            <div className="relative">
              <input
                type="text"
                value={apiUrl}
                onChange={(e) => setApiUrl(e.target.value)}
                placeholder="http://localhost:8000/api"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-sky-500 pr-20"
              />
              <button
                onClick={handleResetDefault}
                className="absolute right-2 top-2 text-[10px] text-slate-400 hover:text-sky-300"
              >
                Reset Default
              </button>
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Direct connection to the Python FastAPI backend engine (CORS enabled for dev origins).
            </p>
          </div>

          {/* Test Connection Button */}
          <div>
            <button
              onClick={handleTest}
              disabled={isTesting || !apiUrl.trim()}
              className="w-full py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs border border-slate-700 flex items-center justify-center gap-2 transition-all disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isTesting ? 'animate-spin' : ''}`} />
              <span>{isTesting ? 'Testing CORS & Health...' : 'Test Connection & CORS'}</span>
            </button>
          </div>

          {/* Test Output Box */}
          {testResult && (
            <div
              className={`p-3.5 rounded-lg border text-xs space-y-2 ${
                testResult.healthy
                  ? 'bg-emerald-950/30 border-emerald-800 text-emerald-300'
                  : 'bg-rose-950/30 border-rose-800 text-rose-300'
              }`}
            >
              <div className="flex items-center justify-between font-bold">
                <div className="flex items-center gap-1.5">
                  {testResult.healthy ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-rose-400" />
                  )}
                  <span>{testResult.healthy ? 'Connection Successful' : 'Backend Unreachable'}</span>
                </div>
                <span className="font-mono text-[10px]">
                  {testResult.latencyMs}ms
                </span>
              </div>

              {testResult.healthy ? (
                <div className="text-[11px] text-slate-300 space-y-1">
                  <div>Engine: <strong>{testResult.service}</strong></div>
                  <div>CORS Access: <strong className="text-emerald-400">Allowed (* wildcard / credentials)</strong></div>
                  <div>Status: <span className="font-mono text-emerald-400">{testResult.status}</span></div>
                </div>
              ) : (
                <div className="text-[11px] text-slate-300 space-y-1">
                  <div>CORS / Network Error: {testResult.error || 'Server is offline or port 8000 is not running.'}</div>
                  <div className="text-[10px] text-amber-400 mt-1">
                    Tip: IPsecScope automatically uses high-fidelity client simulation when offline, so all features continue to work.
                  </div>
                </div>
              )}
            </div>
          )}

          {/* CORS & Architecture Info */}
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800 text-[11px] text-slate-400 space-y-1">
            <div className="flex items-center gap-1.5 font-semibold text-slate-300">
              <Server className="w-3.5 h-3.5 text-sky-400" />
              <span>Backend Deployment Note</span>
            </div>
            <p className="leading-relaxed">
              To launch the real backend on port 8000:
              <br />
              <code className="text-sky-300 bg-slate-900 px-1 py-0.5 rounded text-[10px]">uvicorn app.main:app --port 8000 --reload</code>
            </p>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-5 py-3.5 border-t border-slate-800 bg-slate-950/60 flex items-center justify-end gap-2.5">
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg text-xs text-slate-400 hover:text-white transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            className="px-4 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-bold text-xs shadow-md shadow-sky-600/20 transition-all"
          >
            Save Settings
          </button>
        </div>
      </div>
    </div>
  );
};
