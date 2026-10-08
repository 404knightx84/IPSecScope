import React, { useState } from 'react';
import { Play, UploadCloud, Radio, Layers } from 'lucide-react';
import type { SamplePcap } from '../types/ipsec';
import { UploadPanel } from './UploadPanel';

interface SourceSelectorProps {
  samples: SamplePcap[];
  samplesError: string | null;
  onAnalyze: (file: File | null, sampleId?: string) => Promise<void>;
  isLoading: boolean;
  uploadProgress: number;
  currentScenarioId?: string;
  onPlay?: (id: string, speed: number) => void;
  onStop?: () => void;
  replayRunning?: boolean;
}

export const SourceSelector: React.FC<SourceSelectorProps> = ({
  samples, samplesError, onAnalyze, isLoading, uploadProgress, currentScenarioId, onPlay, onStop, replayRunning
}) => {
  const [speed, setSpeed] = useState<number>(5);
  const [tab, setTab] = useState<'demo' | 'upload' | 'live'>('demo');
  const tabBtn = (id: 'demo' | 'upload' | 'live', icon: React.ReactNode, label: string) => (
    <button
      onClick={() => setTab(id)}
      className={`px-3.5 py-1.5 rounded-md flex items-center gap-2 transition-all ${
        tab === id ? 'bg-sky-500 text-white shadow-md shadow-sky-500/20' : 'text-slate-400 hover:text-slate-200'
      }`}
    >
      {icon}
      <span>{label}</span>
    </button>
  );

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-xl mb-8 overflow-hidden">
      <div className="border-b border-slate-800 bg-slate-950/60 px-6 py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Radio className="w-5 h-5 text-sky-400" />
            Capture source
          </h2>
          <p className="text-xs text-slate-400">Stored lab scenarios (with timed replay), an uploaded pcap, or (planned) a live connection</p>
        </div>
        <div className="flex items-center bg-slate-900 p-1 rounded-lg border border-slate-800 text-xs font-semibold">
          {tabBtn('demo', <Play className="w-3.5 h-3.5" />, 'Demo scenarios')}
          {tabBtn('upload', <UploadCloud className="w-3.5 h-3.5" />, 'Upload')}
          {tabBtn('live', <Layers className="w-3.5 h-3.5" />, 'Live')}
        </div>
      </div>

      {tab === 'demo' && (
        <div className="p-6">
          <p className="text-xs text-slate-400 mb-4">
            Each scenario is a real capture from the lab, analyzed by the same pipeline as an upload. Press Play to replay a capture with its original timing, like a live stream.
          </p>
          {samplesError && (
            <div className="mb-4 p-3 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-200 text-xs font-semibold">
              Could not load scenarios: {samplesError}
            </div>
          )}
          {onPlay && (
            <div className="mb-3 flex items-center gap-2 text-xs text-slate-300">
              <span>Replay speed</span>
              <select value={speed} onChange={(e) => setSpeed(Number(e.target.value))}
                      disabled={replayRunning}
                      className="bg-slate-950 border border-slate-800 rounded px-2 py-1">
                <option value={1}>1x</option><option value={5}>5x</option><option value={10}>10x</option>
              </select>
            </div>
          )}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {samples.map((s) => (
              <div
                key={s.id}
                className={`p-3.5 rounded-lg border transition-all ${
                  s.id === currentScenarioId ? 'border-sky-400 bg-sky-950/40' : 'border-slate-800 hover:border-slate-600 bg-slate-800/30'
                }`}
              >
                <button
                  disabled={isLoading || replayRunning}
                  onClick={() => onAnalyze(null, s.id)}
                  className="w-full text-left disabled:opacity-60"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-bold text-white font-mono">{s.id}</span>
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">{s.scenario}</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1">{s.description}</p>
                </button>
                {onPlay && (
                  <div className="mt-2 flex items-center gap-2">
                    {replayRunning && s.id === currentScenarioId ? (
                      <button onClick={() => onStop?.()} className="px-2.5 py-1 rounded bg-rose-600 text-white text-[11px] font-semibold">Stop</button>
                    ) : (
                      <button
                        disabled={isLoading || replayRunning}
                        onClick={() => onPlay(s.id, speed)}
                        className="px-2.5 py-1 rounded bg-sky-600 text-white text-[11px] font-semibold disabled:opacity-50"
                      >
                        Play replay
                      </button>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
          {isLoading && <p className="mt-4 text-xs text-sky-300">Analyzing... {uploadProgress}%</p>}
        </div>
      )}

      {tab === 'upload' && (
        <div className="p-6">
          <UploadPanel samples={[]} onAnalyze={onAnalyze} isLoading={isLoading} uploadProgress={uploadProgress} />
        </div>
      )}

      {tab === 'live' && (
        <div className="p-6 text-sm text-slate-300">
          <p className="font-semibold text-white mb-1">Live capture from a real gateway is not built in this prototype.</p>
          <p className="text-xs text-slate-400">
            The session manager and WebSocket are built. Use Demo scenarios and press Play replay to see a stored capture analysed like a live stream. Capturing from a local interface or over SSH is a planned extension, and only systems you own or are authorised to monitor should be connected.
          </p>
        </div>
      )}
    </div>
  );
};
