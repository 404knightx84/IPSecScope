import React from 'react';
import { FileCode, Clock, ShieldCheck, Layers, Radio } from 'lucide-react';
import type { SummaryData } from '../types/ipsec';

interface SummaryHeaderProps {
  summary: SummaryData;
}

export const SummaryHeader: React.FC<SummaryHeaderProps> = ({ summary }) => {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg mb-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-sky-500/10 border border-sky-500/20 rounded-lg text-sky-400">
            <FileCode className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs uppercase font-bold tracking-wider text-slate-400">Target Capture File</span>
              <span className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800/60 font-medium">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> Analysis Complete
              </span>
            </div>
            <h1 className="text-lg md:text-xl font-bold text-white tracking-tight break-all">
              {summary.filename}
            </h1>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs text-slate-400">
          <Clock className="w-4 h-4 text-sky-400" />
          <span>Capture Duration:</span>
          <strong className="text-white text-sm">{summary.duration_sec}s</strong>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-4">
        <div className="bg-slate-800/40 border border-slate-800 rounded-lg p-3">
          <div className="flex items-center gap-2 text-slate-400 text-xs mb-1">
            <Layers className="w-3.5 h-3.5 text-sky-400" />
            <span>Total Packets</span>
          </div>
          <p className="text-xl font-bold text-white">{summary.total_packets.toLocaleString()}</p>
        </div>

        <div className="bg-slate-800/40 border border-slate-800 rounded-lg p-3">
          <div className="flex items-center gap-2 text-emerald-400 text-xs mb-1">
            <Radio className="w-3.5 h-3.5" />
            <span>IKE Handshake Packets</span>
          </div>
          <p className="text-xl font-bold text-emerald-400">{summary.ike_count.toLocaleString()}</p>
          <span className="text-[10px] text-slate-400">UDP Ports 500 / 4500</span>
        </div>

        <div className="bg-slate-800/40 border border-slate-800 rounded-lg p-3">
          <div className="flex items-center gap-2 text-amber-400 text-xs mb-1">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>ESP Tunnel Packets</span>
          </div>
          <p className="text-xl font-bold text-amber-400">{summary.esp_count.toLocaleString()}</p>
          <span className="text-[10px] text-slate-400">IP Protocol 50</span>
        </div>

        <div className="bg-slate-800/40 border border-slate-800 rounded-lg p-3">
          <div className="flex items-center gap-2 text-purple-400 text-xs mb-1">
            <Clock className="w-3.5 h-3.5" />
            <span>Average Throughput</span>
          </div>
          <p className="text-xl font-bold text-purple-400">
            {summary.duration_sec > 0 ? (summary.total_packets / summary.duration_sec).toFixed(1) : '0'}
            <span className="text-xs font-normal text-slate-400 ml-1">pkts/sec</span>
          </p>
        </div>
      </div>
    </div>
  );
};
