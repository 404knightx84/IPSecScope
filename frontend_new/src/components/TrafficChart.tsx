import React from 'react';
import { BarChart3, AlertTriangle } from 'lucide-react';
import type { TrafficData } from '../types/ipsec';

interface TrafficChartProps {
  traffic: TrafficData;
}

export const TrafficChart: React.FC<TrafficChartProps> = ({ traffic }) => {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl flex flex-col">
      <div className="flex items-center gap-2 mb-4">
        <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
          <BarChart3 className="w-5 h-5" />
        </div>
        <div>
          <h3 className="text-base font-bold text-white">Traffic type inside ESP</h3>
          <p className="text-xs text-slate-400">
            {traffic.value ? `Most likely: ${traffic.value}` : 'Not determinable'}
            {traffic.windows > 0 ? ` | ${traffic.windows} five-second windows` : ''}
          </p>
        </div>
      </div>

      {traffic.smoke_model && (
        <div className="mb-3 flex gap-2 text-[11px] text-amber-200 bg-amber-950/40 border border-amber-800/60 rounded p-2">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
          <span>Preliminary model. It has not yet been tested on a held-out repeat, so treat this as low confidence.</span>
        </div>
      )}

      {traffic.probabilities.length === 0 ? (
        <p className="text-xs text-slate-400">{traffic.reason || 'No traffic estimate for this capture.'}</p>
      ) : (
        <div className="space-y-3">
          {traffic.probabilities.map((item) => {
            const pct = Math.round(item.probability * 100);
            return (
              <div key={item.type} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-slate-200">{item.type}</span>
                  <span className="font-mono font-bold text-sky-400">{pct}%</span>
                </div>
                <div className="w-full bg-slate-800 rounded-full h-3 overflow-hidden p-0.5">
                  <div
                    className={`h-full rounded-full transition-all duration-700 ${pct >= 50 ? 'bg-sky-500' : pct >= 20 ? 'bg-cyan-600' : 'bg-slate-600'}`}
                    style={{ width: `${Math.max(pct, 2)}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
