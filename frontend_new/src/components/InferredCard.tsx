import React from 'react';
import { Sparkles, HelpCircle } from 'lucide-react';
import type { InferredData } from '../types/ipsec';

interface InferredCardProps {
  data: InferredData;
}

export const InferredCard: React.FC<InferredCardProps> = ({ data }) => {
  return (
    <div className="bg-slate-900 border-2 border-amber-500/40 rounded-xl p-5 shadow-xl flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">Inferred</h3>
            <p className="text-xs text-slate-400">Estimated from ESP lengths, rekey timing and sizes</p>
          </div>
        </div>
        <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-amber-500/20 text-amber-300 border border-amber-500/40">
          <HelpCircle className="w-3.5 h-3.5 text-amber-400" />
          Inferred
        </span>
      </div>

      {data.items.length === 0 ? (
        <p className="text-xs text-slate-400">Nothing could be inferred from this capture.</p>
      ) : (
        <div className="space-y-2.5">
          {data.items.map((it) => (
            <div key={it.id} className="bg-slate-800/60 p-3 rounded-lg border border-slate-700/60">
              <div className="flex items-center justify-between gap-2">
                <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wide">{it.label}</div>
                <div className="flex items-center gap-1.5 shrink-0">
                  {it.lowConfidence && (
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/30">
                      LOW CONFIDENCE
                    </span>
                  )}
                  {it.confidence !== null && (
                    <span className="text-[11px] font-bold px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40">
                      {Math.round(it.confidence * 100)}%
                    </span>
                  )}
                </div>
              </div>
              <div className="text-sm font-bold text-white break-words">{it.value}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
