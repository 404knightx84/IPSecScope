import React from 'react';
import { Eye, CheckCircle2 } from 'lucide-react';
import type { ObservedData } from '../types/ipsec';

interface ObservedCardProps {
  data: ObservedData;
}

const shortPackets = (ev: number[]) =>
  ev.length === 0 ? '' : `Packets ${ev.slice(0, 5).map(n => `#${n}`).join(', ')}${ev.length > 5 ? ' ...' : ''}`;

export const ObservedCard: React.FC<ObservedCardProps> = ({ data }) => {
  return (
    <div className="bg-slate-900 border-2 border-emerald-500/40 rounded-xl p-5 shadow-xl flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <Eye className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">Observed</h3>
            <p className="text-xs text-slate-400">Read directly from cleartext IKE packets</p>
          </div>
        </div>
        <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          Observed
        </span>
      </div>

      {data.items.length === 0 ? (
        <p className="text-xs text-slate-400">No IKE handshake was found in this capture.</p>
      ) : (
        <div className="space-y-2.5">
          {data.items.map((it) => (
            <div key={it.id} className="bg-slate-800/60 p-3 rounded-lg border border-slate-700/60">
              <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wide">{it.label}</div>
              <div className="text-sm font-bold text-white break-words">{it.value}</div>
              {it.evidence.length > 0 && (
                <div className="text-[11px] text-slate-500 font-mono mt-0.5">{shortPackets(it.evidence)}</div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
