import React from 'react';
import { ShieldAlert, LockKeyhole, Lightbulb } from 'lucide-react';
import type { NotDeterminableData } from '../types/ipsec';

interface NotDeterminableCardProps {
  data: NotDeterminableData;
}

export const NotDeterminableCard: React.FC<NotDeterminableCardProps> = ({ data }) => {
  return (
    <div className="bg-slate-900/90 border-2 border-slate-700/80 rounded-xl p-5 shadow-xl flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-slate-800 text-slate-300 border border-slate-700">
            <LockKeyhole className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">Not determinable</h3>
            <p className="text-xs text-slate-400">What this capture cannot show, and why</p>
          </div>
        </div>
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-slate-800/90 text-slate-300 border border-slate-600">
          <ShieldAlert className="w-3.5 h-3.5 text-slate-400" />
          Not determinable
        </span>
      </div>

      {data.items.length === 0 ? (
        <p className="text-xs text-slate-400">Every item was determined from this capture.</p>
      ) : (
        <div className="space-y-3">
          {data.items.map((item, idx) => (
            <div key={idx} className="bg-slate-800/50 p-3 rounded-lg border border-slate-700/60">
              <div className="text-xs font-bold text-slate-200 mb-1">{item.parameter}</div>
              <p className="text-[11px] text-slate-400 leading-relaxed pl-3 border-l-2 border-slate-600">{item.reason}</p>
              {item.advisor && (
                <div className="mt-2 flex gap-1.5 text-[11px] text-sky-200/90 bg-sky-950/40 border border-sky-800/60 rounded p-2">
                  <Lightbulb className="w-3.5 h-3.5 text-sky-400 shrink-0 mt-0.5" />
                  <span>{item.advisor}</span>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
