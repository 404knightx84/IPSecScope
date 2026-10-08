import React, { useState } from 'react';
import { Grid, ShieldAlert, AlertTriangle } from 'lucide-react';
import type { Threat } from '../types/ipsec';

interface ThreatMatrixProps {
  threats: Threat[];
}

export const ThreatMatrix: React.FC<ThreatMatrixProps> = ({ threats }) => {
  const [activeThreat, setActiveThreat] = useState<Threat | null>(null);

  // 5x5 Likelihood (1..5) by Impact (1..5)
  // Likelihood: 5=Almost Certain, 4=Likely, 3=Possible, 2=Unlikely, 1=Rare
  // Impact: 1=Insignificant, 2=Minor, 3=Moderate, 4=Major, 5=Catastrophic
  const likelihoodLevels = [3, 2, 1];
  const likelihoodLabels: Record<number, string> = { 3: 'High', 2: 'Medium', 1: 'Low' };
  const impactLevels = [1, 2, 3];
  const impactLabels: Record<number, string> = { 1: 'Low', 2: 'Medium', 3: 'High' };

  const getCellRiskBg = (likelihood: number, impact: number) => {
    const score = likelihood * impact;
    if (score >= 9) return 'bg-rose-950/70 border-rose-900/60 hover:bg-rose-900/80';
    if (score >= 6) return 'bg-orange-950/70 border-orange-900/60 hover:bg-orange-900/80';
    if (score >= 3) return 'bg-amber-950/60 border-amber-900/60 hover:bg-amber-900/80';
    return 'bg-emerald-950/50 border-emerald-900/50 hover:bg-emerald-900/70';
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl mb-8">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-6">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Grid className="w-6 h-6 text-sky-400" />
            Threat Risk Matrix (Likelihood vs. Impact)
          </h2>
          <p className="text-sm text-slate-400">
            Mapping cryptographic attack vectors based on observed weak parameters and protocol exposures
          </p>
        </div>

        <div className="flex items-center gap-3 text-xs">
          <span className="flex items-center gap-1 text-rose-400 font-semibold">
            <span className="w-2.5 h-2.5 rounded bg-rose-500" /> Critical Risk
          </span>
          <span className="flex items-center gap-1 text-orange-400 font-semibold">
            <span className="w-2.5 h-2.5 rounded bg-orange-500" /> High Risk
          </span>
          <span className="flex items-center gap-1 text-amber-400 font-semibold">
            <span className="w-2.5 h-2.5 rounded bg-amber-500" /> Medium Risk
          </span>
          <span className="flex items-center gap-1 text-emerald-400 font-semibold">
            <span className="w-2.5 h-2.5 rounded bg-emerald-500" /> Low Risk
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* The 5x5 Grid */}
        <div className="lg:col-span-8 overflow-x-auto">
          <div className="min-w-[500px]">
            {/* Y-axis Label */}
            <div className="text-xs uppercase tracking-wider text-slate-400 font-bold mb-2">
              Likelihood &uarr;
            </div>

            <div className="space-y-1.5">
              {likelihoodLevels.map((l) => (
                <div key={l} className="flex items-center gap-2">
                  {/* Y-axis row header */}
                  <span className="w-24 text-right text-[11px] font-semibold text-slate-400 shrink-0">
                    {likelihoodLabels[l]}
                  </span>

                  {/* 5 Impact Cells for this Likelihood */}
                  <div className="grid grid-cols-5 gap-1.5 flex-1">
                    {impactLevels.map((imp) => {
                      const threatsInCell = threats.filter(
                        (t) => t.likelihood === l && t.impact === imp
                      );

                      return (
                        <div
                          key={`${l}_${imp}`}
                          className={`h-16 rounded border p-1.5 flex flex-col justify-between transition-all ${getCellRiskBg(
                            l,
                            imp
                          )}`}
                        >
                          <span className="text-[9px] text-slate-400 font-mono">
                            L{l} : I{imp}
                          </span>

                          <div className="flex flex-wrap gap-1 overflow-y-auto max-h-10">
                            {threatsInCell.map((t, idx) => (
                              <button
                                key={idx}
                                onClick={() => setActiveThreat(t)}
                                className="text-[10px] bg-slate-900/90 text-white font-bold px-1.5 py-0.5 rounded border border-white/20 hover:scale-105 transition-transform truncate max-w-full shadow"
                                title={t.name}
                              >
                                {t.name}
                              </button>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}

              {/* X-axis Column Headers */}
              <div className="flex items-center gap-2 pt-2">
                <span className="w-24 text-right text-[11px] font-bold text-slate-500 shrink-0">
                  Impact &rarr;
                </span>
                <div className="grid grid-cols-5 gap-1.5 flex-1 text-center text-[11px] font-semibold text-slate-400">
                  {impactLevels.map((imp) => (
                    <div key={imp}>{impactLabels[imp]}</div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Threat Details Drawer / Panel */}
        <div className="lg:col-span-4 bg-slate-800/50 border border-slate-750 rounded-lg p-4">
          <h3 className="text-xs uppercase tracking-wider text-slate-400 font-bold mb-3 flex items-center gap-1.5">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            Threat Cell Inspector
          </h3>

          {activeThreat ? (
            <div className="space-y-3">
              <div>
                <span className="text-[10px] uppercase font-bold text-sky-400">Selected Threat</span>
                <h4 className="text-sm font-bold text-white">{activeThreat.name}</h4>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-xs px-2 py-0.5 rounded bg-slate-700 text-slate-200">
                  Likelihood: <strong>{activeThreat.likelihood}/3</strong>
                </span>
                <span className="text-xs px-2 py-0.5 rounded bg-slate-700 text-slate-200">
                  Impact: <strong>{activeThreat.impact}/3</strong>
                </span>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed border-t border-slate-700 pt-2">
                {activeThreat.description}
              </p>
            </div>
          ) : (
            <div className="text-center py-8 text-slate-500 text-xs">
              <ShieldAlert className="w-8 h-8 mx-auto mb-2 text-slate-600" />
              Click any plotted threat in the matrix cells to inspect attack vectors and impact ratings.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
