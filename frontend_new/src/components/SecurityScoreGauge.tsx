import React from 'react';
import { Shield, ShieldAlert, AlertTriangle, CheckCircle, Info } from 'lucide-react';
import type { ScoreRange } from '../types/ipsec';

interface SecurityScoreGaugeProps {
  score: number; // 0 - 100
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  scoreRange?: ScoreRange;
}

export const SecurityScoreGauge: React.FC<SecurityScoreGaugeProps> = ({ score, riskLevel, scoreRange }) => {
  // SVG circular gauge calculations
  const radius = 64;
  const strokeWidth = 12;
  const circumference = 2 * Math.PI * radius;
  // Use 75% arc
  const arcLength = circumference * 0.75;
  const strokeDashoffset = arcLength - (arcLength * score) / 100;

  // Calculate default range if not provided (e.g. 85 -> "82 to 88")
  const computedRange: ScoreRange = scoreRange || {
    min: Math.max(0, score - (riskLevel === 'Critical' ? 3 : 4)),
    max: Math.min(100, score + (riskLevel === 'Critical' ? 3 : 4)),
    display: `${Math.max(0, score - (riskLevel === 'Critical' ? 3 : 4))} to ${Math.min(100, score + (riskLevel === 'Critical' ? 3 : 4))}`
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'Critical':
        return {
          text: 'text-rose-400',
          bg: 'bg-rose-950/40',
          border: 'border-rose-800',
          stroke: '#F43F5E',
          icon: <ShieldAlert className="w-5 h-5 text-rose-400" />
        };
      case 'High':
        return {
          text: 'text-orange-400',
          bg: 'bg-orange-950/40',
          border: 'border-orange-800',
          stroke: '#FB923C',
          icon: <AlertTriangle className="w-5 h-5 text-orange-400" />
        };
      case 'Medium':
        return {
          text: 'text-amber-400',
          bg: 'bg-amber-950/40',
          border: 'border-amber-800',
          stroke: '#FBBF24',
          icon: <AlertTriangle className="w-5 h-5 text-amber-400" />
        };
      default:
        return {
          text: 'text-emerald-400',
          bg: 'bg-emerald-950/40',
          border: 'border-emerald-800',
          stroke: '#34D399',
          icon: <CheckCircle className="w-5 h-5 text-emerald-400" />
        };
    }
  };

  const currentTheme = getRiskColor(riskLevel);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl flex flex-col items-center justify-between h-full">
      <div className="w-full flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20 shadow-inner">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">Cryptographic Posture</h3>
            <p className="text-xs text-slate-400">Security Score & Range Range</p>
          </div>
        </div>

        {/* Range Badge (9.6 Requirement: "82 to 88") */}
        <div className="text-right">
          <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider block">Estimated Range</span>
          <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-slate-800 text-sky-300 border border-slate-700">
            {computedRange.display}
          </span>
        </div>
      </div>

      {/* Radial Gauge */}
      <div className="relative flex items-center justify-center my-3">
        <svg className="w-48 h-48 -rotate-[135deg]" viewBox="0 0 160 160">
          {/* Background Track */}
          <circle
            cx="80"
            cy="80"
            r={radius}
            fill="transparent"
            stroke="#1E293B"
            strokeWidth={strokeWidth}
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeLinecap="round"
          />
          {/* Active Colored Arc */}
          <circle
            cx="80"
            cy="80"
            r={radius}
            fill="transparent"
            stroke={currentTheme.stroke}
            strokeWidth={strokeWidth}
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center Text */}
        <div className="absolute flex flex-col items-center justify-center text-center">
          <span className="text-4xl font-extrabold text-white tracking-tight">{computedRange.min === computedRange.max ? score : computedRange.display}</span>
          <span className="text-xs uppercase tracking-widest text-slate-400 font-semibold">out of 100</span>
          <span className="text-[11px] font-mono text-sky-400 font-semibold mt-0.5">
            Range: {computedRange.display}
          </span>
        </div>
      </div>

      {/* Risk Band Badge */}
      <div
        className={`w-full py-2.5 px-4 rounded-lg border flex items-center justify-between shadow-sm ${currentTheme.bg} ${currentTheme.border}`}
      >
        <div className="flex items-center gap-2">
          {currentTheme.icon}
          <span className="text-xs font-semibold text-slate-300">Overall Risk Level:</span>
        </div>
        <span className={`text-sm font-black uppercase tracking-wider ${currentTheme.text}`}>
          {riskLevel}
        </span>
      </div>

      {/* Range explanation & Score Bands Legend */}
      <div className="w-full mt-3 pt-3 border-t border-slate-800/80">
        <div className="flex items-center gap-1.5 text-[11px] text-slate-400 mb-2 px-1">
          <Info className="w-3.5 h-3.5 text-slate-500 shrink-0" />
          <span>Score interval reflects uncertainty bounds from statistical inferences.</span>
        </div>

        <div className="grid grid-cols-4 gap-1.5 text-[10px] text-center font-bold">
          <div className={`p-1.5 rounded transition-all ${riskLevel === 'Critical' ? 'bg-rose-950/80 text-rose-300 border border-rose-700 shadow-sm' : 'text-slate-500 bg-slate-800/40'}`}>
            0-39 Crit
          </div>
          <div className={`p-1.5 rounded transition-all ${riskLevel === 'High' ? 'bg-orange-950/80 text-orange-300 border border-orange-700 shadow-sm' : 'text-slate-500 bg-slate-800/40'}`}>
            40-59 High
          </div>
          <div className={`p-1.5 rounded transition-all ${riskLevel === 'Medium' ? 'bg-amber-950/80 text-amber-300 border border-amber-700 shadow-sm' : 'text-slate-500 bg-slate-800/40'}`}>
            60-79 Med
          </div>
          <div className={`p-1.5 rounded transition-all ${riskLevel === 'Low' ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-700 shadow-sm' : 'text-slate-500 bg-slate-800/40'}`}>
            80-100 Low
          </div>
        </div>
      </div>
    </div>
  );
};
