import React, { useState } from 'react';
import { AlertCircle, CheckCircle2, HelpCircle, Wrench } from 'lucide-react';
import type { Finding } from '../types/ipsec';

interface FindingsTableProps {
  findings: Finding[];
}

export const FindingsTable: React.FC<FindingsTableProps> = ({ findings }) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');

  const filtered = filterSeverity === 'ALL'
    ? findings
    : findings.filter(f => f.severity.toUpperCase() === filterSeverity);

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'High':
        return 'bg-orange-500/20 text-orange-300 border-orange-500/40';
      case 'Medium':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'Informational':
        return 'bg-sky-500/20 text-sky-300 border-sky-500/40';
      default:
        return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
    }
  };

  const getStatusBadge = (status: string) => {
    if (status === 'Observed') {
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
          <CheckCircle2 className="w-3 h-3 text-emerald-400" />
          Observed
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
        <HelpCircle className="w-3 h-3 text-amber-400" />
        {status}
      </span>
    );
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl mb-8">
      {/* Title & Filter Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <AlertCircle className="w-6 h-6 text-sky-400" />
            Vulnerability Findings & Policy Compliance
          </h2>
          <p className="text-sm text-slate-400">
            Cryptographic misconfigurations, protocol weaknesses, and remediation directives
          </p>
        </div>

        {/* Severity Filter Tabs */}
        <div className="flex items-center gap-1 bg-slate-800 p-1 rounded-lg border border-slate-700 text-xs">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
            <button
              key={lvl}
              onClick={() => setFilterSeverity(lvl)}
              className={`px-2.5 py-1 rounded font-semibold transition-all ${
                filterSeverity === lvl
                  ? 'bg-sky-500 text-slate-950 shadow'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {lvl}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400">
              <th className="py-3 px-4">Finding & Vulnerability</th>
              <th className="py-3 px-3">Severity</th>
              <th className="py-3 px-3">Detection Status</th>
              <th className="py-3 px-3">Confidence</th>
              <th className="py-3 px-4">Packet Evidence</th>
              <th className="py-3 px-4">Recommended Fix</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-xs">
            {filtered.map((item) => (
              <tr key={item.id} className="hover:bg-slate-800/30 transition-colors">
                {/* Finding */}
                <td className="py-4 px-4 font-semibold text-white max-w-xs">
                  <div className="flex items-start gap-2">
                    <span className="text-[10px] font-mono text-slate-500 shrink-0 mt-0.5">{item.id}</span>
                    <span>{item.finding}</span>
                  </div>
                </td>

                {/* Severity */}
                <td className="py-4 px-3">
                  <span className={`inline-block px-2 py-0.5 rounded text-[11px] font-bold border ${getSeverityBadge(item.severity)}`}>
                    {item.severity}
                  </span>
                </td>

                {/* Status */}
                <td className="py-4 px-3 whitespace-nowrap">
                  {getStatusBadge(item.status)}
                </td>

                {/* Confidence */}
                <td className="py-4 px-3 font-mono font-medium text-slate-300">
                  {item.confidence}
                </td>

                {/* Evidence */}
                <td className="py-4 px-4 text-slate-300 font-mono text-[11px] max-w-xs">
                  <div className="bg-slate-800/60 px-2 py-1.5 rounded border border-slate-750 break-words">
                    {item.evidence}
                  </div>
                </td>

                {/* Recommended Fix */}
                <td className="py-4 px-4 text-slate-300 max-w-sm">
                  <div className="flex items-start gap-1.5 text-[11px] text-slate-200">
                    <Wrench className="w-3.5 h-3.5 text-sky-400 shrink-0 mt-0.5" />
                    <span>{item.recommended_fix}</span>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
