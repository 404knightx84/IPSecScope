import React, { useState } from 'react';
import { TrendingUp, Info } from 'lucide-react';
import type { ConfidencePoint } from '../types/ipsec';

interface ConfidenceChartProps {
  data?: ConfidencePoint[];
}

export const ConfidenceChart: React.FC<ConfidenceChartProps> = ({ data }) => {
  const [activeMetric, setActiveMetric] = useState<'all' | 'cipher' | 'mode' | 'pfs'>('all');

  // Default curve if not passed
  const points: ConfidencePoint[] = data && data.length > 0 ? data : [
    { packetCount: 10, timeSec: 0.5, cipherConfidence: 0.45, modeConfidence: 0.55, pfsConfidence: 0.10 },
    { packetCount: 50, timeSec: 2.0, cipherConfidence: 0.65, modeConfidence: 0.72, pfsConfidence: 0.20 },
    { packetCount: 150, timeSec: 6.0, cipherConfidence: 0.82, modeConfidence: 0.85, pfsConfidence: 0.40 },
    { packetCount: 500, timeSec: 18.0, cipherConfidence: 0.91, modeConfidence: 0.92, pfsConfidence: 0.65 },
    { packetCount: 1200, timeSec: 42.0, cipherConfidence: 0.95, modeConfidence: 0.95, pfsConfidence: 0.88 },
    { packetCount: 2500, timeSec: 90.0, cipherConfidence: 0.97, modeConfidence: 0.96, pfsConfidence: 0.94 }
  ];

  // SVG dimensions
  const svgWidth = 600;
  const svgHeight = 200;
  const padding = { top: 20, right: 30, bottom: 35, left: 45 };
  const graphWidth = svgWidth - padding.left - padding.right;
  const graphHeight = svgHeight - padding.top - padding.bottom;

  // Max X is the highest packet count
  const maxX = Math.max(...points.map(p => p.packetCount), 100);

  // Scalers
  const getX = (packetCount: number) => {
    // Log scale or square root scale to show early growth clearly
    const norm = Math.log10(packetCount) / Math.log10(maxX);
    return padding.left + Math.max(0, Math.min(1, norm)) * graphWidth;
  };

  const getY = (val: number) => {
    return padding.top + (1 - val) * graphHeight;
  };

  const createPath = (key: 'cipherConfidence' | 'modeConfidence' | 'pfsConfidence') => {
    return points
      .map((p, idx) => {
        const x = getX(p.packetCount);
        const y = getY(p[key]);
        return `${idx === 0 ? 'M' : 'L'} ${x} ${y}`;
      })
      .join(' ');
  };

  const createAreaPath = (key: 'cipherConfidence' | 'modeConfidence' | 'pfsConfidence') => {
    const linePath = points
      .map((p, idx) => {
        const x = getX(p.packetCount);
        const y = getY(p[key]);
        return `${idx === 0 ? 'M' : 'L'} ${x} ${y}`;
      })
      .join(' ');
    const lastX = getX(points[points.length - 1].packetCount);
    const firstX = getX(points[0].packetCount);
    const bottomY = getY(0);
    return `${linePath} L ${lastX} ${bottomY} L ${firstX} ${bottomY} Z`;
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
            <TrendingUp className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              Confidence Over Time
            </h3>
            <p className="text-xs text-slate-400">Statistical convergence as packet volume accumulates</p>
          </div>
        </div>

        {/* Metric toggles */}
        <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs font-semibold">
          <button
            onClick={() => setActiveMetric('all')}
            className={`px-2.5 py-1 rounded transition-colors ${
              activeMetric === 'all' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All Metrics
          </button>
          <button
            onClick={() => setActiveMetric('cipher')}
            className={`px-2.5 py-1 rounded transition-colors flex items-center gap-1.5 ${
              activeMetric === 'cipher' ? 'bg-sky-950 text-sky-300 border border-sky-800' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-sky-400" />
            Cipher
          </button>
          <button
            onClick={() => setActiveMetric('mode')}
            className={`px-2.5 py-1 rounded transition-colors flex items-center gap-1.5 ${
              activeMetric === 'mode' ? 'bg-indigo-950 text-indigo-300 border border-indigo-800' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-indigo-400" />
            Mode
          </button>
          <button
            onClick={() => setActiveMetric('pfs')}
            className={`px-2.5 py-1 rounded transition-colors flex items-center gap-1.5 ${
              activeMetric === 'pfs' ? 'bg-amber-950 text-amber-300 border border-amber-800' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-amber-400" />
            PFS
          </button>
        </div>
      </div>

      {/* SVG Chart */}
      <div className="w-full overflow-x-auto">
        <svg viewBox={`0 0 ${svgWidth} ${svgHeight}`} className="w-full h-48 select-none">
          <defs>
            <linearGradient id="cipherGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.0" />
            </linearGradient>
            <linearGradient id="modeGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#818cf8" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#818cf8" stopOpacity="0.0" />
            </linearGradient>
            <linearGradient id="pfsGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#fbbf24" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#fbbf24" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          {[0.25, 0.5, 0.75, 1.0].map((v) => (
            <g key={v}>
              <line
                x1={padding.left}
                y1={getY(v)}
                x2={svgWidth - padding.right}
                y2={getY(v)}
                stroke="#1e293b"
                strokeDasharray="4 4"
              />
              <text
                x={padding.left - 8}
                y={getY(v) + 3}
                fill="#64748b"
                fontSize="10"
                textAnchor="end"
                fontFamily="monospace"
              >
                {Math.round(v * 100)}%
              </text>
            </g>
          ))}

          {/* X axis ticks */}
          {points.map((p, i) => (
            <g key={i}>
              <line
                x1={getX(p.packetCount)}
                y1={svgHeight - padding.bottom}
                x2={getX(p.packetCount)}
                y2={svgHeight - padding.bottom + 4}
                stroke="#334155"
              />
              <text
                x={getX(p.packetCount)}
                y={svgHeight - padding.bottom + 16}
                fill="#64748b"
                fontSize="9"
                textAnchor="middle"
                fontFamily="monospace"
              >
                {p.packetCount >= 1000 ? `${(p.packetCount / 1000).toFixed(1)}k` : p.packetCount}
              </text>
            </g>
          ))}

          <text
            x={svgWidth / 2}
            y={svgHeight - 4}
            fill="#64748b"
            fontSize="10"
            textAnchor="middle"
            fontFamily="sans-serif"
          >
            Encapsulated Packets Analyzed (Logarithmic Timeline)
          </text>

          {/* Areas and Lines */}
          {(activeMetric === 'all' || activeMetric === 'cipher') && (
            <>
              <path d={createAreaPath('cipherConfidence')} fill="url(#cipherGrad)" />
              <path d={createPath('cipherConfidence')} fill="none" stroke="#38bdf8" strokeWidth="2.5" />
              {points.map((p, i) => (
                <circle
                  key={`c-${i}`}
                  cx={getX(p.packetCount)}
                  cy={getY(p.cipherConfidence)}
                  r="3.5"
                  fill="#0284c7"
                  stroke="#38bdf8"
                  strokeWidth="1.5"
                />
              ))}
            </>
          )}

          {(activeMetric === 'all' || activeMetric === 'mode') && (
            <>
              <path d={createAreaPath('modeConfidence')} fill="url(#modeGrad)" />
              <path d={createPath('modeConfidence')} fill="none" stroke="#818cf8" strokeWidth="2.5" />
              {points.map((p, i) => (
                <circle
                  key={`m-${i}`}
                  cx={getX(p.packetCount)}
                  cy={getY(p.modeConfidence)}
                  r="3.5"
                  fill="#4f46e5"
                  stroke="#818cf8"
                  strokeWidth="1.5"
                />
              ))}
            </>
          )}

          {(activeMetric === 'all' || activeMetric === 'pfs') && (
            <>
              <path d={createAreaPath('pfsConfidence')} fill="url(#pfsGrad)" />
              <path d={createPath('pfsConfidence')} fill="none" stroke="#fbbf24" strokeWidth="2.5" />
              {points.map((p, i) => (
                <circle
                  key={`p-${i}`}
                  cx={getX(p.packetCount)}
                  cy={getY(p.pfsConfidence)}
                  r="3.5"
                  fill="#d97706"
                  stroke="#fbbf24"
                  strokeWidth="1.5"
                />
              ))}
            </>
          )}
        </svg>
      </div>

      <div className="flex items-center justify-between pt-3 border-t border-slate-800 text-[11px] text-slate-400">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-400" />
            <span className="text-slate-300 font-medium">Cipher Family (Length Residue)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-indigo-400" />
            <span className="text-slate-300 font-medium">Mode (Tunnel vs Transport)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-400" />
            <span className="text-slate-300 font-medium">PFS (Rekey KE Detection)</span>
          </div>
        </div>

        <div className="hidden sm:flex items-center gap-1 text-slate-500">
          <Info className="w-3.5 h-3.5" />
          <span>Cold-start stabilization: ~500 frames</span>
        </div>
      </div>
    </div>
  );
};
