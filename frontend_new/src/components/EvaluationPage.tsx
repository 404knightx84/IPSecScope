import React, { useEffect, useState } from 'react';
import { Award, RefreshCw } from 'lucide-react';
import { fetchEval } from '../api';
import type { EvalRow } from '../types/ipsec';

export const EvaluationPage: React.FC = () => {
  const [rows, setRows] = useState<EvalRow[] | null>(null);
  const [generated, setGenerated] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetchEval();
      setRows(r.rows);
      setGenerated(r.generated);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Could not load results');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const badge = (p: boolean | null) =>
    p === null
      ? <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-slate-800 text-slate-300 border border-slate-600">n/a</span>
      : p
      ? <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">yes</span>
      : <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-950 text-rose-300 border border-rose-800">NO</span>;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black text-white flex items-center gap-2.5">
            <Award className="w-7 h-7 text-sky-400" />
            Evaluation
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Every row is read from the output of <span className="font-mono">make eval</span> on the backend. Nothing here is typed by hand, and failures and unavailable checks are shown.
          </p>
          {generated && (
            <p className="text-xs text-slate-500 mt-1 font-mono">
              Results file last written {new Date(generated * 1000).toLocaleString()}
            </p>
          )}
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-bold"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Reload results
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-200 text-xs font-semibold">
          {error}. Run <span className="font-mono">make eval</span> in the project folder, then reload.
        </div>
      )}

      {rows && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-xl overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Check</th>
                <th className="py-3 px-4">Goal</th>
                <th className="py-3 px-4">Measured</th>
                <th className="py-3 px-4">Pass</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {rows.map((r, i) => (
                <tr key={i} className="align-top">
                  <td className="py-3 px-4 font-semibold text-slate-200">{r.check}</td>
                  <td className="py-3 px-4 text-slate-400">{r.goal}</td>
                  <td className="py-3 px-4 font-mono text-slate-300">{r.measured}</td>
                  <td className="py-3 px-4">{badge(r.pass)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
