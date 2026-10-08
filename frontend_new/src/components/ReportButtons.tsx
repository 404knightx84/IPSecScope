import React, { useState } from 'react';
import { Download, FileText, Code2, FileCode, Check } from 'lucide-react';
import type { AnalysisResponse } from '../types/ipsec';
import { downloadReport } from '../api';

interface ReportButtonsProps {
  analysisData?: AnalysisResponse | null;
}

export const ReportButtons: React.FC<ReportButtonsProps> = ({ analysisData }) => {
  const [downloadingType, setDownloadingType] = useState<string | null>(null);
  const [copiedJson, setCopiedJson] = useState<boolean>(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const handleDownload = async (type: 'executive' | 'technical') => {
    if (!analysisData) {
      setDownloadError('Report data is not available. Run an analysis before exporting a report.');
      return;
    }

    setDownloadError(null);
    setDownloadingType(type);
    try {
      await downloadReport(analysisData, type);
    } catch (error: unknown) {
      setDownloadError(error instanceof Error ? `Report failed: ${error.message}` : 'PDF export failed.');
    } finally {
      setTimeout(() => setDownloadingType(null), 800);
    }
  };

  const handleExportJson = () => {
    if (!analysisData) return;
    const jsonStr = JSON.stringify(analysisData, (k, v) => (k === 'file' ? undefined : v), 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ipsecscope-telemetry-${analysisData.id.replace(/\.pcap$/, '')}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl mb-8 flex flex-col lg:flex-row items-center justify-between gap-4">
      <div>
        <h3 className="text-lg font-bold text-white flex items-center gap-2">
          <Download className="w-5 h-5 text-sky-400" />
          Export Cryptographic Audit Reports & Telemetry
        </h3>
        <p className="text-xs text-slate-400 mt-1">
          Download formatted audit deliverables for CISO leadership or engineering teams
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2.5 w-full lg:w-auto">
        {/* Executive Summary Button */}
        <button
          onClick={() => handleDownload('executive')}
          disabled={downloadingType === 'executive'}
          className="flex-1 sm:flex-initial flex items-center justify-center gap-2 px-3.5 py-2.5 rounded-lg bg-sky-500/10 hover:bg-sky-500/20 text-sky-300 border border-sky-500/30 text-xs font-bold transition-all shadow-sm active:scale-95"
        >
          <FileText className="w-4 h-4 text-sky-400" />
          <span>Executive PDF</span>
        </button>

        {/* Technical Report Button */}
        <button
          onClick={() => handleDownload('technical')}
          disabled={downloadingType === 'technical'}
          className="flex-1 sm:flex-initial flex items-center justify-center gap-2 px-3.5 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-bold transition-all shadow-sm active:scale-95"
        >
          <Code2 className="w-4 h-4 text-emerald-400" />
          <span>Technical PDF</span>
        </button>

        {/* JSON Export Button */}
        <button
          onClick={handleExportJson}
          className="flex-1 sm:flex-initial flex items-center justify-center gap-1.5 px-3 py-2.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold transition-all shadow-sm active:scale-95"
        >
          {copiedJson ? (
            <>
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              <span>Downloaded!</span>
            </>
          ) : (
            <>
              <FileCode className="w-3.5 h-3.5 text-purple-400" />
              <span>JSON Export</span>
            </>
          )}
        </button>
        {downloadError && (
          <p className="basis-full text-sm text-rose-400" role="alert">{downloadError}</p>
        )}
      </div>
    </div>
  );
};
