import React, { useState, useRef } from 'react';
import { UploadCloud, FileSpreadsheet, Play, CheckCircle2, AlertCircle } from 'lucide-react';
import type { SamplePcap } from '../types/ipsec';

interface UploadPanelProps {
  samples: SamplePcap[];
  onAnalyze: (file: File | null, sampleId?: string) => Promise<void>;
  isLoading: boolean;
  uploadProgress: number;
}

export const UploadPanel: React.FC<UploadPanelProps> = ({
  samples,
  onAnalyze,
  isLoading,
  uploadProgress,
}) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [selectedSampleId, setSelectedSampleId] = useState<string>('');
  const [isDragOver, setIsDragOver] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = () => {
    setIsDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    setErrorMsg(null);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    setErrorMsg(null);
    if (e.target.files && e.target.files.length > 0) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const validateAndSetFile = (file: File) => {
    const validExts = ['.pcap', '.pcapng', '.cap'];
    const hasValidExt = validExts.some(ext => file.name.toLowerCase().endsWith(ext));
    if (!hasValidExt) {
      setErrorMsg('Please upload a valid .pcap or .pcapng file');
      return;
    }
    if (file.size > 50 * 1024 * 1024) {
      setErrorMsg('File exceeds 50MB upload limit');
      return;
    }
    setSelectedFile(file);
    setSelectedSampleId('');
  };

  const handleSampleSelect = (sampleId: string) => {
    setSelectedSampleId(sampleId);
    setSelectedFile(null);
    setErrorMsg(null);
  };

  const handleRunAnalysis = () => {
    if (selectedFile) {
      onAnalyze(selectedFile);
    } else if (selectedSampleId) {
      onAnalyze(null, selectedSampleId);
    } else {
      setErrorMsg('Please upload a PCAP or select a lab sample');
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl mb-8">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <UploadCloud className="w-6 h-6 text-sky-400" />
            PCAP Ingestion & Telemetry Analyzer
          </h2>
          <p className="text-sm text-slate-400">
            Upload raw capture file or test with pre-recorded IPsec testbed scenarios
          </p>
        </div>
        <span className="text-xs font-semibold px-2.5 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700">
          Max Limit: 50MB
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Drag and drop area */}
        <div className="lg:col-span-7 flex flex-col justify-between">
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-lg p-6 flex flex-col items-center justify-center cursor-pointer transition-all ${
              isDragOver
                ? 'border-sky-400 bg-sky-950/30'
                : selectedFile
                ? 'border-emerald-500/60 bg-emerald-950/10'
                : 'border-slate-700 hover:border-slate-500 bg-slate-800/40'
            }`}
          >
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileInput}
              accept=".pcap,.pcapng,.cap"
              className="hidden"
            />
            {selectedFile ? (
              <div className="text-center">
                <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-2" />
                <p className="text-sm font-semibold text-white truncate max-w-xs">{selectedFile.name}</p>
                <p className="text-xs text-slate-400 mt-1">{(selectedFile.size / 1024 / 1024).toFixed(2)} MB</p>
                <span className="text-xs text-emerald-400 font-medium underline mt-2 inline-block">Change file</span>
              </div>
            ) : (
              <div className="text-center">
                <UploadCloud className="w-10 h-10 text-slate-400 mx-auto mb-2" />
                <p className="text-sm font-medium text-slate-200">
                  Drag and drop your <span className="text-sky-400 font-semibold">.pcap</span> file here
                </p>
                <p className="text-xs text-slate-500 mt-1">or click to browse local filesystem</p>
              </div>
            )}
          </div>

          {errorMsg && (
            <div className="mt-3 flex items-center gap-2 text-xs text-rose-400 bg-rose-950/40 p-2.5 rounded border border-rose-900/50">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Progress bar */}
          {isLoading && (
            <div className="mt-4">
              <div className="flex justify-between text-xs text-slate-400 mb-1">
                <span>Processing & Dissecting Telemetry...</span>
                <span>{uploadProgress}%</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                <div
                  className="bg-sky-400 h-2 transition-all duration-200 rounded-full"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            </div>
          )}

          {/* Analyze button */}
          <button
            onClick={handleRunAnalysis}
            disabled={isLoading || (!selectedFile && !selectedSampleId)}
            className={`mt-4 w-full py-2.5 px-4 rounded-lg font-semibold flex items-center justify-center gap-2 transition-all shadow-lg ${
              isLoading || (!selectedFile && !selectedSampleId)
                ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                : 'bg-sky-500 hover:bg-sky-400 text-slate-950 shadow-sky-500/20 active:scale-[0.99]'
            }`}
          >
            {isLoading ? (
              <>
                <div className="w-4 h-4 border-2 border-slate-900 border-t-transparent rounded-full animate-spin" />
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>Analyze PCAP Telemetry</span>
              </>
            )}
          </button>
        </div>

        {/* Right: Sample lab pcaps for demo */}
        <div className={`lg:col-span-5 ${samples.length === 0 ? 'hidden' : ''} border-t lg:border-t-0 lg:border-l border-slate-800 pt-4 lg:pt-0 lg:pl-6`}>
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-1.5">
            <FileSpreadsheet className="w-4 h-4 text-emerald-400" />
            Lab scenarios (stored captures)
          </p>
          <div className="space-y-2">
            {samples.map((sample) => {
              const isSelected = selectedSampleId === sample.id;
              return (
                <div
                  key={sample.id}
                  onClick={() => handleSampleSelect(sample.id)}
                  className={`p-3 rounded-lg border text-left cursor-pointer transition-all ${
                    isSelected
                      ? 'border-sky-400 bg-sky-950/40 shadow-sm'
                      : 'border-slate-800 hover:border-slate-700 bg-slate-800/30'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white truncate max-w-[200px]">
                      {sample.name}
                    </span>
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">{sample.scenario}</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1 line-clamp-1">
                    {sample.description}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
