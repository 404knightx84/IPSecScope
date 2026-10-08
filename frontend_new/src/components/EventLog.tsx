import React, { useState } from 'react';
import { Terminal, Search, ShieldCheck } from 'lucide-react';
import type { TimelineEvent } from '../types/ipsec';

interface EventLogProps {
  events?: TimelineEvent[];
}

export const EventLog: React.FC<EventLogProps> = ({ events = [] }) => {
  const [filterType, setFilterType] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const displayEvents: TimelineEvent[] = events.length > 0 ? events : [
    { timestamp: "00:00.035", offset_sec: 0.035, type: "IKE_INIT", message: "IKE_SA_INIT Request", details: "Initiator proposes IKEv2 with DH Group 14/19 (Packet #1)", packet_no: 1 },
    { timestamp: "00:00.075", offset_sec: 0.075, type: "IKE_INIT", message: "IKE_SA_INIT Response Accepted", details: "Responder selects AES-GCM-256 + Group 19 (Packet #2)", packet_no: 2 },
    { timestamp: "00:00.180", offset_sec: 0.18, type: "IKE_AUTH", message: "IKE_AUTH Encrypted Handshake", details: "Authentication payloads protected by derived cryptographic keys (Packet #3)", packet_no: 3 },
    { timestamp: "00:00.410", offset_sec: 0.41, type: "ESP", message: "ESP Encapsulated Session Established", details: "Tunnel SPI 0x7fa281b9 active; minimal padding overhead observed (Packet #10)", packet_no: 10 },
    { timestamp: "00:30.000", offset_sec: 30.0, type: "TRAFFIC", message: "Traffic Classification Window 1", details: "HTTPS Web (74%) and Database RPC (16%) detected", packet_no: 850 },
    { timestamp: "01:00.000", offset_sec: 60.0, type: "REKEY", message: "CREATE_CHILD_SA Rekey Observed", details: "Secondary DH KE exchange completed; PFS active (Packet #1820)", packet_no: 1820 },
    { timestamp: "02:00.000", offset_sec: 120.0, type: "ESP", message: "SPI Transition Complete", details: "New SPI 0x19bb40e2 seamlessly receives traffic", packet_no: 3200 }
  ];

  const filtered = displayEvents.filter((ev) => {
    if (filterType !== 'ALL' && ev.type !== filterType) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        ev.message.toLowerCase().includes(q) ||
        ev.details.toLowerCase().includes(q) ||
        ev.timestamp.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const getBadgeStyle = (type: string) => {
    switch (type) {
      case 'WARN':
        return 'bg-rose-950/80 text-rose-300 border-rose-800';
      case 'REKEY':
        return 'bg-amber-950/80 text-amber-300 border-amber-800';
      case 'IKE_INIT':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-800';
      case 'IKE_AUTH':
        return 'bg-sky-950/80 text-sky-300 border-sky-800';
      case 'TRAFFIC':
        return 'bg-purple-950/80 text-purple-300 border-purple-800';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl flex flex-col h-full">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20 shadow-inner">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              Wire Protocol Event Log
            </h3>
            <p className="text-xs text-slate-400">Chronological telemetry events and state transitions</p>
          </div>
        </div>

        {/* Search & Filter */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-400" />
            <input
              type="text"
              placeholder="Search events..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 w-36 sm:w-44"
            />
          </div>

          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-300 focus:outline-none focus:border-sky-500 font-medium"
          >
            <option value="ALL">All Events</option>
            <option value="IKE_INIT">IKE Init</option>
            <option value="IKE_AUTH">IKE Auth</option>
            <option value="ESP">ESP Data</option>
            <option value="REKEY">Rekey / PFS</option>
            <option value="TRAFFIC">Traffic Profile</option>
            <option value="WARN">Warnings</option>
          </select>
        </div>
      </div>

      {/* Log Feed */}
      <div className="flex-1 bg-slate-950 rounded-lg border border-slate-800/80 p-3 overflow-y-auto max-h-80 space-y-2 font-mono text-xs">
        {filtered.length === 0 ? (
          <div className="text-center py-8 text-slate-500 font-sans">
            No events match your filter criteria.
          </div>
        ) : (
          filtered.map((ev, idx) => (
            <div
              key={idx}
              className="flex flex-col sm:flex-row sm:items-start gap-2 p-2 rounded hover:bg-slate-900/60 border border-transparent hover:border-slate-800/60 transition-colors"
            >
              <div className="flex items-center gap-2 shrink-0">
                <span className="text-[11px] text-slate-500 select-none">
                  {ev.timestamp}
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${getBadgeStyle(ev.type)}`}>
                  {ev.type}
                </span>
              </div>

              <div className="flex-1 min-w-0 font-sans">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-slate-200">
                    {ev.message}
                  </span>
                  {ev.packet_no && (
                    <span className="text-[10px] font-mono text-sky-400/80 px-1.5 py-0.2 rounded bg-sky-950/40 border border-sky-900/50 shrink-0">
                      Pkt #{ev.packet_no}
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">
                  {ev.details}
                </p>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between pt-3 mt-2 border-t border-slate-800 text-[11px] text-slate-500">
        <span>Displaying {filtered.length} of {displayEvents.length} wire events</span>
        <span className="flex items-center gap-1 text-slate-400">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          Deterministic Wire Log
        </span>
      </div>
    </div>
  );
};
