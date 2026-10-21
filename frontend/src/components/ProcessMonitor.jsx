import React, { useState } from 'react';
import { Cpu, Search, AlertTriangle, Trash2, CheckCircle2 } from 'lucide-react';

export default function ProcessMonitor({ procTelemetry, onTerminateProcess }) {
  const [search, setSearch] = useState('');
  const processes = procTelemetry.processes || [];

  const filtered = processes.filter(p =>
    p.name.toLowerCase().includes(search.toLowerCase()) ||
    p.pid.toString().includes(search) ||
    p.cmdline.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="glass-panel p-6 border border-slate-800 space-y-4">
      {/* Table Header */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-200 font-mono uppercase tracking-wider flex items-center space-x-2">
            <Cpu className="w-5 h-5 text-cyan-400" />
            <span>Process Monitor & Execution Inspector</span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Total active processes: <strong className="text-slate-200">{procTelemetry.process_count ?? 0}</strong> • Spawn velocity: <strong className="text-cyan-400">{procTelemetry.spawn_rate ?? 0}/s</strong>
          </p>
        </div>

        {/* Search Input */}
        <div className="relative w-full sm:w-64">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search PID, name, cmd..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Process Table */}
      <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950/60">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-slate-900/90 text-slate-400 uppercase tracking-wider border-b border-slate-800">
            <tr>
              <th className="py-3 px-4">PID / PPID</th>
              <th className="py-3 px-4">Process Name</th>
              <th className="py-3 px-4">CPU %</th>
              <th className="py-3 px-4">RAM %</th>
              <th className="py-3 px-4">Execution Path / Flag</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-slate-300">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan="6" className="py-6 text-center text-slate-500">No matching processes found.</td>
              </tr>
            ) : (
              filtered.map((proc) => (
                <tr key={proc.pid} className="hover:bg-slate-900/40 transition-colors">
                  <td className="py-2.5 px-4 font-bold text-slate-200">
                    {proc.pid} <span className="text-slate-500 font-normal">({proc.ppid})</span>
                  </td>
                  <td className="py-2.5 px-4">
                    <span className="font-semibold text-cyan-300">{proc.name}</span>
                    <span className="block text-[10px] text-slate-500 truncate max-w-xs">{proc.cmdline}</span>
                  </td>
                  <td className="py-2.5 px-4">
                    <span className={proc.cpu_percent > 50 ? "text-rose-400 font-bold" : "text-slate-300"}>
                      {proc.cpu_percent}%
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-slate-300">
                    {proc.memory_percent}%
                  </td>
                  <td className="py-2.5 px-4">
                    {proc.is_tmp ? (
                      <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold">
                        <AlertTriangle className="w-3 h-3" />
                        <span>TMP / SUSPICIOUS EXEC</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        <CheckCircle2 className="w-3 h-3" />
                        <span>NORMAL BINARY</span>
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-4 text-right">
                    <button
                      onClick={() => onTerminateProcess && onTerminateProcess(proc.pid, proc.name)}
                      className="px-2.5 py-1 rounded bg-rose-500/10 hover:bg-rose-500/30 text-rose-400 border border-rose-500/30 transition-colors font-mono text-[11px] flex items-center space-x-1 ml-auto"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span>KILL</span>
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
