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
    <div className="card-panel p-6 space-y-4">
      {/* Table Header & Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-extrabold text-slate-900 font-mono uppercase tracking-wider flex items-center space-x-2 m-0">
            <Cpu className="w-5 h-5 text-slate-800" />
            <span>Process Monitor & Execution Inspector</span>
          </h3>
          <p className="text-xs text-slate-500 m-0 mt-1 font-medium">
            Active processes: <strong className="text-slate-900">{procTelemetry.process_count ?? 0}</strong> • Spawn rate: <strong className="text-slate-900">{procTelemetry.spawn_rate ?? 0}/s</strong>
          </p>
        </div>

        {/* Search Input */}
        <div style={{ position: 'relative', width: '100%', maxWidth: '280px' }}>
          <Search className="w-4 h-4 text-slate-400" style={{ position: 'absolute', left: '10px', top: '10px' }} />
          <input
            type="text"
            placeholder="Search PID, name, cmd..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              width: '100%',
              paddingLeft: '32px',
              paddingRight: '12px',
              paddingTop: '8px',
              paddingBottom: '8px',
              backgroundColor: '#ffffff',
              border: '1.5px solid #cbd5e1',
              borderRadius: '6px',
              fontSize: '12px',
              fontFamily: 'var(--font-mono)',
              color: '#0f172a',
              outline: 'none',
            }}
          />
        </div>
      </div>

      {/* Process Table */}
      <div className="data-table-container">
        <table className="clean-table">
          <thead>
            <tr>
              <th>PID / PPID</th>
              <th>Process Name</th>
              <th>CPU %</th>
              <th>RAM %</th>
              <th>Execution Path / Status</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', padding: '2rem 1rem', color: '#64748b' }}>
                  No matching processes found.
                </td>
              </tr>
            ) : (
              filtered.slice(0, 50).map((proc) => (
                <tr key={proc.pid}>
                  <td className="font-mono font-bold text-slate-900">
                    {proc.pid} <span className="text-slate-400 font-normal">({proc.ppid})</span>
                  </td>
                  <td>
                    <strong className="text-slate-900 font-bold block">{proc.name}</strong>
                    <span className="text-[11px] font-mono text-slate-500 truncate block" style={{ maxWidth: '260px' }}>
                      {proc.cmdline}
                    </span>
                  </td>
                  <td className="font-mono">
                    <span className={proc.cpu_percent > 50 ? "text-red-700 font-extrabold" : "text-slate-700 font-bold"}>
                      {proc.cpu_percent}%
                    </span>
                  </td>
                  <td className="font-mono text-slate-700 font-bold">
                    {proc.memory_percent}%
                  </td>
                  <td>
                    {proc.is_tmp ? (
                      <span className="badge-clean badge-rose font-mono">
                        <AlertTriangle className="w-3 h-3" />
                        SPAWNED FROM /TMP
                      </span>
                    ) : (
                      <span className="badge-clean badge-neutral font-mono">
                        SYSTEM PATH
                      </span>
                    )}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      onClick={() => onTerminateProcess(proc.pid, proc.name)}
                      className="btn-bold-danger"
                      style={{ padding: '5px 10px', fontSize: '11px' }}
                      title="Terminate Process"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span>TERMINATE</span>
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
