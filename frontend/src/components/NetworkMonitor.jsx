import React from 'react';
import { Network, AlertCircle, ShieldAlert, ArrowUpRight, CheckCircle2 } from 'lucide-react';

export default function NetworkMonitor({ netTelemetry }) {
  const outboundCount = netTelemetry.outbound_conn_count ?? 0;
  const suspiciousFlag = netTelemetry.suspicious_port_flag ?? 0;
  const exfilRate = netTelemetry.data_exfil_kb_sec ?? 0.0;
  const connections = netTelemetry.connections || [];

  return (
    <div className="space-y-6">
      {/* Network Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass-panel p-4 border border-slate-800">
          <p className="text-xs text-slate-400 font-mono">ACTIVE OUTBOUND SOCKETS</p>
          <p className="text-3xl font-extrabold text-cyan-400 font-mono mt-2">{outboundCount}</p>
          <p className="text-xs text-slate-400 mt-2 font-mono">Monitored TCP/UDP connections</p>
        </div>

        <div className="glass-panel p-4 border border-slate-800">
          <p className="text-xs text-slate-400 font-mono">C2 THREAT PORT FLAG</p>
          <div className="flex items-center space-x-2 mt-2">
            <span className={`text-2xl font-bold font-mono ${suspiciousFlag ? 'text-rose-400' : 'text-emerald-400'}`}>
              {suspiciousFlag ? 'TRIGGERED' : 'CLEAN'}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-2 font-mono">Threat ports: 4444, 1337, 31337, 8888</p>
        </div>

        <div className="glass-panel p-4 border border-slate-800">
          <p className="text-xs text-slate-400 font-mono">OUTBOUND THROUGHPUT RATE</p>
          <p className="text-3xl font-extrabold text-purple-400 font-mono mt-2">
            {exfilRate > 1024 ? `${(exfilRate / 1024).toFixed(2)} MB/s` : `${exfilRate} KB/s`}
          </p>
          <p className="text-xs text-slate-400 mt-2 font-mono">Exfiltration threshold: &ge; 1.0 MB/s</p>
        </div>
      </div>

      {/* Network Matrix Table */}
      <div className="glass-panel p-6 border border-slate-800 space-y-4">
        <h3 className="text-sm font-semibold text-slate-200 font-mono uppercase tracking-wider flex items-center space-x-2">
          <Network className="w-5 h-5 text-cyan-400" />
          <span>Active Network Sockets & C2 Connection Matrix</span>
        </h3>

        <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950/60">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/90 text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Local Address</th>
                <th className="py-3 px-4">Remote Destination</th>
                <th className="py-3 px-4">Protocol</th>
                <th className="py-3 px-4">PID</th>
                <th className="py-3 px-4">Threat Port Status</th>
                <th className="py-3 px-4 text-right">State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {connections.length === 0 ? (
                <tr>
                  <td colSpan="6" className="py-6 text-center text-slate-500">No active network socket connections found.</td>
                </tr>
              ) : (
                connections.map((conn, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/40">
                    <td className="py-2.5 px-4 text-slate-300">{conn.laddr || '0.0.0.0:*'}</td>
                    <td className="py-2.5 px-4 font-semibold text-cyan-300 flex items-center space-x-1">
                      <span>{conn.raddr || 'N/A'}</span>
                      {conn.raddr && <ArrowUpRight className="w-3 h-3 text-slate-500" />}
                    </td>
                    <td className="py-2.5 px-4 text-slate-400">{conn.type} / {conn.family}</td>
                    <td className="py-2.5 px-4 font-bold text-slate-200">{conn.pid}</td>
                    <td className="py-2.5 px-4">
                      {conn.is_suspicious ? (
                        <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold flex items-center space-x-1 w-max">
                          <ShieldAlert className="w-3 h-3" />
                          <span>C2 THREAT PORT</span>
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 inline-block">
                          CLEAN PORT
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-4 text-right font-semibold text-slate-300">
                      {conn.status}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
