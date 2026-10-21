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
        <div className="card-panel p-5">
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider font-mono m-0">ACTIVE OUTBOUND SOCKETS</p>
          <p className="text-3xl font-extrabold text-slate-900 font-mono mt-2 mb-0">{outboundCount}</p>
          <p className="text-xs text-slate-500 mt-2 font-mono m-0">Live TCP/UDP host sockets</p>
        </div>

        <div className="card-panel p-5">
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider font-mono m-0">C2 THREAT PORT FLAG</p>
          <div className="flex items-center space-x-2 mt-2">
            <span className={`text-2xl font-extrabold font-mono ${suspiciousFlag ? 'text-red-600' : 'text-emerald-700'}`}>
              {suspiciousFlag ? 'THREAT DETECTED' : 'CLEAN'}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-2 font-mono m-0">Signature ports: 4444, 1337, 31337, 8888</p>
        </div>

        <div className="card-panel p-5">
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider font-mono m-0">OUTBOUND THROUGHPUT RATE</p>
          <p className="text-3xl font-extrabold text-slate-900 font-mono mt-2 mb-0">
            {exfilRate > 1024 ? `${(exfilRate / 1024).toFixed(2)} MB/s` : `${exfilRate} KB/s`}
          </p>
          <p className="text-xs text-slate-500 mt-2 font-mono m-0">Exfiltration threshold: &ge; 1.0 MB/s</p>
        </div>
      </div>

      {/* Network Matrix Table */}
      <div className="card-panel p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-extrabold text-slate-900 font-mono uppercase tracking-wider flex items-center space-x-2 m-0">
            <Network className="w-5 h-5 text-slate-800" />
            <span>Active Network Sockets & Connection Matrix</span>
          </h3>
          <span className="badge-clean badge-neutral font-mono">
            {connections.length} ACTIVE CONNECTIONS
          </span>
        </div>

        <div className="data-table-container">
          <table className="clean-table">
            <thead>
              <tr>
                <th>Local Address</th>
                <th>Remote Destination</th>
                <th>Protocol</th>
                <th>PID</th>
                <th>Threat Port Assessment</th>
                <th style={{ textAlign: 'right' }}>Socket State</th>
              </tr>
            </thead>
            <tbody>
              {connections.length === 0 ? (
                <tr>
                  <td colSpan="6" style={{ textAlign: 'center', padding: '2rem 1rem', color: '#64748b' }}>
                    No active remote socket sessions intercepted.
                  </td>
                </tr>
              ) : (
                connections.slice(0, 40).map((conn, idx) => (
                  <tr key={idx}>
                    <td className="font-mono text-xs text-slate-700 font-semibold">{conn.laddr}</td>
                    <td className="font-mono text-xs font-bold text-slate-900">{conn.raddr || 'N/A'}</td>
                    <td className="font-mono text-xs font-bold text-slate-600">{conn.type}</td>
                    <td className="font-mono text-xs font-semibold text-slate-800">{conn.pid || '-'}</td>
                    <td>
                      {conn.is_suspicious ? (
                        <span className="badge-clean badge-rose font-mono">
                          SUSPICIOUS PORT
                        </span>
                      ) : (
                        <span className="badge-clean badge-emerald font-mono">
                          BENIGN PORT
                        </span>
                      )}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <span className="font-mono text-xs font-bold text-slate-700 bg-slate-100 px-2 py-0.5 rounded border border-slate-300">
                        {conn.status}
                      </span>
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
