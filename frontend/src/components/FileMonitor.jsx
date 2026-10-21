import React from 'react';
import { HardDrive, AlertTriangle, ShieldCheck, FileCode, Lock } from 'lucide-react';

export default function FileMonitor({ fileTelemetry }) {
  const avgEntropy = fileTelemetry.avg_file_entropy ?? 0.0;
  const modRate = fileTelemetry.file_mod_rate ?? 0.0;
  const delRate = fileTelemetry.file_deletion_rate ?? 0.0;
  const isHighEntropy = fileTelemetry.high_entropy_alert;
  const sampleFiles = fileTelemetry.sample_files || [];

  return (
    <div className="space-y-6">
      {/* Entropy Alert Banner if High */}
      {isHighEntropy && (
        <div className="card-panel p-4 bg-red-50 border-red-300 flex items-center space-x-3 text-red-900">
          <AlertTriangle className="w-6 h-6 text-red-600 flex-shrink-0" />
          <div>
            <h4 className="font-extrabold font-mono text-sm uppercase m-0 text-red-800">
              Ransomware Cryptographic Entropy Alert Triggered!
            </h4>
            <p className="text-xs text-red-700 font-mono m-0 mt-0.5">
              Shannon Entropy reached high threshold ({avgEntropy} / 8.0) with rapid write rate ({modRate} writes/sec). High probability of active cryptographic encryption.
            </p>
          </div>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card-panel p-5">
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider font-mono m-0">SHANNON ENTROPY H(X)</p>
          <div className="flex items-baseline space-x-2 mt-2">
            <span className={`text-3xl font-extrabold font-mono ${avgEntropy >= 7.2 ? 'text-red-600' : 'text-slate-900'}`}>
              {avgEntropy}
            </span>
            <span className="text-xs text-slate-400 font-mono font-medium">/ 8.0 bits/byte</span>
          </div>
          <p className="text-xs text-slate-500 mt-2 font-mono m-0">
            Encrypted content threshold: &ge; 7.2 bits/byte
          </p>
        </div>

        <div className="card-panel p-5">
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider font-mono m-0">FILE MODIFICATION RATE</p>
          <div className="flex items-baseline space-x-2 mt-2">
            <span className="text-3xl font-extrabold font-mono text-slate-900">{modRate}</span>
            <span className="text-xs text-slate-400 font-mono font-medium">writes / sec</span>
          </div>
          <p className="text-xs text-slate-500 mt-2 font-mono m-0">
            Rapid encryption velocity threshold: &ge; 15 writes/sec
          </p>
        </div>

        <div className="card-panel p-5">
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider font-mono m-0">DELETION BURST RATE</p>
          <div className="flex items-baseline space-x-2 mt-2">
            <span className="text-3xl font-extrabold font-mono text-slate-900">{delRate}</span>
            <span className="text-xs text-slate-400 font-mono font-medium">deletions / sec</span>
          </div>
          <p className="text-xs text-slate-500 mt-2 font-mono m-0">
            Mass deletion threshold: &ge; 10 deletes/sec
          </p>
        </div>
      </div>

      {/* Sample Monitored Files Table */}
      <div className="card-panel p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-extrabold text-slate-900 font-mono uppercase tracking-wider flex items-center space-x-2 m-0">
            <HardDrive className="w-5 h-5 text-slate-800" />
            <span>Monitored File System Watchdog & Entropy Inspector</span>
          </h3>
          <span className="badge-clean badge-neutral font-mono">
            {sampleFiles.length} FILES TRACKED
          </span>
        </div>

        <div className="data-table-container">
          <table className="clean-table">
            <thead>
              <tr>
                <th>Monitored File Path</th>
                <th>Entropy Score H(X)</th>
                <th>Entropy Category</th>
                <th style={{ textAlign: 'right' }}>Security Status</th>
              </tr>
            </thead>
            <tbody>
              {sampleFiles.length === 0 ? (
                <tr>
                  <td colSpan="4" style={{ textAlign: 'center', padding: '2rem 1rem', color: '#64748b' }}>
                    No file system write events intercepted in active window.
                  </td>
                </tr>
              ) : (
                sampleFiles.map((file, idx) => (
                  <tr key={idx}>
                    <td className="font-mono text-xs font-semibold text-slate-800">
                      {file.path}
                    </td>
                    <td className="font-mono font-bold text-slate-900">
                      {file.entropy} bits/byte
                    </td>
                    <td>
                      {file.entropy >= 7.2 ? (
                        <span className="badge-clean badge-rose font-mono">ENCRYPTED / HIGH ENTROPY</span>
                      ) : file.entropy >= 5.0 ? (
                        <span className="badge-clean badge-amber font-mono">COMPRESSED / NORMAL</span>
                      ) : (
                        <span className="badge-clean badge-emerald font-mono">PLAINTEXT / LOW</span>
                      )}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <span className={`badge-clean ${file.status === 'SUSPICIOUS' ? 'badge-rose' : 'badge-emerald'}`}>
                        {file.status || 'NORMAL'}
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
