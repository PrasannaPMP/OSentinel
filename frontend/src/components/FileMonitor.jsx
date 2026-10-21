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
        <div className="glass-panel-rose p-4 border border-rose-500/50 flex items-center space-x-3 text-rose-200 animate-pulse">
          <AlertTriangle className="w-6 h-6 text-rose-400 flex-shrink-0" />
          <div>
            <h4 className="font-bold font-mono text-sm uppercase">Ransomware Entropy Anomaly Alert!</h4>
            <p className="text-xs text-rose-300 font-mono">
              Shannon Entropy $H(X)$ reached high threshold ({avgEntropy} / 8.0) with rapid write rate ({modRate} files/sec). High likelihood of cryptographic ransomware payload.
            </p>
          </div>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass-panel p-4 border border-slate-800">
          <p className="text-xs text-slate-400 font-mono">AVERAGE SHANNON ENTROPY H(X)</p>
          <div className="flex items-baseline space-x-2 mt-2">
            <span className={`text-3xl font-extrabold font-mono ${avgEntropy >= 7.2 ? 'text-rose-400' : 'text-purple-400'}`}>
              {avgEntropy}
            </span>
            <span className="text-xs text-slate-500 font-mono">/ 8.0 bits/byte</span>
          </div>
          <p className="text-xs text-slate-400 mt-2 font-mono">
            Encrypted content threshold: &ge; 7.2 bits/byte
          </p>
        </div>

        <div className="glass-panel p-4 border border-slate-800">
          <p className="text-xs text-slate-400 font-mono">FILE MODIFICATION RATE</p>
          <div className="flex items-baseline space-x-2 mt-2">
            <span className="text-3xl font-extrabold font-mono text-cyan-400">{modRate}</span>
            <span className="text-xs text-slate-500 font-mono">writes / sec</span>
          </div>
          <p className="text-xs text-slate-400 mt-2 font-mono">
            High write velocity threshold: &ge; 15 writes/sec
          </p>
        </div>

        <div className="glass-panel p-4 border border-slate-800">
          <p className="text-xs text-slate-400 font-mono">DELETION BURST RATE</p>
          <div className="flex items-baseline space-x-2 mt-2">
            <span className="text-3xl font-extrabold font-mono text-amber-400">{delRate}</span>
            <span className="text-xs text-slate-500 font-mono">deletions / sec</span>
          </div>
          <p className="text-xs text-slate-400 mt-2 font-mono">
            Mass deletion threshold: &ge; 10 deletes/sec
          </p>
        </div>
      </div>

      {/* File Activity Log Table */}
      <div className="glass-panel p-6 border border-slate-800 space-y-4">
        <h3 className="text-sm font-semibold text-slate-200 font-mono uppercase tracking-wider flex items-center space-x-2">
          <HardDrive className="w-5 h-5 text-purple-400" />
          <span>Active File System Telemetry & Entropy Logs</span>
        </h3>

        <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950/60">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/90 text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">File Path</th>
                <th className="py-3 px-4">Calculated Entropy H(X)</th>
                <th className="py-3 px-4">Encryption Risk</th>
                <th className="py-3 px-4 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {sampleFiles.map((file, idx) => (
                <tr key={idx} className="hover:bg-slate-900/40">
                  <td className="py-3 px-4 flex items-center space-x-2 text-slate-200">
                    <FileCode className="w-4 h-4 text-slate-500" />
                    <span>{file.path}</span>
                  </td>
                  <td className="py-3 px-4 font-bold text-purple-300">
                    {file.entropy} bits
                  </td>
                  <td className="py-3 px-4">
                    {file.entropy >= 7.2 ? (
                      <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold">
                        HIGH ENTROPY (ENCRYPTED)
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        NORMAL STRUCTURE
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-right">
                    {file.status === 'ENCRYPTED' ? (
                      <span className="inline-flex items-center space-x-1 text-rose-400 font-bold">
                        <Lock className="w-3.5 h-3.5" />
                        <span>QUARANTINED</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center space-x-1 text-emerald-400">
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>VERIFIED</span>
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
