import React, { useState } from 'react';
import { Zap, ShieldAlert, Lock, Network, Cpu, ArrowUpRight, CheckCircle2 } from 'lucide-react';

export default function AttackSimulator({ onSimulateAttack, activeSim }) {
  const [loadingType, setLoadingType] = useState(null);

  const handleSimulate = async (type) => {
    setLoadingType(type);
    try {
      await onSimulateAttack(type);
    } catch (e) {
      console.error("Simulation error:", e);
    } finally {
      setLoadingType(null);
    }
  };

  const scenarios = [
    {
      id: 'RANSOMWARE',
      title: 'Ransomware Mass Encryption',
      icon: Lock,
      color: 'rose',
      description: 'Simulates rapid file modification velocity (85 writes/sec) with high Shannon Entropy (H=7.85 bits/byte) in an isolated memory buffer.',
      impact: 'Triggers RULE-RANSOMWARE-01, raises Risk Score to >85 (HIGH), generates incident and isolates process.'
    },
    {
      id: 'REVERSE_SHELL',
      title: 'Reverse Shell C2 Connect',
      icon: Network,
      color: 'amber',
      description: 'Simulates outbound socket connection to C2 port 4444 originating from executable binary spawned under /tmp.',
      impact: 'Triggers RULE-C2-SHELL-01 & RULE-EXEC-01, flags threat port, raises Risk Score to >80 (HIGH).'
    },
    {
      id: 'EXFILTRATION',
      title: 'Data Exfiltration Burst',
      icon: ArrowUpRight,
      color: 'purple',
      description: 'Simulates high throughput outbound data stream (14.5 MB/s) across 18 concurrent socket descriptors.',
      impact: 'Triggers RULE-EXFIL-01, flags high data exfiltration rate, predicts Data Exfiltration category.'
    },
    {
      id: 'CRYPTOMINER',
      title: 'CryptoMiner CPU Hijack',
      icon: Cpu,
      color: 'cyan',
      description: 'Simulates sustained 96% CPU spike accompanied by high thread spawn velocity originating from xmrig payload.',
      impact: 'Triggers RULE-MINER-01, flags abnormal CPU spike, predicts CryptoMiner threat category.'
    }
  ];

  return (
    <div className="space-y-6">
      {/* Simulation Info Header */}
      <div className="glass-panel p-6 border border-slate-800 space-y-2">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400">
            <Zap className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-bold font-mono text-slate-100 uppercase tracking-wider">
              Interactive Safe Threat Simulator Sandbox
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Test OSentinel's real-time detection, Isolation Forest anomaly scoring, and automated triage containment safely in memory without risking host files.
            </p>
          </div>
        </div>
      </div>

      {/* Active Simulation Status Banner */}
      {activeSim && (
        <div className="glass-panel-rose p-4 border border-rose-500/50 flex items-center justify-between text-rose-200 animate-pulse font-mono text-xs">
          <div className="flex items-center space-x-3">
            <ShieldAlert className="w-6 h-6 text-rose-400" />
            <div>
              <strong className="text-sm block">THREAT SCENARIO IN PROGRESS: {activeSim.type}</strong>
              <span>{activeSim.details}</span>
            </div>
          </div>
          <span className="px-3 py-1 rounded bg-rose-500 text-white font-bold">ACTIVE</span>
        </div>
      )}

      {/* Scenario Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {scenarios.map((scen) => {
          const Icon = scen.icon;
          const isLoading = loadingType === scen.id;

          return (
            <div key={scen.id} className="glass-panel p-6 border border-slate-800 flex flex-col justify-between space-y-4 hover:border-slate-700 transition-colors">
              <div className="space-y-3">
                <div className="flex items-center space-x-3">
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-700 text-cyan-400">
                    <Icon className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="font-bold font-mono text-slate-100 text-sm">{scen.title}</h4>
                    <span className="text-[11px] font-mono text-cyan-400">SCENARIO: {scen.id}</span>
                  </div>
                </div>

                <p className="text-xs text-slate-300 font-mono leading-relaxed">
                  {scen.description}
                </p>

                <div className="p-2.5 rounded bg-slate-950/80 border border-slate-800/80 text-[11px] font-mono text-slate-400">
                  <strong className="text-slate-300">Expected Outcome:</strong> {scen.impact}
                </div>
              </div>

              <button
                disabled={isLoading}
                onClick={() => handleSimulate(scen.id)}
                className={`w-full py-2.5 px-4 rounded-lg font-mono text-xs font-bold transition-all flex items-center justify-center space-x-2 ${
                  isLoading
                    ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                    : 'bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 shadow-lg shadow-cyan-500/10 active:scale-[0.98]'
                }`}
              >
                <Zap className="w-4 h-4 text-cyan-400" />
                <span>{isLoading ? "LAUNCHING SIMULATION..." : `FIRE SIMULATION: ${scen.title.toUpperCase()}`}</span>
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
