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
      description: 'Simulates rapid file modification velocity (85 writes/sec) with high Shannon Entropy (H=7.85 bits/byte) in a sandbox memory buffer.',
      impact: 'Triggers RULE-RANSOMWARE-01, raises composite Risk Score to >85 (HIGH), and dispatches automated process suspension.',
      buttonText: 'EXECUTE RANSOMWARE SIMULATION'
    },
    {
      id: 'REVERSE_SHELL',
      title: 'Reverse Shell C2 Connection',
      icon: Network,
      description: 'Simulates unauthorized outbound socket connection to remote Command & Control (C2) port 4444 from an executable located under /tmp.',
      impact: 'Triggers RULE-C2-SHELL-01 & RULE-EXEC-01, flags threat port, raises Risk Score to >80 (HIGH).',
      buttonText: 'EXECUTE REVERSE SHELL C2'
    },
    {
      id: 'EXFILTRATION',
      title: 'Data Exfiltration Burst',
      icon: ArrowUpRight,
      description: 'Simulates high-throughput outbound data transmission (14.5 MB/s) across multiple concurrent foreign socket descriptors.',
      impact: 'Triggers RULE-EXFIL-01, flags excessive data exfiltration threshold, predicts Data Exfiltration attack vector.',
      buttonText: 'EXECUTE DATA EXFILTRATION'
    },
    {
      id: 'CRYPTOMINER',
      title: 'CryptoMiner CPU Hijack',
      icon: Cpu,
      description: 'Simulates sustained 96% CPU spike accompanied by rapid thread spawn velocity originating from an xmrig-like background payload.',
      impact: 'Triggers RULE-MINER-01, flags abnormal processor consumption, predicts CryptoMiner threat category.',
      buttonText: 'EXECUTE CRYPTOMINER SPIKE'
    }
  ];

  return (
    <div className="space-y-6">
      {/* Simulation Info Header */}
      <div className="card-panel p-6">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 rounded-lg bg-slate-900 text-white flex items-center justify-center">
            <Zap className="w-6 h-6 text-amber-400" />
          </div>
          <div>
            <h3 className="text-base font-extrabold text-slate-900 uppercase tracking-tight font-mono m-0">
              Interactive Safe Threat Simulation Sandbox
            </h3>
            <p className="text-xs text-slate-600 font-medium m-0 mt-1">
              Test OSentinel's real-time detection, Isolation Forest anomaly scoring, and automated triage containment safely in memory without risking host files.
            </p>
          </div>
        </div>
      </div>

      {/* Active Simulation Status Banner */}
      {activeSim && (
        <div className="card-panel p-4 bg-red-50 border-red-300 flex items-center justify-between text-red-900 font-mono text-xs">
          <div className="flex items-center space-x-3">
            <ShieldAlert className="w-5 h-5 text-red-600 flex-shrink-0" />
            <div>
              <strong className="text-sm block text-red-800">ATTACK SCENARIO ACTIVE: {activeSim.type}</strong>
              <span className="text-slate-700">{activeSim.details}</span>
            </div>
          </div>
          <span className="px-3 py-1 rounded-md bg-red-600 text-white font-extrabold text-xs">
            SIMULATION RUNNING
          </span>
        </div>
      )}

      {/* Scenario Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {scenarios.map((scen) => {
          const Icon = scen.icon;
          const isLoading = loadingType === scen.id;

          return (
            <div key={scen.id} className="card-panel p-6 flex flex-col justify-between space-y-4">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="p-2.5 rounded-md bg-slate-100 border border-slate-300 text-slate-800">
                      <Icon className="w-5 h-5" />
                    </div>
                    <div>
                      <h4 className="font-extrabold text-slate-900 text-sm m-0">{scen.title}</h4>
                      <span className="text-[11px] font-mono font-bold text-slate-500">SCENARIO: {scen.id}</span>
                    </div>
                  </div>
                  <span className="badge-clean badge-neutral font-mono">SAFE DEMO</span>
                </div>

                <p className="text-xs text-slate-600 leading-relaxed m-0 font-medium">
                  {scen.description}
                </p>

                <div className="p-3 rounded-md bg-slate-50 border border-slate-200 text-xs font-mono text-slate-600">
                  <strong className="text-slate-900 font-bold block mb-1">Expected Security Response:</strong>
                  {scen.impact}
                </div>
              </div>

              {/* Bold, Legible Action Button */}
              <button
                disabled={isLoading}
                onClick={() => handleSimulate(scen.id)}
                className="btn-bold-primary w-full py-3 text-xs tracking-wide"
                style={{
                  backgroundColor: isLoading ? '#94a3b8' : '#0f172a',
                  color: '#ffffff',
                }}
              >
                <Zap className="w-4 h-4 text-amber-300" />
                <span>{isLoading ? "DISPATCHING SIMULATION..." : scen.buttonText}</span>
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
