import React from 'react';
import { Shield, ShieldAlert, Activity, Cpu, Database, Server } from 'lucide-react';

export default function Header({ statusData, isConnected }) {
  const riskScore = statusData?.risk_assessment?.risk_score ?? 0;
  const severity = statusData?.risk_assessment?.severity ?? 'LOW';
  const activeSim = statusData?.active_simulation;

  let riskColor = "bg-emerald-500/20 text-emerald-400 border-emerald-500/40";
  let pulseColor = "bg-emerald-500";
  if (severity === "HIGH") {
    riskColor = "bg-rose-500/20 text-rose-400 border-rose-500/40 animate-pulse";
    pulseColor = "bg-rose-500 pulse-danger";
  } else if (severity === "MEDIUM") {
    riskColor = "bg-amber-500/20 text-amber-400 border-amber-500/40";
    pulseColor = "bg-amber-500";
  }

  return (
    <header className="sticky top-0 z-50 glass-panel border-b border-slate-800/80 px-6 py-3 mb-6 flex flex-col md:flex-row items-center justify-between gap-4">
      {/* Brand Title */}
      <div className="flex items-center space-x-3">
        <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-lg shadow-cyan-500/10">
          <Shield className="w-7 h-7" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-bold tracking-wider text-slate-50 uppercase font-mono">OSentinel</h1>
            <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-mono">v1.0.0</span>
          </div>
          <p className="text-xs text-slate-400">Intelligent Host-Based Security Framework • Ubuntu Linux</p>
        </div>
      </div>

      {/* Center Simulation Status Banner if Active */}
      {activeSim && (
        <div className="flex items-center space-x-2 px-3.5 py-1.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono animate-pulse">
          <ShieldAlert className="w-4 h-4 text-rose-400" />
          <span>SIMULATION ACTIVE: <strong>{activeSim.type}</strong></span>
        </div>
      )}

      {/* Right Metric Badges */}
      <div className="flex items-center space-x-4">
        {/* Live Status Indicator */}
        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 text-xs font-mono">
          <span className={`w-2.5 h-2.5 rounded-full ${isConnected ? pulseColor : 'bg-slate-600'}`}></span>
          <span className="text-slate-300">{isConnected ? "STREAM ONLINE" : "CONNECTING..."}</span>
        </div>

        {/* Global Risk Badge */}
        <div className={`flex items-center space-x-2 px-4 py-1.5 rounded-lg border font-mono text-sm font-semibold ${riskColor}`}>
          <Activity className="w-4 h-4" />
          <span>RISK SCORE: {riskScore} ({severity})</span>
        </div>
      </div>
    </header>
  );
}
