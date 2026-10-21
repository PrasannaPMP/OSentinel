import React from 'react';
import { Shield, ShieldAlert, Activity, CheckCircle2, AlertTriangle, AlertCircle } from 'lucide-react';

export default function Header({ statusData, isConnected }) {
  const riskScore = statusData?.risk_assessment?.risk_score ?? 0;
  const severity = statusData?.risk_assessment?.severity ?? 'LOW';
  const activeSim = statusData?.active_simulation;

  let riskBadgeClass = "badge-clean badge-emerald";
  let RiskIcon = CheckCircle2;
  let severityLabel = "NORMAL (LOW)";

  if (severity === "HIGH") {
    riskBadgeClass = "badge-clean badge-rose";
    RiskIcon = AlertTriangle;
    severityLabel = "CRITICAL (HIGH)";
  } else if (severity === "MEDIUM") {
    riskBadgeClass = "badge-clean badge-amber";
    RiskIcon = AlertCircle;
    severityLabel = "ELEVATED (MED)";
  }

  return (
    <header className="card-panel px-6 py-4 mb-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
      {/* Brand Title */}
      <div className="flex items-center gap-3.5">
        <div className="p-2.5 rounded-lg bg-slate-900 text-white shadow-sm flex items-center justify-center flex-shrink-0">
          <Shield className="w-6 h-6 text-white" />
        </div>
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-extrabold tracking-tight text-slate-900 m-0">OSentinel</h1>
            <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-300 font-mono">
              SOC v1.0
            </span>
          </div>
          <p className="text-xs text-slate-500 m-0 mt-0.5 font-medium">
            Host-Based Intrusion Detection & Real-Time Incident Defense
          </p>
        </div>
      </div>

      {/* Center Simulation Status Banner if Active */}
      {activeSim && (
        <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-md bg-red-50 border border-red-300 text-red-800 text-xs font-mono font-bold flex-shrink-0">
          <ShieldAlert className="w-4 h-4 text-red-600 flex-shrink-0" />
          <span>ATTACK SIMULATION RUNNING: {activeSim.type}</span>
        </div>
      )}

      {/* Right Metric Badges */}
      <div className="flex items-center gap-3 flex-wrap">
        {/* Stream Status */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-slate-100 border border-slate-300 text-xs font-mono font-bold text-slate-700">
          <span className={`w-2.5 h-2.5 rounded-full ${isConnected ? 'bg-emerald-500' : 'bg-slate-400'}`}></span>
          <span>{isConnected ? "TELEMETRY LIVE" : "DISCONNECTED"}</span>
        </div>

        {/* Global Risk Score Badge */}
        <div className={`px-3.5 py-1.5 rounded-md font-mono text-xs font-bold flex items-center gap-1.5 ${riskBadgeClass}`}>
          <RiskIcon className="w-4 h-4 flex-shrink-0" />
          <span>RISK: {riskScore}/100 • {severityLabel}</span>
        </div>
      </div>
    </header>
  );
}
