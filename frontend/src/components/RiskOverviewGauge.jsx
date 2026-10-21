import React, { useState, useEffect } from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { ShieldCheck, ShieldAlert, Cpu, HardDrive, Network, Zap } from 'lucide-react';

export default function RiskOverviewGauge({ statusData }) {
  const [history, setHistory] = useState([]);

  const riskScore = statusData?.risk_assessment?.risk_score ?? 0;
  const severity = statusData?.risk_assessment?.severity ?? 'LOW';
  const threatCat = statusData?.risk_assessment?.threat_category ?? 'Normal';
  const breakdown = statusData?.risk_assessment?.score_breakdown ?? { rule_component: 0, anomaly_component: 0, classifier_component: 0 };
  
  const procTelemetry = statusData?.process_telemetry ?? {};
  const fileTelemetry = statusData?.file_telemetry ?? {};
  const netTelemetry = statusData?.network_telemetry ?? {};

  useEffect(() => {
    if (statusData?.timestamp) {
      const timeStr = new Date(statusData.timestamp * 1000).toLocaleTimeString();
      setHistory(prev => {
        const next = [...prev, { time: timeStr, risk: riskScore }];
        return next.slice(-20); // Keep last 20 ticks
      });
    }
  }, [statusData?.timestamp, riskScore]);

  // Color mapping
  let gaugeColor = "#10b981"; // Emerald
  let strokeColor = "stroke-emerald-500";
  if (riskScore >= 70) {
    gaugeColor = "#f43f5e"; // Rose
    strokeColor = "stroke-rose-500";
  } else if (riskScore >= 40) {
    gaugeColor = "#f59e0b"; // Amber
    strokeColor = "stroke-amber-500";
  }

  return (
    <div className="space-y-6">
      {/* Top 4 KPI Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="glass-panel p-4 border border-slate-800 flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-400 font-mono">ACTIVE PROCESSES</p>
            <p className="text-2xl font-bold text-slate-100 font-mono mt-1">{procTelemetry.process_count ?? 0}</p>
            <p className="text-xs text-cyan-400 mt-1">Spawn velocity: {procTelemetry.spawn_rate ?? 0}/s</p>
          </div>
          <div className="p-3 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Cpu className="w-6 h-6" />
          </div>
        </div>

        <div className="glass-panel p-4 border border-slate-800 flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-400 font-mono">FILE ENTROPY H(X)</p>
            <p className="text-2xl font-bold text-slate-100 font-mono mt-1">{fileTelemetry.avg_file_entropy ?? 0.0}</p>
            <p className="text-xs text-slate-400 mt-1">Mod rate: {fileTelemetry.file_mod_rate ?? 0}/s</p>
          </div>
          <div className="p-3 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <HardDrive className="w-6 h-6" />
          </div>
        </div>

        <div className="glass-panel p-4 border border-slate-800 flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-400 font-mono">OUTBOUND SOCKETS</p>
            <p className="text-2xl font-bold text-slate-100 font-mono mt-1">{netTelemetry.outbound_conn_count ?? 0}</p>
            <p className="text-xs text-slate-400 mt-1">Threat port flag: {netTelemetry.suspicious_port_flag ? "TRIGGERED" : "CLEAN"}</p>
          </div>
          <div className="p-3 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <Network className="w-6 h-6" />
          </div>
        </div>

        <div className="glass-panel p-4 border border-slate-800 flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-400 font-mono">PREDICTED THREAT</p>
            <p className="text-xl font-bold text-slate-100 font-mono mt-1 truncate max-w-[150px]">{threatCat}</p>
            <p className="text-xs text-slate-400 mt-1">Severity: <span className="font-bold text-slate-200">{severity}</span></p>
          </div>
          <div className="p-3 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <Zap className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* Main Gauge & Real-Time Risk Graph Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Radial Risk Gauge Dial */}
        <div className="glass-panel p-6 border border-slate-800 flex flex-col items-center justify-center text-center relative overflow-hidden">
          <h3 className="text-sm font-semibold text-slate-300 font-mono uppercase tracking-wider mb-4">
            Unified OS Risk Index
          </h3>
          
          <div className="relative w-48 h-48 flex items-center justify-center my-2">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
              <circle
                cx="50"
                cy="50"
                r="40"
                className="stroke-slate-800"
                strokeWidth="8"
                fill="transparent"
              />
              <circle
                cx="50"
                cy="50"
                r="40"
                stroke={gaugeColor}
                strokeWidth="8"
                strokeDasharray={251.2}
                strokeDashoffset={251.2 - (251.2 * riskScore) / 100}
                strokeLinecap="round"
                fill="transparent"
                className="transition-all duration-500 ease-out"
              />
            </svg>

            <div className="absolute flex flex-col items-center justify-center">
              <span className="text-4xl font-extrabold font-mono text-slate-50">{riskScore}</span>
              <span className="text-xs font-mono text-slate-400">/ 100</span>
              <span className={`mt-1 text-xs px-2 py-0.5 rounded font-mono font-bold uppercase ${
                severity === 'HIGH' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40' :
                severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' :
                'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
              }`}>
                {severity} RISK
              </span>
            </div>
          </div>

          <p className="text-xs text-slate-400 mt-2 font-mono">
            {severity === 'HIGH' ? 'High Risk Threat Detected - Automated Containment Enabled' :
             severity === 'MEDIUM' ? 'Suspicious Behavioral Anomalies Flagged - Monitoring' :
             'System Operating in Baseline Safe State'}
          </p>
        </div>

        {/* Real-time Risk Score Trend Line Chart */}
        <div className="lg:col-span-2 glass-panel p-6 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-300 font-mono uppercase tracking-wider">
                Real-Time Risk Telemetry Stream
              </h3>
              <p className="text-xs text-slate-400">Live 2-second polling tick stream</p>
            </div>
            <div className="flex items-center space-x-2 text-xs font-mono text-cyan-400">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
              <span>LIVE FEED</span>
            </div>
          </div>

          <div className="h-48 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={history}>
                <defs>
                  <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={gaugeColor} stopOpacity={0.4}/>
                    <stop offset="95%" stopColor={gaugeColor} stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#475569" tick={{ fontSize: 10 }} />
                <YAxis domain={[0, 100]} stroke="#475569" tick={{ fontSize: 10 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                />
                <Area type="monotone" dataKey="risk" stroke={gaugeColor} strokeWidth={2} fillOpacity={1} fill="url(#riskGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Risk Weight Breakdown Bar */}
          <div className="mt-4 pt-3 border-t border-slate-800/80">
            <p className="text-xs font-mono text-slate-400 mb-2">RISK FORMULA CONTRIBUTION WEIGHTS:</p>
            <div className="grid grid-cols-3 gap-2 text-center text-xs font-mono">
              <div className="p-2 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-400 block">Rule Engine (45%)</span>
                <span className="text-cyan-400 font-bold">+{breakdown.rule_component} pts</span>
              </div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-400 block">Isolation Forest (35%)</span>
                <span className="text-purple-400 font-bold">+{breakdown.anomaly_component} pts</span>
              </div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-400 block">Random Forest (20%)</span>
                <span className="text-amber-400 font-bold">+{breakdown.classifier_component} pts</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
