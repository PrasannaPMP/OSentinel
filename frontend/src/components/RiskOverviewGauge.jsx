import React, { useState, useEffect } from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { Cpu, HardDrive, Network, ShieldCheck, AlertTriangle } from 'lucide-react';

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
        return next.slice(-20);
      });
    }
  }, [statusData?.timestamp, riskScore]);

  // Color mapping
  let gaugeColor = "#16a34a"; // Green
  let badgeClass = "badge-clean badge-emerald";
  if (riskScore >= 70) {
    gaugeColor = "#dc2626"; // Red
    badgeClass = "badge-clean badge-rose";
  } else if (riskScore >= 40) {
    gaugeColor = "#d97706"; // Amber
    badgeClass = "badge-clean badge-amber";
  }

  return (
    <div className="space-y-6">
      {/* Top 4 KPI Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Card 1 */}
        <div className="card-panel p-4 flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-500 font-bold uppercase tracking-wider font-mono m-0">ACTIVE PROCESSES</p>
            <p className="text-2xl font-extrabold text-slate-900 font-mono mt-1 mb-0">{procTelemetry.process_count ?? 0}</p>
            <p className="text-xs text-slate-600 mt-1 mb-0 font-medium">Spawn rate: <strong className="text-slate-900">{procTelemetry.spawn_rate ?? 0}/s</strong></p>
          </div>
          <div className="p-3 rounded-lg bg-slate-100 text-slate-700 border border-slate-200">
            <Cpu className="w-6 h-6" />
          </div>
        </div>

        {/* Card 2 */}
        <div className="card-panel p-4 flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-500 font-bold uppercase tracking-wider font-mono m-0">FILE ENTROPY H(X)</p>
            <p className="text-2xl font-extrabold text-slate-900 font-mono mt-1 mb-0">{fileTelemetry.avg_file_entropy ?? 0.0}</p>
            <p className="text-xs text-slate-600 mt-1 mb-0 font-medium">Write rate: <strong className="text-slate-900">{fileTelemetry.file_mod_rate ?? 0}/s</strong></p>
          </div>
          <div className="p-3 rounded-lg bg-slate-100 text-slate-700 border border-slate-200">
            <HardDrive className="w-6 h-6" />
          </div>
        </div>

        {/* Card 3 */}
        <div className="card-panel p-4 flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-500 font-bold uppercase tracking-wider font-mono m-0">OUTBOUND SOCKETS</p>
            <p className="text-2xl font-extrabold text-slate-900 font-mono mt-1 mb-0">{netTelemetry.outbound_conn_count ?? 0}</p>
            <p className="text-xs text-slate-600 mt-1 mb-0 font-medium">
              Threat ports: <strong className={netTelemetry.suspicious_port_flag ? "text-red-600 font-bold" : "text-emerald-700 font-bold"}>
                {netTelemetry.suspicious_port_flag ? "TRIGGERED" : "CLEAN"}
              </strong>
            </p>
          </div>
          <div className="p-3 rounded-lg bg-slate-100 text-slate-700 border border-slate-200">
            <Network className="w-6 h-6" />
          </div>
        </div>

        {/* Card 4 */}
        <div className="card-panel p-4 flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-500 font-bold uppercase tracking-wider font-mono m-0">PREDICTED VECTOR</p>
            <p className="text-xl font-extrabold text-slate-900 font-mono mt-1 mb-0 truncate max-w-[150px]">{threatCat}</p>
            <p className="text-xs text-slate-600 mt-1 mb-0 font-medium">
              Severity: <strong className="text-slate-900">{severity}</strong>
            </p>
          </div>
          <div className="p-3 rounded-lg bg-slate-100 text-slate-700 border border-slate-200">
            {severity === 'HIGH' ? <AlertTriangle className="w-6 h-6 text-red-600" /> : <ShieldCheck className="w-6 h-6 text-emerald-600" />}
          </div>
        </div>
      </div>

      {/* Main Gauge & Real-Time Risk Graph Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Radial Risk Gauge Dial */}
        <div className="card-panel p-6 flex flex-col items-center justify-center text-center">
          <h3 className="text-xs font-bold text-slate-700 font-mono uppercase tracking-wider mb-2">
            Host Risk Severity Index
          </h3>
          
          <div className="relative w-44 h-44 flex items-center justify-center my-2">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
              <circle
                cx="50"
                cy="50"
                r="38"
                stroke="#e2e8f0"
                strokeWidth="7"
                fill="transparent"
              />
              <circle
                cx="50"
                cy="50"
                r="38"
                stroke={gaugeColor}
                strokeWidth="7"
                strokeDasharray={238.7}
                strokeDashoffset={238.7 - (238.7 * riskScore) / 100}
                strokeLinecap="round"
                fill="transparent"
                style={{ transition: 'stroke-dashoffset 0.5s ease-out' }}
              />
            </svg>

            <div className="absolute flex flex-col items-center justify-center">
              <span className="text-4xl font-extrabold font-mono text-slate-900 leading-none">{riskScore}</span>
              <span className="text-xs font-mono font-medium text-slate-400 mt-0.5">/ 100</span>
              <span className={`mt-2 ${badgeClass}`}>
                {severity} RISK
              </span>
            </div>
          </div>

          <p className="text-xs text-slate-500 mt-2 font-mono m-0 font-medium">
            {severity === 'HIGH' ? 'Critical anomaly detected — containment engaged' :
             severity === 'MEDIUM' ? 'Behavioral deviation flagged — monitoring' :
             'System operating in verified safe baseline'}
          </p>
        </div>

        {/* Real-time Risk Score Trend Line Chart */}
        <div className="md:grid-cols-2 card-panel p-6 flex flex-col justify-between" style={{ gridColumn: 'span 2' }}>
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-xs font-bold text-slate-800 font-mono uppercase tracking-wider m-0">
                Live Risk Telemetry Activity
              </h3>
              <p className="text-xs text-slate-500 m-0 mt-0.5 font-medium">Consecutive 2-second telemetry probe timeline</p>
            </div>
            <div className="flex items-center space-x-1.5 text-xs font-mono font-bold text-emerald-700 bg-emerald-50 px-2.5 py-1 rounded border border-emerald-200">
              <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
              <span>LIVE POLLING</span>
            </div>
          </div>

          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={history}>
                <defs>
                  <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={gaugeColor} stopOpacity={0.25}/>
                    <stop offset="95%" stopColor={gaugeColor} stopOpacity={0.02}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#94a3b8" tick={{ fontSize: 10, fill: '#64748b' }} />
                <YAxis domain={[0, 100]} stroke="#94a3b8" tick={{ fontSize: 10, fill: '#64748b' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#ffffff', borderColor: '#cbd5e1', borderRadius: '6px', fontSize: '12px', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)' }}
                  labelStyle={{ color: '#0f172a', fontWeight: 'bold' }}
                />
                <Area type="monotone" dataKey="risk" stroke={gaugeColor} strokeWidth={2.5} fillOpacity={1} fill="url(#riskGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Risk Weight Breakdown Bar */}
          <div className="mt-4 pt-3 border-t border-slate-200">
            <p className="text-[11px] font-mono font-bold text-slate-500 mb-2 uppercase">
              Composite Risk Model Contribution Weights:
            </p>
            <div className="grid grid-cols-3 gap-2 text-center text-xs font-mono">
              <div className="p-2 rounded bg-slate-50 border border-slate-200">
                <span className="text-slate-500 block text-[11px]">Rule Heuristics (45%)</span>
                <span className="text-slate-900 font-extrabold text-sm">+{breakdown.rule_component} pts</span>
              </div>
              <div className="p-2 rounded bg-slate-50 border border-slate-200">
                <span className="text-slate-500 block text-[11px]">Isolation Forest (35%)</span>
                <span className="text-slate-900 font-extrabold text-sm">+{breakdown.anomaly_component} pts</span>
              </div>
              <div className="p-2 rounded bg-slate-50 border border-slate-200">
                <span className="text-slate-500 block text-[11px]">Random Forest (20%)</span>
                <span className="text-slate-900 font-extrabold text-sm">+{breakdown.classifier_component} pts</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
