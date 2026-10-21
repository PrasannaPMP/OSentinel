import React, { useState } from 'react';
import { AlertTriangle, ShieldAlert, CheckCircle2, XCircle, ChevronRight, Info, Trash2 } from 'lucide-react';

export default function IncidentsList({ incidents, onContainIncident }) {
  const [selectedIncident, setSelectedIncident] = useState(null);

  return (
    <div className="space-y-6">
      <div className="glass-panel p-6 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 font-mono uppercase tracking-wider flex items-center space-x-2">
              <AlertTriangle className="w-5 h-5 text-rose-400" />
              <span>Security Incidents & Automated Response Triage</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">High risk threats (&ge; 70 score) requiring forensic review and containment action</p>
          </div>
        </div>

        {/* Incidents Table */}
        <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950/60">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/90 text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Incident Code</th>
                <th className="py-3 px-4">Threat Category</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Target Process</th>
                <th className="py-3 px-4">Containment Action</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {incidents.length === 0 ? (
                <tr>
                  <td colSpan="7" className="py-8 text-center text-slate-500 font-mono">
                    <CheckCircle2 className="w-8 h-8 text-emerald-500/40 mx-auto mb-2" />
                    No security incidents logged. All system metrics within safe baseline.
                  </td>
                </tr>
              ) : (
                incidents.map((inc) => {
                  let evidenceObj = {};
                  try { evidenceObj = JSON.parse(inc.evidence); } catch (e) {}

                  return (
                    <tr key={inc.id} className="hover:bg-slate-900/40">
                      <td className="py-3 px-4 font-bold text-slate-200">{inc.incident_code}</td>
                      <td className="py-3 px-4">
                        <span className="px-2.5 py-1 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold">
                          {inc.threat_category}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-extrabold text-rose-400 text-sm">
                        {inc.risk_score} / 100
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-cyan-300 font-semibold">{inc.process_name}</span>
                        <span className="text-slate-500 text-[11px] block">PID: {inc.pid}</span>
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        {inc.containment_action}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded font-bold text-[11px] ${
                          inc.status === 'OPEN' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40 animate-pulse' :
                          inc.status === 'RESOLVED' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' :
                          'bg-slate-800 text-slate-400 border border-slate-700'
                        }`}>
                          {inc.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => setSelectedIncident(inc)}
                          className="px-2.5 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 transition-colors font-mono text-[11px] inline-flex items-center space-x-1"
                        >
                          <span>INSPECT EVIDENCE</span>
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Forensic Evidence Modal View */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="glass-panel-cyan max-w-3xl w-full p-6 space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-bold font-mono text-slate-100 flex items-center space-x-2">
                  <ShieldAlert className="w-5 h-5 text-rose-400" />
                  <span>Incident Forensic Breakdown: {selectedIncident.incident_code}</span>
                </h3>
                <p className="text-xs text-slate-400 font-mono mt-0.5">Logged: {selectedIncident.timestamp}</p>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs"
              >
                CLOSE
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4 text-xs font-mono">
              <div className="p-3 bg-slate-900/80 rounded border border-slate-800">
                <span className="text-slate-400 block">Threat Category</span>
                <span className="text-rose-400 font-bold text-sm">{selectedIncident.threat_category}</span>
              </div>
              <div className="p-3 bg-slate-900/80 rounded border border-slate-800">
                <span className="text-slate-400 block">Risk Score</span>
                <span className="text-rose-400 font-bold text-sm">{selectedIncident.risk_score} / 100</span>
              </div>
            </div>

            {/* Containment Buttons */}
            {selectedIncident.status === 'OPEN' && (
              <div className="p-4 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-between">
                <div>
                  <h4 className="font-bold text-xs text-rose-300 uppercase font-mono">Execute Containment Override</h4>
                  <p className="text-[11px] text-slate-400 font-mono">Terminate target process PID {selectedIncident.pid} immediately</p>
                </div>
                <div className="flex space-x-2">
                  <button
                    onClick={() => {
                      onContainIncident(selectedIncident.id, selectedIncident.pid, selectedIncident.process_name, "TERMINATE");
                      setSelectedIncident(null);
                    }}
                    className="px-3 py-1.5 rounded bg-rose-500 hover:bg-rose-600 text-white font-mono text-xs font-bold flex items-center space-x-1"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>TERMINATE PID {selectedIncident.pid}</span>
                  </button>
                  <button
                    onClick={() => {
                      onContainIncident(selectedIncident.id, selectedIncident.pid, selectedIncident.process_name, "IGNORE");
                      setSelectedIncident(null);
                    }}
                    className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs"
                  >
                    DISMISS
                  </button>
                </div>
              </div>
            )}

            {/* Evidence Payload */}
            <div className="space-y-2 font-mono text-xs">
              <h4 className="text-xs font-bold text-slate-300 uppercase">Evidence Log Dump:</h4>
              <pre className="p-4 bg-slate-950 rounded border border-slate-800 text-cyan-300 overflow-x-auto text-[11px]">
                {JSON.stringify(JSON.parse(selectedIncident.evidence || '{}'), null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
