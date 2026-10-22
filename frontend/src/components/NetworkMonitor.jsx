import React, { useState, useEffect } from 'react';
import { Network, AlertCircle, ShieldAlert, ShieldBan, Plus, Trash2, Power, Globe, CheckCircle2 } from 'lucide-react';
import { fetchRestrictedNetworks, addRestrictedNetwork, deleteRestrictedNetwork, toggleRestrictedNetwork } from '../services/api';

export default function NetworkMonitor({ netTelemetry }) {
  const outboundCount = netTelemetry.outbound_conn_count ?? 0;
  const suspiciousFlag = netTelemetry.suspicious_port_flag ?? 0;
  const restrictedIpFlag = netTelemetry.restricted_ip_flag ?? 0;
  const restrictedConnsCount = netTelemetry.restricted_conns_count ?? 0;
  const exfilRate = netTelemetry.data_exfil_kb_sec ?? 0.0;
  const connections = netTelemetry.connections || [];

  const [restrictedNetworks, setRestrictedNetworks] = useState([]);
  const [newCidr, setNewCidr] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [feedbackMsg, setFeedbackMsg] = useState(null);

  const loadRestrictedNetworks = async () => {
    try {
      const data = await fetchRestrictedNetworks();
      setRestrictedNetworks(data);
    } catch (e) {
      console.error("Failed to load restricted networks:", e);
    }
  };

  useEffect(() => {
    loadRestrictedNetworks();
  }, []);

  const handleAddNetwork = async (e) => {
    e.preventDefault();
    if (!newCidr.trim()) return;
    setIsSubmitting(true);
    setFeedbackMsg(null);
    try {
      await addRestrictedNetwork(newCidr.trim(), newDesc.trim(), "BLOCK");
      setNewCidr('');
      setNewDesc('');
      setFeedbackMsg({ type: 'success', text: `Successfully added ${newCidr} to restricted networks.` });
      await loadRestrictedNetworks();
    } catch (err) {
      setFeedbackMsg({ type: 'error', text: err.message });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDelete = async (id, cidr) => {
    if (!window.confirm(`Are you sure you want to delete restriction for ${cidr}?`)) return;
    try {
      await deleteRestrictedNetwork(id);
      await loadRestrictedNetworks();
    } catch (err) {
      alert(`Error deleting: ${err.message}`);
    }
  };

  const handleToggle = async (id) => {
    try {
      await toggleRestrictedNetwork(id);
      await loadRestrictedNetworks();
    } catch (err) {
      alert(`Error toggling status: ${err.message}`);
    }
  };

  const activePoliciesCount = restrictedNetworks.filter(n => n.is_active).length;

  return (
    <div className="space-y-6">
      {/* Network Overview Cards (4 Grid) */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card-panel p-5">
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider font-mono m-0">ACTIVE OUTBOUND SOCKETS</p>
          <p className="text-3xl font-extrabold text-slate-900 font-mono mt-2 mb-0">{outboundCount}</p>
          <p className="text-xs text-slate-500 mt-2 font-mono m-0">Live TCP/UDP host sockets</p>
        </div>

        <div className="card-panel p-5">
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider font-mono m-0">RESTRICTED IP FIREWALL</p>
          <div className="flex items-center space-x-2 mt-2">
            <span className={`text-xl font-extrabold font-mono ${restrictedIpFlag ? 'text-red-600 animate-pulse' : 'text-emerald-700'}`}>
              {restrictedIpFlag ? 'ACCESS BLOCKED' : `${activePoliciesCount} POLICIES ACTIVE`}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-2 font-mono m-0">
            {restrictedIpFlag ? `${restrictedConnsCount} restricted socket(s) severed` : 'Auto-blocks unauthorized subnets'}
          </p>
        </div>

        <div className="card-panel p-5">
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider font-mono m-0">C2 THREAT PORT FLAG</p>
          <div className="flex items-center space-x-2 mt-2">
            <span className={`text-xl font-extrabold font-mono ${suspiciousFlag ? 'text-red-600' : 'text-emerald-700'}`}>
              {suspiciousFlag ? 'THREAT DETECTED' : 'CLEAN'}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-2 font-mono m-0">Ports: 4444, 1337, 31337, 8888</p>
        </div>

        <div className="card-panel p-5">
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider font-mono m-0">OUTBOUND THROUGHPUT RATE</p>
          <p className="text-3xl font-extrabold text-slate-900 font-mono mt-2 mb-0">
            {exfilRate > 1024 ? `${(exfilRate / 1024).toFixed(2)} MB/s` : `${exfilRate} KB/s`}
          </p>
          <p className="text-xs text-slate-500 mt-2 font-mono m-0">Exfiltration threshold: &ge; 1.0 MB/s</p>
        </div>
      </div>

      {/* Restricted Network Policies Management Panel */}
      <div className="card-panel p-6 space-y-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-200 pb-4">
          <div>
            <h3 className="text-sm font-extrabold text-slate-900 font-mono uppercase tracking-wider flex items-center space-x-2 m-0">
              <ShieldBan className="w-5 h-5 text-red-600" />
              <span>Restricted Networks & IP Access Restriction Policy</span>
            </h3>
            <p className="text-xs text-slate-600 mt-1 m-0">
              Define IP addresses or CIDR subnets (e.g. <code className="text-slate-800 bg-slate-100 px-1 py-0.5 rounded font-mono">198.51.100.0/24</code>, <code className="text-slate-800 bg-slate-100 px-1 py-0.5 rounded font-mono">10.99.0.0/16</code>). Any access to/from these networks is immediately blocked and auto-contained.
            </p>
          </div>
          <span className="badge-clean badge-rose font-mono self-start md:self-auto">
            AUTO-CONTAINMENT ACTIVE
          </span>
        </div>

        {/* Add New Restricted Network Form */}
        <form onSubmit={handleAddNetwork} className="bg-slate-50 p-4 rounded-lg border border-slate-200 space-y-3">
          <div className="text-xs font-bold font-mono text-slate-800 uppercase">
            Restrict New Network Subnet or IP Address
          </div>
          <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-center">
            <div className="md:col-span-4">
              <input
                type="text"
                placeholder="IP or CIDR (e.g., 198.51.100.0/24, 192.168.1.50)"
                value={newCidr}
                onChange={(e) => setNewCidr(e.target.value)}
                className="w-full text-xs font-mono px-3 py-2 border border-slate-300 rounded bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-900"
                required
              />
            </div>
            <div className="md:col-span-5">
              <input
                type="text"
                placeholder="Description / Reason (e.g., Blocked external vendor, Malware subnet)"
                value={newDesc}
                onChange={(e) => setNewDesc(e.target.value)}
                className="w-full text-xs font-mono px-3 py-2 border border-slate-300 rounded bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-900"
              />
            </div>
            <div className="md:col-span-3">
              <button
                type="submit"
                disabled={isSubmitting || !newCidr.trim()}
                className="w-full btn-bold-primary py-2 text-xs font-mono flex items-center justify-center space-x-1.5"
                style={{ backgroundColor: isSubmitting ? '#94a3b8' : '#0f172a', color: '#ffffff' }}
              >
                <Plus className="w-4 h-4" />
                <span>{isSubmitting ? "ADDING..." : "ADD RESTRICTION"}</span>
              </button>
            </div>
          </div>
          {feedbackMsg && (
            <p className={`text-xs font-mono m-0 ${feedbackMsg.type === 'error' ? 'text-red-600' : 'text-emerald-700'}`}>
              {feedbackMsg.text}
            </p>
          )}
        </form>

        {/* Restricted Networks List Table */}
        <div className="data-table-container">
          <table className="clean-table">
            <thead>
              <tr>
                <th>Restricted Subnet / IP</th>
                <th>Description / Purpose</th>
                <th>Policy Action</th>
                <th>Enforcement Status</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {restrictedNetworks.length === 0 ? (
                <tr>
                  <td colSpan="5" style={{ textAlign: 'center', padding: '1.5rem', color: '#64748b' }}>
                    No restricted IP subnets configured yet. Add an IP or CIDR block above.
                  </td>
                </tr>
              ) : (
                restrictedNetworks.map((net) => (
                  <tr key={net.id}>
                    <td className="font-mono text-xs font-bold text-slate-900">
                      <div className="flex items-center space-x-1.5">
                        <Globe className="w-3.5 h-3.5 text-slate-500" />
                        <span>{net.network_cidr}</span>
                      </div>
                    </td>
                    <td className="font-mono text-xs text-slate-700">
                      {net.description || 'No description provided'}
                    </td>
                    <td>
                      <span className="badge-clean badge-rose font-mono">
                        {net.action || 'BLOCK'} (AUTO-SEVER)
                      </span>
                    </td>
                    <td>
                      <button
                        onClick={() => handleToggle(net.id)}
                        className={`text-xs font-mono font-bold px-2 py-1 rounded flex items-center space-x-1 border transition-colors ${
                          net.is_active
                            ? 'bg-emerald-50 text-emerald-800 border-emerald-300 hover:bg-emerald-100'
                            : 'bg-slate-100 text-slate-500 border-slate-300 hover:bg-slate-200'
                        }`}
                        title="Click to toggle policy active/inactive"
                      >
                        <Power className="w-3 h-3" />
                        <span>{net.is_active ? 'ENFORCED' : 'DISABLED'}</span>
                      </button>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        onClick={() => handleDelete(net.id, net.network_cidr)}
                        className="text-slate-400 hover:text-red-600 p-1 rounded transition-colors inline-flex items-center"
                        title="Delete restriction policy"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
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
                <th>Threat & Restriction Assessment</th>
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
                  <tr key={idx} className={conn.is_restricted ? 'bg-red-50/60' : ''}>
                    <td className="font-mono text-xs text-slate-700 font-semibold">{conn.laddr}</td>
                    <td className="font-mono text-xs font-bold text-slate-900">{conn.raddr || 'N/A'}</td>
                    <td className="font-mono text-xs font-bold text-slate-600">{conn.type}</td>
                    <td className="font-mono text-xs font-semibold text-slate-800">{conn.pid || '-'}</td>
                    <td>
                      {conn.is_restricted ? (
                        <div className="flex flex-col space-y-0.5">
                          <span className="badge-clean badge-rose font-mono inline-flex items-center space-x-1">
                            <ShieldBan className="w-3 h-3 mr-1" />
                            <span>RESTRICTED IP BLOCKED</span>
                          </span>
                          <span className="text-[10px] text-red-700 font-mono font-semibold">
                            Matched: {conn.matched_network}
                          </span>
                        </div>
                      ) : conn.is_suspicious ? (
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
                      {conn.is_restricted ? (
                        <span className="font-mono text-xs font-bold text-red-800 bg-red-100 px-2 py-0.5 rounded border border-red-300">
                          AUTO-SEVERED
                        </span>
                      ) : (
                        <span className="font-mono text-xs font-bold text-slate-700 bg-slate-100 px-2 py-0.5 rounded border border-slate-300">
                          {conn.status}
                        </span>
                      )}
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
