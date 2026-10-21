import React from 'react';
import { LayoutDashboard, Cpu, HardDrive, Network, AlertTriangle, Zap, BrainCircuit } from 'lucide-react';

export default function Navigation({ activeTab, setActiveTab, openIncidentsCount }) {
  const tabs = [
    { id: 'overview', label: 'Risk Overview', icon: LayoutDashboard },
    { id: 'processes', label: 'Process Monitor', icon: Cpu },
    { id: 'files', label: 'File Entropy', icon: HardDrive },
    { id: 'network', label: 'Network Matrix', icon: Network },
    { id: 'incidents', label: 'Incidents & Triage', icon: AlertTriangle, badge: openIncidentsCount },
    { id: 'simulator', label: 'Attack Simulator', icon: Zap },
    { id: 'ml_metrics', label: 'ML Transparency', icon: BrainCircuit },
  ];

  return (
    <nav className="flex flex-wrap items-center gap-2 mb-6 p-1.5 glass-panel border border-slate-800">
      {tabs.map((tab) => {
        const Icon = tab.icon;
        const isActive = activeTab === tab.id;
        return (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center space-x-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 font-mono ${
              isActive
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-lg shadow-cyan-500/10'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
            <span>{tab.label}</span>
            {tab.badge > 0 && (
              <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-rose-500 text-white animate-pulse">
                {tab.badge}
              </span>
            )}
          </button>
        );
      })}
    </nav>
  );
}
