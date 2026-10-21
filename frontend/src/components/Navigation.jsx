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
    <nav className="card-panel p-2 mb-6 flex flex-wrap items-center gap-1.5">
      {tabs.map((tab) => {
        const Icon = tab.icon;
        const isActive = activeTab === tab.id;
        return (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              backgroundColor: isActive ? '#0f172a' : 'transparent',
              color: isActive ? '#ffffff' : '#334155',
              borderColor: isActive ? '#0f172a' : 'transparent',
            }}
            className={`flex items-center space-x-2 px-3.5 py-2.5 rounded-md text-xs font-bold transition-all duration-150 border cursor-pointer ${
              isActive
                ? 'shadow-sm'
                : 'hover:bg-slate-100 hover:text-slate-900'
            }`}
          >
            <Icon className={`w-4 h-4 ${isActive ? 'text-white' : 'text-slate-500'}`} />
            <span>{tab.label}</span>
            {tab.badge > 0 && (
              <span className="px-1.5 py-0.5 rounded-full text-[10px] font-extrabold bg-red-600 text-white leading-none">
                {tab.badge}
              </span>
            )}
          </button>
        );
      })}
    </nav>
  );
}
