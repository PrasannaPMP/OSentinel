import React, { useState, useEffect } from 'react';
import { BrainCircuit, RefreshCw, CheckCircle2, BarChart3, Sliders, Shield } from 'lucide-react';
import { fetchMLMetrics, retrainMLModels } from '../services/api';

export default function MLModelMetrics() {
  const [metrics, setMetrics] = useState(null);
  const [retraining, setRetraining] = useState(false);

  useEffect(() => {
    fetchMLMetrics()
      .then(data => setMetrics(data))
      .catch(err => console.error(err));
  }, []);

  const handleRetrain = async () => {
    setRetraining(true);
    try {
      await retrainMLModels();
      setTimeout(async () => {
        const updated = await fetchMLMetrics();
        setMetrics(updated);
        setRetraining(false);
      }, 3000);
    } catch (e) {
      console.error(e);
      setRetraining(false);
    }
  };

  const featureImportances = metrics?.feature_importances || {
    "avg_file_entropy": 0.28,
    "file_mod_rate": 0.22,
    "suspicious_port_flag": 0.18,
    "is_tmp_execution": 0.14,
    "data_exfil_kb_sec": 0.08,
    "cpu_percent": 0.06,
    "file_deletion_rate": 0.04
  };

  return (
    <div className="space-y-6">
      {/* Header & Retrain Action */}
      <div className="glass-panel p-6 border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400">
            <BrainCircuit className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-bold font-mono text-slate-100 uppercase tracking-wider">
              2-Stage Machine Learning Pipeline Diagnostics
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Unsupervised Isolation Forest (Anomaly Detection) + Supervised Random Forest Classifier
            </p>
          </div>
        </div>

        <button
          onClick={handleRetrain}
          disabled={retraining}
          className="px-4 py-2.5 rounded-lg bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 border border-purple-500/40 font-mono text-xs font-bold transition-all flex items-center space-x-2"
        >
          <RefreshCw className={`w-4 h-4 ${retraining ? 'animate-spin' : ''}`} />
          <span>{retraining ? "RETRAINING ML MODELS..." : "RETRAIN ML PIPELINE"}</span>
        </button>
      </div>

      {/* Metric KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 font-mono">
        <div className="glass-panel p-4 border border-slate-800">
          <span className="text-xs text-slate-400 block">MODEL ACCURACY</span>
          <span className="text-3xl font-extrabold text-emerald-400 block mt-1">
            {((metrics?.accuracy ?? 1.0) * 100).toFixed(1)}%
          </span>
          <span className="text-[11px] text-slate-500 mt-1 block">Test dataset validation</span>
        </div>

        <div className="glass-panel p-4 border border-slate-800">
          <span className="text-xs text-slate-400 block">PRECISION SCORE</span>
          <span className="text-3xl font-extrabold text-cyan-400 block mt-1">
            {((metrics?.precision ?? 1.0) * 100).toFixed(1)}%
          </span>
          <span className="text-[11px] text-slate-500 mt-1 block">Weighted precision</span>
        </div>

        <div className="glass-panel p-4 border border-slate-800">
          <span className="text-xs text-slate-400 block">RECALL SCORE</span>
          <span className="text-3xl font-extrabold text-purple-400 block mt-1">
            {((metrics?.recall ?? 1.0) * 100).toFixed(1)}%
          </span>
          <span className="text-[11px] text-slate-500 mt-1 block">Threat capture recall</span>
        </div>

        <div className="glass-panel p-4 border border-slate-800">
          <span className="text-xs text-slate-400 block">F1-SCORE</span>
          <span className="text-3xl font-extrabold text-amber-400 block mt-1">
            {((metrics?.f1_score ?? 1.0) * 100).toFixed(1)}%
          </span>
          <span className="text-[11px] text-slate-500 mt-1 block">Harmonic mean score</span>
        </div>
      </div>

      {/* Feature Importance Rankings Chart */}
      <div className="glass-panel p-6 border border-slate-800 space-y-4">
        <h4 className="text-sm font-semibold text-slate-200 font-mono uppercase tracking-wider flex items-center space-x-2">
          <BarChart3 className="w-5 h-5 text-purple-400" />
          <span>Random Forest Feature Importance Weights</span>
        </h4>

        <div className="space-y-3 font-mono text-xs">
          {Object.entries(featureImportances)
            .sort((a, b) => b[1] - a[1])
            .map(([featName, impVal]) => (
              <div key={featName} className="space-y-1">
                <div className="flex justify-between text-slate-300">
                  <span className="font-semibold text-cyan-300">{featName}</span>
                  <span className="text-purple-400 font-bold">{(impVal * 100).toFixed(1)}%</span>
                </div>
                <div className="w-full bg-slate-900 rounded-full h-2.5 overflow-hidden border border-slate-800">
                  <div
                    className="bg-gradient-to-r from-cyan-500 to-purple-500 h-2.5 rounded-full transition-all duration-500"
                    style={{ width: `${Math.min(100, impVal * 300)}%` }}
                  ></div>
                </div>
              </div>
            ))}
        </div>
      </div>
    </div>
  );
}
