import os
import sys
import time
import math
import collections
from pathlib import Path
import pandas as pd
import numpy as np

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import streamlit as st
except ImportError:
    print("Streamlit is not installed in the local environment. Install it via 'pip install streamlit'.")
    sys.exit(0)

# Import OSentinel Modules
from backend.database import init_db, get_restricted_networks, add_restricted_network, delete_restricted_network, toggle_restricted_network, get_incidents, get_alerts
from backend.modules.module1_process import collect_process_telemetry
from backend.modules.module2_file import collect_file_telemetry, calculate_shannon_entropy, compute_file_entropy
from backend.modules.module3_network import collect_network_telemetry, match_restricted_ip
from backend.modules.module4_feature_extraction import extract_feature_vector
from backend.modules.module5_rule_engine import evaluate_rules
from backend.modules.module6_ml_engine import run_ml_inference, load_ml_models
from backend.modules.module7_risk_assessment import calculate_risk_score, triage_and_respond, terminate_process_safe
from backend.modules.attack_simulator import trigger_attack_simulation, get_active_simulation

# Page Configuration
st.set_page_config(
    page_title="OSentinel | Host Threat Defense",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom High-End Styling
st.markdown("""
<style>
    .metric-card {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 18px;
        color: white;
    }
    .metric-title {
        font-size: 0.75rem;
        font-family: monospace;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 800;
        font-family: monospace;
        margin-top: 4px;
        color: #f8fafc;
    }
    .badge-high {
        background-color: #ef4444;
        color: white;
        padding: 4px 10px;
        border-radius: 6px;
        font-family: monospace;
        font-size: 0.75rem;
        font-weight: bold;
    }
    .badge-clean {
        background-color: #10b981;
        color: white;
        padding: 4px 10px;
        border-radius: 6px;
        font-family: monospace;
        font-size: 0.75rem;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Initialize Database & ML Models
init_db()
load_ml_models()

# Sidebar
st.sidebar.image("https://raw.githubusercontent.com/PrasannaPMP/OSentinel/main/frontend/public/favicon.svg", width=48) if False else None
st.sidebar.title("🛡️ OSentinel HIDS")
st.sidebar.caption("Intelligent Host-Based Threat Defense Framework")

nav_choice = st.sidebar.radio(
    "Navigation Console",
    [
        "⚡ SOC Overview & Risk",
        "📄 File Shannon Entropy Analyzer",
        "⚙️ Process Telemetry & Rogue Kill",
        "🌐 Network & IP Firewall Policy",
        "🚀 Safe Threat Simulator",
        "🤖 2-Stage ML Explainability"
    ]
)

st.sidebar.divider()
st.sidebar.markdown("**Engine Status:** `ONLINE (Sub-second)`")
st.sidebar.markdown("**Protection:** `Host Kernel + ML + Rules`")

# Helper function to gather real pipeline snapshot
def get_pipeline_snapshot():
    proc = collect_process_telemetry()
    file_data = collect_file_telemetry()
    net = collect_network_telemetry()
    feat_out = extract_feature_vector(proc, file_data, net)
    feat_dict = feat_out["feature_dict"]
    rules = evaluate_rules(feat_dict)
    ml = run_ml_inference(feat_out["vector"], feat_dict)
    risk = calculate_risk_score(rules, ml)
    triage = triage_and_respond(proc, file_data, net, rules, ml, risk)
    return proc, file_data, net, rules, ml, risk, triage

# -----------------------------------------------------------------------------
# TAB 1: SOC OVERVIEW & RISK GAUGE
# -----------------------------------------------------------------------------
if nav_choice == "⚡ SOC Overview & Risk":
    st.subheader("⚡ Real-Time Security Operations Center (SOC) Telemetry")
    
    proc, file_data, net, rules, ml, risk, triage = get_pipeline_snapshot()
    risk_score = risk.get("risk_score", 0.0)
    severity = risk.get("severity", "LOW")
    threat_cat = risk.get("threat_category", "Normal")
    
    # 4 Metric Cards
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">COMPOSITE RISK SCORE</div>
            <div class="metric-value" style="color: {'#ef4444' if severity == 'HIGH' else ('#f59e0b' if severity == 'MEDIUM' else '#10b981')}">{risk_score} / 100</div>
            <small style="color: #94a3b8;">Severity: {severity}</small>
        </div>
        """, unsafe_allow_html=True)
        
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">PREDICTED THREAT VECTOR</div>
            <div class="metric-value" style="color: {'#ef4444' if threat_cat != 'Normal' else '#10b981'}; font-size: 1.4rem;">{threat_cat}</div>
            <small style="color: #94a3b8;">2-Stage ML Classifier</small>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">ACTIVE SOCKETS & RESTRICTIONS</div>
            <div class="metric-value">{net.get('outbound_conn_count', 0)}</div>
            <small style="color: #94a3b8;">Restricted IP Flag: {net.get('restricted_ip_flag', 0)}</small>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">FILE SHANNON ENTROPY H(X)</div>
            <div class="metric-value">{file_data.get('avg_file_entropy', 0.0)} <span style="font-size: 0.9rem;">bits/byte</span></div>
            <small style="color: #94a3b8;">High Entropy Alert: {file_data.get('high_entropy_alert', False)}</small>
        </div>
        """, unsafe_allow_html=True)

    st.write("")
    st.write("")
    
    # Risk Breakdown & Triage Action
    b_col1, b_col2 = st.columns([1, 1])
    with b_col1:
        st.markdown("#### ⚖️ Risk Score Component Breakdown")
        breakdown = risk.get("score_breakdown", {})
        df_breakdown = pd.DataFrame({
            "Component": ["Rule Engine (45%)", "Isolation Forest Anomaly (35%)", "Random Forest Classifier (20%)"],
            "Weighted Score": [breakdown.get("rule_component", 0.0), breakdown.get("anomaly_component", 0.0), breakdown.get("classifier_component", 0.0)]
        })
        st.bar_chart(df_breakdown.set_index("Component"))

    with b_col2:
        st.markdown("#### 🚨 Automated Triage & Containment Status")
        st.info(f"**Recommended Action:** `{triage.get('response_action', 'LOG')}`")
        if triage.get("terminated_count", 0) > 0:
            st.error(f"**Auto-Terminated Rogue Workloads:** {triage.get('terminated_details')}")
        else:
            st.success("✅ Host operating normally. No active runaway processes or unauthorized network sockets.")

# -----------------------------------------------------------------------------
# TAB 2: FILE SHANNON ENTROPY ANALYZER
# -----------------------------------------------------------------------------
elif nav_choice == "📄 File Shannon Entropy Analyzer":
    st.subheader("📄 Shannon Entropy Analysis Engine (Ransomware Detection)")
    st.markdown("""
    **Shannon Entropy Formula:**
    $$H(X) = -\\sum_{i=1}^{n} P(x_i) \\log_2 P(x_i)$$
    - **Scale:** $0.0$ to $8.0$ bits/byte.
    - **Plaintext & Source Code:** $\\approx 3.5 - 4.8$ bits/byte.
    - **Encrypted Ransomware Payload:** $\\approx 7.8 - 8.0$ bits/byte (Trigger threshold $\\ge 7.2$).
    """)

    st.divider()
    st.markdown("#### 🧪 Interactive File Entropy Tester")
    
    uploaded_file = st.file_uploader("Upload any file to calculate Shannon Entropy live:", type=None)
    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        ent = calculate_shannon_entropy(file_bytes)
        st.metric("Calculated Shannon Entropy", f"{ent} / 8.0 bits/byte")
        if ent >= 7.2:
            st.error("🚨 HIGH ENTROPY DETECTED! File payload exhibits cryptographic randomness characteristic of Ransomware (AES/RSA).")
        else:
            st.success("✅ NORMAL / LOW ENTROPY. Byte frequency exhibits standard predictable plaintext distribution.")
            
        # Byte distribution chart
        counts = collections.Counter(file_bytes[:4096])
        df_counts = pd.DataFrame({"Byte (0-255)": list(counts.keys()), "Frequency": list(counts.values())})
        st.bar_chart(df_counts.set_index("Byte (0-255)"))

    st.write("")
    st.markdown("#### 📁 Test Live Sandbox Files")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Calculate Entropy for 'financial_records.txt' (Plaintext)"):
            sample_path = PROJECT_ROOT / "live_threat_sandbox" / "financial_records.txt"
            if sample_path.exists():
                ent = compute_file_entropy(str(sample_path))
                st.success(f"Plaintext File Entropy: **{ent} bits/byte** (SAFE)")
    with c2:
        if st.button("Calculate Entropy for 'financial_records.txt.locked' (Encrypted)"):
            sample_path = PROJECT_ROOT / "live_threat_sandbox" / "financial_records.txt.locked"
            if sample_path.exists():
                ent = compute_file_entropy(str(sample_path))
                st.error(f"Encrypted File Entropy: **{ent} bits/byte** (CRITICAL RANSOMWARE THRESHOLD)")

# -----------------------------------------------------------------------------
# TAB 3: PROCESS TELEMETRY & ROGUE KILL
# -----------------------------------------------------------------------------
elif nav_choice == "⚙️ Process Telemetry & Rogue Kill":
    st.subheader("⚙️ Live Host Process Telemetry & Rogue Kill Policy")
    proc = collect_process_telemetry()
    processes = proc.get("processes", [])
    
    st.markdown(f"**Total Process Count:** `{proc.get('process_count')}` | **Spawn Velocity:** `{proc.get('spawn_rate')}/sec` | **Scratch/Temp Executables:** `{proc.get('tmp_execution_count')}`")
    
    if processes:
        df_procs = pd.DataFrame(processes)[["pid", "name", "cpu_percent", "memory_percent", "is_tmp", "is_browser", "is_ide"]]
        df_procs.rename(columns={"is_tmp": "In Scratch Path", "is_browser": "Browser Tab", "is_ide": "AntiGravity (Immune)"}, inplace=True)
        st.dataframe(df_procs, use_container_width=True)

# -----------------------------------------------------------------------------
# TAB 4: NETWORK & RESTRICTED IP FIREWALL POLICY
# -----------------------------------------------------------------------------
elif nav_choice == "🌐 Network & IP Firewall Policy":
    st.subheader("🌐 Network Matrix & IP Access Restriction Policy")
    net = collect_network_telemetry()
    
    st.markdown("#### 🛡️ Configured Restricted IP Subnets (Auto-Sever & Contain)")
    restr_nets = get_restricted_networks()
    if restr_nets:
        df_nets = pd.DataFrame(restr_nets)[["id", "network_cidr", "description", "action", "is_active", "created_at"]]
        st.dataframe(df_nets, use_container_width=True)
        
    st.write("")
    st.markdown("##### ➕ Restrict New IP / Subnet")
    with st.form("add_net_form"):
        new_cidr = st.text_input("IP Address or CIDR block (e.g., 198.51.100.0/24 or 192.168.1.100)")
        new_desc = st.text_input("Description / Reason (e.g., Suspicious External Subnet)")
        submitted = st.form_submit_button("Add Restriction Rule")
        if submitted and new_cidr:
            import ipaddress
            try:
                ipaddress.ip_network(new_cidr.strip(), strict=False)
                add_restricted_network(new_cidr.strip(), new_desc.strip(), "BLOCK")
                st.success(f"Added {new_cidr} to restricted firewall policy!")
                st.rerun()
            except ValueError as e:
                st.error(f"Invalid IP / CIDR format: {e}")

    st.write("")
    st.markdown("#### 📡 Intercepted Sockets Matrix")
    conns = net.get("connections", [])
    if conns:
        df_conns = pd.DataFrame(conns)[["laddr", "raddr", "type", "status", "pid", "is_suspicious", "is_restricted"]]
        st.dataframe(df_conns, use_container_width=True)

# -----------------------------------------------------------------------------
# TAB 5: ATTACK SIMULATOR
# -----------------------------------------------------------------------------
elif nav_choice == "🚀 Safe Threat Simulator":
    st.subheader("🚀 Safe Threat Simulation Sandbox")
    st.markdown("Execute safe in-memory threat simulations to test real-time detection, Isolation Forest anomaly scoring, and automated containment:")
    
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("### 🔒 Ransomware")
        st.caption("Rapid file write velocity (85/s) with Shannon Entropy H=7.85 bits/byte.")
        if st.button("Simulate Ransomware"):
            res = trigger_attack_simulation("RANSOMWARE")
            st.warning(res["message"])
            
    with c2:
        st.markdown("### 📡 Reverse Shell C2")
        st.caption("Outbound connection to threat port 4444 from /tmp.")
        if st.button("Simulate Reverse Shell"):
            res = trigger_attack_simulation("REVERSE_SHELL")
            st.warning(res["message"])

    with c3:
        st.markdown("### 🚫 Restricted IP Access")
        st.caption("Socket to restricted subnet 198.51.100.45:8080 (RFC 5737).")
        if st.button("Simulate Restricted Network"):
            res = trigger_attack_simulation("RESTRICTED_NETWORK")
            st.warning(res["message"])

    st.write("")
    c4, c5, _ = st.columns(3)
    with c4:
        st.markdown("### 📤 Data Exfiltration")
        st.caption("High throughput outbound socket stream (14.5 MB/s).")
        if st.button("Simulate Data Exfil"):
            res = trigger_attack_simulation("EXFILTRATION")
            st.warning(res["message"])

    with c5:
        st.markdown("### ⚡ CryptoMiner")
        st.caption("CPU spike to 98.5% (>95% threshold) with rapid spawn rate.")
        if st.button("Simulate CryptoMiner"):
            res = trigger_attack_simulation("CRYPTOMINER")
            st.warning(res["message"])

# -----------------------------------------------------------------------------
# TAB 6: 2-STAGE ML EXPLAINABILITY
# -----------------------------------------------------------------------------
elif nav_choice == "🤖 2-Stage ML Explainability":
    st.subheader("🤖 2-Stage Machine Learning Pipeline Explainability")
    st.markdown("""
    - **Stage 1 (Unsupervised Anomaly Scoring):** Isolation Forest measures host behavior divergence.
    - **Stage 2 (Supervised Threat Classification):** Random Forest classifies into *Normal*, *Ransomware*, *Reverse Shell C2*, *CryptoMiner*, or *Data Exfiltration*.
    """)
    
    proc, file_data, net, rules, ml, risk, triage = get_pipeline_snapshot()
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Isolation Forest Anomaly Score", f"{ml.get('anomaly_score', 0.0)} / 100")
        st.metric("Random Forest Prediction", f"{ml.get('predicted_category', 'Normal')}")
        st.metric("Prediction Confidence", f"{round(ml.get('confidence', 0.0) * 100, 1)}%")

    with col2:
        st.markdown("#### Feature Importances")
        top_feats = ml.get("top_features", [])
        if top_feats:
            df_feats = pd.DataFrame(top_feats)
            st.dataframe(df_feats, use_container_width=True)
