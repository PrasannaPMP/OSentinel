# 🛡️ OSentinel: Intelligent Host-Based Threat Defense & SOC Dashboard

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-5.0%2B-646CFF.svg)](https://vitejs.dev/)
[![Cross-Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Ubuntu%20%7C%20Windows-green.svg)](#cross-platform-compatibility)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

**OSentinel** is an intelligent, real-time Host-Based Intrusion Detection and Incident Defense Framework (HIDS/EDR). It combines **deterministic security heuristics**, a **2-stage Machine Learning pipeline** (Unsupervised Isolation Forest for anomaly detection + Supervised Random Forest for threat classification), and a **high-contrast SOC dashboard** providing sub-second security telemetry.

---

## 🌟 Key Features

- **🌐 Cross-Platform Telemetry**: Runs natively on **macOS**, **Ubuntu Linux**, and **Windows 10/11**.
- **📊 Shannon Entropy File Analysis**: Calculates real-time byte distribution entropy $H(X)$ to catch ransomware and cryptographic wipes before signatures exist.
- **⚡ Process Behavior & Execution Inspection**: Detects anomalous binaries spawned from temporary/scratch paths (`/tmp`, `/private/tmp`, `%TEMP%`) and sustained CPU usage above **95%**.
- **📡 Network Matrix & Threat Socket Interception**: Flags unauthorized outbound connections to known threat ports (e.g., `4444`, `1337`, `31337`) and measures data exfiltration velocity.
- **🤖 2-Stage Machine Learning Pipeline**:
  - **Stage 1 (Unsupervised)**: Isolation Forest scores system deviation from baseline (0.0 to 1.0).
  - **Stage 2 (Supervised)**: Random Forest classifies specific threat vectors (*Ransomware*, *Reverse Shell C2*, *CryptoMiner*, *Data Exfiltration*).
- **🛡️ Automated Triage & Containment**: Triages incidents into `LOW`, `MEDIUM`, and `HIGH` severity with real-time SQLite persistence and WebSocket broadcasting.
- **🖥️ SOC Operations Center**: Intuitive React + Vite SOC dashboard with real-time risk gauges, interactive process killer, incident audit logs, attack simulator, and ML model explainability.

---

## 🏗️ System Architecture

```mermaid
graph TD
    subgraph Host Telemetry Collectors
        P[Module 1: Process Monitor<br/>CPU > 95%, Spawn Rate, Temp Paths]
        F[Module 2: File Entropy Monitor<br/>Shannon H(X), Mod & Delete Rates]
        N[Module 3: Network Monitor<br/>C2 Threat Ports, Exfiltration KB/s]
    end

    subgraph Feature Extraction & Correlation
        E[Module 4: Feature Vectorizer<br/>10 Normalized Numerical Features]
    end

    P --> E
    F --> E
    N --> E

    subgraph Dual-Engine Analysis
        R[Module 5: Deterministic Rule Engine<br/>Heuristics & Signature Weights]
        ML[Module 6: 2-Stage ML Pipeline<br/>Isolation Forest + Random Forest]
    end

    E --> R
    E --> ML

    subgraph Decision & SOC
        RA[Module 7: Risk Assessment Engine<br/>Composite Score: 0 - 100]
        DB[(SQLite Audit Database)]
        WS[WebSocket Live Streamer]
        SOC[React / Vite SOC Dashboard]
    end

    R --> RA
    ML --> RA
    RA --> DB
    RA --> WS
    WS --> SOC
```

---

## 💻 Cross-Platform Compatibility

OSentinel is engineered from the ground up to operate across all major desktop and server operating systems:

| Feature / Module | macOS | Ubuntu / Linux | Windows 10/11 |
| :--- | :--- | :--- | :--- |
| **Process Inspection** | `psutil` + `/private/tmp` | `psutil` + `/proc` + `/tmp` | `psutil` + Win32 API + `%TEMP%` |
| **High CPU Detection** | Sustained CPU &gt; 95% | Sustained CPU &gt; 95% | Sustained CPU &gt; 95% |
| **File Shannon Entropy** | Dynamic byte analysis | Dynamic byte analysis | Dynamic byte analysis |
| **Network Telemetry** | Non-root I/O + Sockets | Non-root I/O + Sockets | Non-root I/O + Sockets |
| **Auto-Containment** | Safe PID termination | Safe PID termination | Safe Process kill |

---

## 🔬 How to Prove OSentinel Works in Real Life

You can mathematically and practically demonstrate to professors, reviewers, or security teams that OSentinel detects live, real-world threats:

### 1. Real File Entropy Proof (Shannon Entropy $H(X)$)
- **Normal Files**: Plain text, source code, and JSON have non-uniform byte distributions:
  $$\text{Shannon Entropy: } H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i) \approx 3.5 \text{ to } 4.8 \text{ bits/byte}$$
- **Ransomware Encryption**: AES/RSA cryptographic ciphertext produces near-uniform byte randomness:
  $$H(X) \approx 7.92 \text{ to } 8.0 \text{ bits/byte}$$
- **Proof**: When files in `live_threat_sandbox/` are encrypted, OSentinel's `module2_file.py` reads the sample bytes, calculates $H(X) \ge 7.2$, triggers **`RULE-RANSOMWARE-01`**, and flashes the red cryptographic alert in the SOC!

### 2. Real Process Anomaly Proof (Temp Path Execution & CPU &gt; 95%)
- **Malware Behavior**: Attackers drop scripts into scratch directories (`/tmp`, `%TEMP%`) and spin up threads to mine cryptocurrency or perform brute-forcing.
- **Proof**: Executing a worker script inside the OS temp directory immediately causes `module1_process.py` to flag `is_tmp=1`. When CPU usage crosses **95%**, **`RULE-MINER-01`** and **`RULE-EXEC-01`** fire, driving the Isolation Forest anomaly score into critical territory.

### 3. Real Network C2 Threat Port Proof
- **Malware Behavior**: Reverse shells and Command-and-Control beacons commonly dial out to default handler ports (e.g., `4444`, `1337`).
- **Proof**: Opening a local socket connection to `127.0.0.1:4444` is intercepted by `module3_network.py`, setting `suspicious_port_flag=1` and firing **`RULE-C2-SHELL-01`**.

---

## 🚀 Live Real-World Proof of Concept Script

We provide a self-contained demonstration script that tests all three threat vectors on your live machine:

```bash
# Run the automated real-world proof suite
python3 demo_real_life_threat.py
```

### Script Execution Output:
```text
============================================================================
  🛡️  OSentinel: Live Threat & Real-World Proof of Concept Suite
  Compatible with: macOS, Ubuntu Linux, and Windows
============================================================================

[STEP 1: PROVING FILE SHANNON ENTROPY H(X) & RANSOMWARE ENCRYPTION]
  📄 Normal Plaintext File: 'financial_records.txt'
     -> Size: 3650 bytes | Entropy: 4.645 / 8.0 bits/byte (NORMAL)
  🔒 Simulating Ransomware Encryption: 'financial_records.txt.locked'
     -> Size: 8192 bytes | Entropy: 7.978 / 8.0 bits/byte
     -> 🚨 CRITICAL THRESHOLD BREACHED (Threshold: >= 7.2 bits/byte)
     -> ✅ OSentinel Rule Fired: RULE-RANSOMWARE-01

[STEP 2: PROVING PROCESS EXECUTION FROM TEMP & CPU SPIKE > 95%]
  ⚡ Dropped rogue worker script into system temporary directory
  🚀 Launched worker process with PID: 36491
     -> Flag: is_tmp_execution = 1 (Detected!)
     -> Flag: cpu_percent >= 95% (Detected!)
     -> ✅ OSentinel Rule Fired: RULE-EXEC-01 & RULE-MINER-01

[STEP 3: PROVING NETWORK THREAT PORT DETECTION (C2 PORT 4444)]
  📡 Listening on local suspicious C2 threat port: 127.0.0.1:4444
  🚨 Established active connection from 127.0.0.1 to C2 port 4444!
     -> Flag: suspicious_port_flag = 1 (Detected!)
     -> ✅ OSentinel Rule Fired: RULE-C2-SHELL-01
```

---

## ⚙️ Configuration & Safety Notes

| Setting | Default | Purpose |
| :--- | :--- | :--- |
| `OSENTINEL_HOST` | `127.0.0.1` | API binds to localhost only, so other devices on your Wi-Fi cannot call `/api/contain`. Set to `0.0.0.0` only for cloud deploys. |
| `OSENTINEL_CORS_ORIGINS` | `localhost:5173`, `localhost:8000` | Browser origins allowed to call the API. |
| `OSENTINEL_WATCH_DIRS` | *(sandbox only)* | Extra folders to watch for ransomware-style writes (separate with `:` on macOS/Linux, `;` on Windows). |

- **Models train automatically** on first start if `backend/models/` is empty.
- **Train on your own machine's baseline:** `python -m backend.modules.train_models --baseline 300` records 5 minutes of real normal activity and adds it to the Isolation Forest baseline. Do normal work while it records.
- **Simulations never touch real processes.** Simulated entries use negative PIDs and are marked `[SIMULATED]` in alerts and incidents.
- **Browser policy:** only tab renderer processes are terminated, and only after staying above 70% CPU for ~6 seconds (3 polls). The main browser process is alerted on, never killed.
- **Ransomware response** kills only processes that can be linked to the watched folders (open file, working directory, or command line). If none can be identified, OSentinel raises an alert instead of guessing.

---

## ⚡ Quick Start Guide

### 1. Prerequisites
- **Python**: 3.10 or higher
- **Node.js**: v18 or higher with `npm`

### 2. Backend Setup
```bash
# Clone the repository
git clone https://github.com/PrasannaPMP/OSentinel.git
cd OSentinel

# Install Python dependencies
pip install fastapi uvicorn psutil scikit-learn numpy

# Launch the FastAPI backend server (Runs on port 8000)
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
*Backend Swagger Docs*: Available at `http://localhost:8000/docs`

### 3. Frontend SOC Dashboard Setup
```bash
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Start Vite development server (Runs on port 5173)
npm run dev
```
*Frontend SOC Dashboard*: Open your browser to `http://localhost:5173`

---

## 🖥️ SOC Dashboard Navigation

- **Risk Overview**: Real-time 0–100 composite risk gauge, timeline trend chart, active process counters, file entropy, and score breakdown.
- **Process Monitor**: Live inspection of top host processes, execution paths, temporary directory flags, and safe one-click process termination.
- **File Entropy**: Live monitoring of Shannon entropy $H(X)$, write velocity, and sample file cryptographic statuses.
- **Network Matrix**: Active socket descriptors, protocol detection, suspicious port flags, and data exfiltration velocity.
- **Incidents & Triage**: Audit log of all security alerts, root-cause rule evidence, and status management (`OPEN`, `INVESTIGATING`, `CONTAINED`).
- **Attack Simulator**: Safe, non-destructive threat injection sandbox:
  - *Ransomware Mass Encryption* (Entropy H=7.85)
  - *Reverse Shell C2* (Port 4444 outbound)
  - *Data Exfiltration* (14.5 MB/s upload burst)
  - *CryptoMiner CPU Hijack* (Sustained CPU &gt; 95%)
- **ML Transparency**: Real-time evaluation metrics (Accuracy, Precision, Recall, F1) and relative Random Forest feature importance weights.

---

## 📄 License

This project is licensed under the MIT License. Developed for research and educational purposes.
