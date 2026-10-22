import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

from backend.config import MODELS_DIR
from backend.database import get_db, init_db
from backend.modules.module4_feature_extraction import FEATURE_NAMES

def generate_synthetic_telemetry(num_samples=2500):
    """
    Generates a labelled synthetic dataset of host behaviour.

    Ranges match what the live collectors actually report:
      - cpu_percent: whole-machine CPU, 0-100 (normalised by core count)
      - mem_percent: system RAM usage %, typically 30-90 on a real laptop
      - outbound_conn_count: non-loopback ESTABLISHED sockets (browsers open dozens)
      - data_exfil_kb_sec: machine-wide upload rate in KB/s
    NOTE: this data is synthetic, so classifier accuracy measured on it only shows the
    model can separate the classes as defined here, not real-world detection accuracy.
    """
    rng = np.random.default_rng(42)
    u = rng.uniform

    def mostly_zero(high, n, p_zero=0.85):
        """Real activity counters are exactly 0 most of the time (idle machine)."""
        return np.where(rng.random(n) < p_zero, 0.0, u(0.0, high, n))

    # 1. Normal System Activity (70% of dataset)
    n_normal = int(num_samples * 0.70)
    normal_data = {
        "cpu_percent": u(1.0, 60.0, n_normal),
        "mem_percent": u(25.0, 90.0, n_normal),
        "is_tmp_execution": rng.choice([0.0, 1.0], p=[0.99, 0.01], size=n_normal),
        "file_mod_rate": mostly_zero(3.0, n_normal),
        "avg_file_entropy": u(0.0, 6.5, n_normal),
        "outbound_conn_count": rng.integers(0, 120, size=n_normal),
        "suspicious_port_flag": np.zeros(n_normal),
        "data_exfil_kb_sec": u(0.0, 800.0, n_normal),
        "spawn_rate": mostly_zero(3.0, n_normal, p_zero=0.5),
        "file_deletion_rate": mostly_zero(1.0, n_normal, p_zero=0.95),
        "label": ["Normal"] * n_normal
    }

    # 2. Ransomware Attack Samples (7.5%)
    n_rans = int(num_samples * 0.075)
    rans_data = {
        "cpu_percent": u(30.0, 95.0, n_rans),
        "mem_percent": u(30.0, 90.0, n_rans),
        "is_tmp_execution": rng.choice([0.0, 1.0], p=[0.3, 0.7], size=n_rans),
        "file_mod_rate": u(15.0, 120.0, n_rans),
        "avg_file_entropy": u(7.2, 7.99, n_rans),
        "outbound_conn_count": rng.integers(0, 60, size=n_rans),
        "suspicious_port_flag": np.zeros(n_rans),
        "data_exfil_kb_sec": u(0.0, 300.0, n_rans),
        "spawn_rate": u(0.5, 5.0, n_rans),
        "file_deletion_rate": u(8.0, 45.0, n_rans),
        "label": ["Ransomware"] * n_rans
    }

    # 3. Reverse Shell C2 Samples (7.5%)
    n_c2 = int(num_samples * 0.075)
    c2_data = {
        "cpu_percent": u(2.0, 40.0, n_c2),
        "mem_percent": u(25.0, 90.0, n_c2),
        "is_tmp_execution": rng.choice([0.0, 1.0], p=[0.2, 0.8], size=n_c2),
        "file_mod_rate": mostly_zero(2.0, n_c2),
        "avg_file_entropy": u(0.0, 6.0, n_c2),
        "outbound_conn_count": rng.integers(1, 60, size=n_c2),
        "suspicious_port_flag": np.ones(n_c2),
        "data_exfil_kb_sec": u(5.0, 500.0, n_c2),
        "spawn_rate": u(0.5, 8.0, n_c2),
        "file_deletion_rate": mostly_zero(1.0, n_c2, p_zero=0.95),
        "label": ["Reverse Shell C2"] * n_c2
    }

    # 4. Data Exfiltration Samples (7.5%)
    n_exfil = int(num_samples * 0.075)
    exfil_data = {
        "cpu_percent": u(10.0, 70.0, n_exfil),
        "mem_percent": u(25.0, 90.0, n_exfil),
        "is_tmp_execution": rng.choice([0.0, 1.0], p=[0.5, 0.5], size=n_exfil),
        "file_mod_rate": mostly_zero(15.0, n_exfil, p_zero=0.5),
        "avg_file_entropy": u(3.0, 7.0, n_exfil),
        "outbound_conn_count": rng.integers(5, 150, size=n_exfil),
        "suspicious_port_flag": rng.choice([0.0, 1.0], p=[0.6, 0.4], size=n_exfil),
        "data_exfil_kb_sec": u(1024.0, 15000.0, n_exfil),
        "spawn_rate": u(0.0, 3.0, n_exfil),
        "file_deletion_rate": mostly_zero(1.0, n_exfil, p_zero=0.95),
        "label": ["Data Exfiltration"] * n_exfil
    }

    # 5. CryptoMiner Samples (7.5%)
    n_miner = int(num_samples * 0.075)
    miner_data = {
        "cpu_percent": u(88.0, 100.0, n_miner),
        "mem_percent": u(25.0, 95.0, n_miner),
        "is_tmp_execution": rng.choice([0.0, 1.0], p=[0.2, 0.8], size=n_miner),
        "file_mod_rate": mostly_zero(1.0, n_miner),
        "avg_file_entropy": u(0.0, 6.0, n_miner),
        "outbound_conn_count": rng.integers(1, 60, size=n_miner),
        "suspicious_port_flag": rng.choice([0.0, 1.0], p=[0.8, 0.2], size=n_miner),
        "data_exfil_kb_sec": u(1.0, 200.0, n_miner),
        "spawn_rate": u(3.0, 15.0, n_miner),
        "file_deletion_rate": mostly_zero(1.0, n_miner, p_zero=0.95),
        "label": ["CryptoMiner"] * n_miner
    }

    dfs = [pd.DataFrame(d) for d in [normal_data, rans_data, c2_data, exfil_data, miner_data]]
    dataset = pd.concat(dfs, ignore_index=True).sample(frac=1.0, random_state=42).reset_index(drop=True)
    return dataset


def collect_live_baseline(seconds: int = 120) -> pd.DataFrame:
    """
    Records REAL feature vectors from this machine while it is behaving normally.
    Used to train the Isolation Forest on your own baseline instead of synthetic data.
    Run it while doing normal work (browsing, coding), not while running attacks.
    """
    import time
    from backend.config import POLL_INTERVAL_SEC
    from backend.modules.module1_process import collect_process_telemetry
    from backend.modules.module2_file import collect_file_telemetry
    from backend.modules.module3_network import collect_network_telemetry
    from backend.modules.module4_feature_extraction import extract_feature_vector

    print(f"[OSentinel ML] Recording live baseline for {seconds}s. Use the machine normally...")
    rows = []
    end = time.time() + seconds
    first = True
    while time.time() < end:
        feat = extract_feature_vector(collect_process_telemetry(), collect_file_telemetry(),
                                      collect_network_telemetry())["feature_dict"]
        if not first:  # first poll has no deltas yet
            rows.append({k: feat[k] for k in FEATURE_NAMES})
        first = False
        time.sleep(POLL_INTERVAL_SEC)
    print(f"[OSentinel ML] Collected {len(rows)} live baseline samples.")
    return pd.DataFrame(rows, columns=FEATURE_NAMES)


def train_and_save_models(baseline_seconds: int = 0):
    os.makedirs(MODELS_DIR, exist_ok=True)
    init_db()
    
    print("[OSentinel ML] Generating synthetic security telemetry dataset...")
    df = generate_synthetic_telemetry(3000)
    
    X = df[FEATURE_NAMES]
    y = df["label"]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    
    # 1. Train Unsupervised Isolation Forest (trained on Normal traffic samples)
    print("[OSentinel ML] Training Isolation Forest anomaly detector...")
    X_normal_train = X_train[y_train == "Normal"]
    baseline_source = "synthetic"
    if baseline_seconds > 0:
        live = collect_live_baseline(baseline_seconds)
        if len(live) >= 10:
            X_normal_train = pd.concat([X_normal_train, live], ignore_index=True)
            baseline_source = f"synthetic + {len(live)} live samples"
    iso_forest = IsolationForest(n_estimators=200, contamination=0.02, random_state=42)
    iso_forest.fit(X_normal_train)

    # Calibrate raw scores to 0-100: typical normal behaviour -> ~0,
    # the model's own anomaly threshold -> 50, clearly anomalous -> 100.
    normal_scores = iso_forest.score_samples(X_normal_train)
    anomaly_calibration = {
        "normal_median": float(np.median(normal_scores)),
        "threshold": float(iso_forest.offset_),
    }
    attack_scores = iso_forest.score_samples(X_test[y_test != "Normal"])
    normal_test_scores = iso_forest.score_samples(X_test[y_test == "Normal"])
    iso_detection_rate = float(np.mean(attack_scores < iso_forest.offset_))
    iso_false_positive_rate = float(np.mean(normal_test_scores < iso_forest.offset_))
    print(f"[OSentinel ML] Isolation Forest: detects {iso_detection_rate*100:.1f}% of attack samples, "
          f"{iso_false_positive_rate*100:.1f}% false positives on normal samples")
    
    # 2. Train Supervised Random Forest Classifier
    print("[OSentinel ML] Training Random Forest multi-class threat classifier...")
    rf_classifier = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
    rf_classifier.fit(X_train, y_train)
    
    # Evaluate Classifier
    y_pred = rf_classifier.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')
    
    print(f"[OSentinel ML] Model Evaluation Results:")
    print(f"  - Accuracy:  {acc*100:.2f}%")
    print(f"  - Precision: {prec*100:.2f}%")
    print(f"  - Recall:    {rec*100:.2f}%")
    print(f"  - F1-Score:  {f1*100:.2f}%")
    
    # Save Model Artifacts
    joblib.dump(iso_forest, MODELS_DIR / "isolation_forest.joblib")
    joblib.dump(rf_classifier, MODELS_DIR / "random_forest.joblib")
    
    feature_importances = dict(zip(FEATURE_NAMES, rf_classifier.feature_importances_.round(4).tolist()))
    
    meta_info = {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "feature_importances": feature_importances,
        "labels": list(rf_classifier.classes_),
        "anomaly_calibration": anomaly_calibration,
        "iso_detection_rate": round(iso_detection_rate, 4),
        "iso_false_positive_rate": round(iso_false_positive_rate, 4),
        "training_data": "synthetic (labelled classes)",
        "baseline_source": baseline_source,
        "model_status": "ACTIVE",
    }
    
    joblib.dump(meta_info, MODELS_DIR / "model_metadata.joblib")
    
    # Log metrics to DB
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO ml_metrics (accuracy, precision, recall, f1_score, model_version) VALUES (?, ?, ?, ?, ?)",
        (round(acc, 4), round(prec, 4), round(rec, 4), round(f1, 4), "1.0.0")
    )
    conn.commit()
    conn.close()
    
    print("[OSentinel ML] Model training & artifact export complete!")
    return meta_info

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train OSentinel ML models")
    parser.add_argument("--baseline", type=int, default=0,
                        help="Seconds of REAL normal activity to record and add to the anomaly baseline (e.g. 300)")
    args = parser.parse_args()
    train_and_save_models(baseline_seconds=args.baseline)
