import os
import joblib
import numpy as np
import pandas as pd
from backend.config import MODELS_DIR
from backend.modules.module4_feature_extraction import FEATURE_NAMES

_iso_forest = None
_rf_classifier = None
_meta_info = None

def load_ml_models():
    global _iso_forest, _rf_classifier, _meta_info
    iso_path = MODELS_DIR / "isolation_forest.joblib"
    rf_path = MODELS_DIR / "random_forest.joblib"
    meta_path = MODELS_DIR / "model_metadata.joblib"
    
    if os.path.exists(iso_path) and os.path.exists(rf_path):
        try:
            _iso_forest = joblib.load(iso_path)
            _rf_classifier = joblib.load(rf_path)
            if os.path.exists(meta_path):
                _meta_info = joblib.load(meta_path)
            return True
        except Exception:
            return False
    return False

def iso_threshold(raw_score: float) -> float:
    """Fallback mapping for models trained before calibration was stored."""
    return 50.0 + (_iso_forest.offset_ - raw_score) * 200.0


def run_ml_inference(feature_vector: np.ndarray, feature_dict: dict) -> dict:
    global _iso_forest, _rf_classifier, _meta_info
    
    if _iso_forest is None or _rf_classifier is None:
        if not load_ml_models():
            # No model yet: contribute nothing rather than a made-up score
            return {
                "anomaly_score": 0.0,
                "predicted_category": "Normal",
                "confidence": 0.0,
                "top_features": [],
                "model_status": "NOT_TRAINED"
            }
            
    # Wrap feature vector in DataFrame with feature names matching model training
    X_sample = pd.DataFrame([feature_vector], columns=FEATURE_NAMES)
    
    # 1. Unsupervised Anomaly Score via Isolation Forest
    # score_samples returns negative anomaly score (more negative = more anomalous)
    raw_score = _iso_forest.score_samples(X_sample)[0]
    calib = (_meta_info or {}).get("anomaly_calibration")
    if calib and calib["normal_median"] > calib["threshold"]:
        # median normal behaviour -> 0, model threshold -> 50, twice as far -> 100
        span = calib["normal_median"] - calib["threshold"]
        anomaly_score = (calib["normal_median"] - raw_score) / span * 50.0
    else:
        anomaly_score = (iso_threshold(raw_score))
    anomaly_score = max(0.0, min(100.0, anomaly_score))
    
    # 2. Supervised Threat Category Prediction via Random Forest
    probs = _rf_classifier.predict_proba(X_sample)[0]
    best_idx = np.argmax(probs)
    predicted_category = _rf_classifier.classes_[best_idx]
    confidence = float(probs[best_idx])
    
    # 3. Compute Feature Contribution / Importance Breakdown (SHAP-inspired)
    importances = _meta_info.get("feature_importances", {}) if _meta_info else {}
    top_features = []
    for name in FEATURE_NAMES:
        val = feature_dict.get(name, 0.0)
        imp = importances.get(name, 0.1)
        # Highlight non-zero/elevated features
        if val > 0:
            top_features.append({
                "feature": name,
                "value": val,
                "importance": imp,
                "contribution_score": round(val * imp, 2)
            })
    top_features.sort(key=lambda x: x["contribution_score"], reverse=True)
    
    return {
        "anomaly_score": round(anomaly_score, 1),
        "predicted_category": predicted_category,
        "confidence": round(confidence, 3),
        "class_probabilities": {cls: round(float(p), 3) for cls, p in zip(_rf_classifier.classes_, probs)},
        "top_features": top_features[:4],
        "model_status": "ACTIVE"
    }

def get_ml_metrics():
    global _meta_info
    if _meta_info is None:
        load_ml_models()
    # No trained model: report that honestly instead of showing made-up numbers
    return _meta_info or {
        "accuracy": None,
        "precision": None,
        "recall": None,
        "f1_score": None,
        "feature_importances": {},
        "labels": ["Normal", "Ransomware", "Reverse Shell C2", "Data Exfiltration", "CryptoMiner"],
        "model_status": "NOT_TRAINED"
    }
