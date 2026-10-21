import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"
RULES_DIR = BASE_DIR / "rules"
DB_PATH = BASE_DIR / "osentinel.db"

# Risk Assessment Thresholds
RISK_THRESHOLD_LOW = 40.0       # < 40 is LOW (Log only)
RISK_THRESHOLD_HIGH = 70.0      # >= 70 is HIGH (Incident & Containment), 40-69 is MEDIUM (Alert)

# Risk Score Weights: Risk = w_rule * RuleScore + w_anomaly * AnomalyScore + w_class * ClassifierConfidence
WEIGHT_RULE = 0.45
WEIGHT_ANOMALY = 0.35
WEIGHT_CLASSIFIER = 0.20

# Feature Normalization Bounds & Constants
ENTROPY_HIGH_THRESHOLD = 7.2     # Shannon entropy threshold (0.0 to 8.0)
WRITE_RATE_HIGH_THRESHOLD = 50   # Writes/sec threshold
SUSPICIOUS_PORTS = [4444, 1337, 6667, 31337, 8888, 5555, 9999, 4445]
SUSPICIOUS_PATHS = ["/tmp", "/var/tmp", "/dev/shm", "/home/prasana/tmp"]

# System Data Polling Interval (seconds)
POLL_INTERVAL_SEC = 2.0
