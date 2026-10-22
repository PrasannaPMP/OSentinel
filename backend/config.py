import os
import sys
import tempfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
MODELS_DIR = BASE_DIR / "models"
RULES_DIR = BASE_DIR / "rules"
DB_PATH = BASE_DIR / "osentinel.db"
SANDBOX_DIR = PROJECT_ROOT / "live_threat_sandbox"

# Ensure directories exist
MODELS_DIR.mkdir(parents=True, exist_ok=True)
RULES_DIR.mkdir(parents=True, exist_ok=True)
SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

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
# 8888 removed: it is Jupyter Notebook's default port and caused constant false alarms.
SUSPICIOUS_PORTS = [4444, 1337, 6667, 31337, 5555, 9999, 4445]

def get_platform_suspicious_paths():
    """Returns cross-platform list of temporary and scratch directories."""
    paths = []
    # 1. Standard OS temp directory
    t = tempfile.gettempdir()
    if t:
        paths.append(t.lower().replace("\\", "/"))
        
    # 2. Windows specific environment paths
    # NOTE: %LOCALAPPDATA% and %APPDATA% are deliberately NOT included. Many normal
    # apps (VS Code user install, Discord, Spotify, Teams, Slack) are installed there,
    # and flagging them would auto-terminate legitimate software.
    if sys.platform.startswith("win"):
        for env_k in ["TEMP", "TMP"]:
            val = os.environ.get(env_k)
            if val:
                paths.append(val.lower().replace("\\", "/"))
        paths.extend(["c:/temp", "c:/windows/temp"])
    # 3. macOS / Linux specific directories
    else:
        paths.extend(["/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp", "/dev/shm"])

    # Deduplicate and normalize
    return list(set(p.rstrip("/") for p in paths if p))

SUSPICIOUS_PATHS = get_platform_suspicious_paths()

# Legitimate software that runs from temp-like locations (e.g. AppImage mounts on Linux).
TEMP_PATH_ALLOWLIST = ["/tmp/.mount_"]


def normalize_path(path: str) -> str:
    return (path or "").replace("\\", "/").lower()


def is_under_path(path: str, base: str) -> bool:
    """True if `path` is `base` itself or inside it (avoids '/tmpfoo' matching '/tmp')."""
    p = normalize_path(path).rstrip("/")
    b = normalize_path(base).rstrip("/")
    return bool(p and b) and (p == b or p.startswith(b + "/"))


def is_suspicious_temp_path(path: str) -> bool:
    p = normalize_path(path)
    if not p or any(p.startswith(a) for a in TEMP_PATH_ALLOWLIST):
        return False
    return any(is_under_path(p, sp) for sp in SUSPICIOUS_PATHS)

# System Data Polling Interval (seconds)
POLL_INTERVAL_SEC = 2.0

# Browser containment policy
BROWSER_TAB_CPU_THRESHOLD = 70.0      # % CPU (per process, single core = 100%)
BROWSER_SUSTAINED_SAMPLES = 3         # must exceed threshold for N consecutive polls (~6s) before kill
TAB_BURST_THRESHOLD = 6               # new renderer processes in one poll window to count as a burst

# Alert/incident de-duplication window (seconds)
INCIDENT_COOLDOWN_SEC = 30.0

# API server binding. Default is localhost-only so other machines on the same
# network cannot call /api/contain. Set OSENTINEL_HOST=0.0.0.0 to expose it.
API_HOST = os.environ.get("OSENTINEL_HOST", "127.0.0.1")
CORS_ORIGINS = [
    o.strip() for o in os.environ.get(
        "OSENTINEL_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8000,http://127.0.0.1:8000"
    ).split(",") if o.strip()
]
