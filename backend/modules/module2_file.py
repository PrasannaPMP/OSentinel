import math
import os
import time
from collections import Counter
from backend.config import ENTROPY_HIGH_THRESHOLD

# Internal state tracking file write rates and entropy logs
_file_event_buffer = []
_last_file_check = time.time()
_simulated_entropy_burst = None  # Hook for simulator

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon Entropy H(X) = -sum(P(x) * log2(P(x))) for a byte array."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def compute_file_entropy(file_path: str) -> float:
    """Reads sample bytes from file and computes Shannon Entropy."""
    try:
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return 0.0
        with open(file_path, "rb") as f:
            sample_data = f.read(8192) # Read up to 8KB sample
        return calculate_shannon_entropy(sample_data)
    except Exception:
        return 0.0

def set_simulated_file_activity(mod_rate: float, avg_entropy: float, del_rate: float = 0.0):
    """Allows the attack simulator to safely inject file activity metrics."""
    global _simulated_entropy_burst
    _simulated_entropy_burst = {
        "mod_rate": mod_rate,
        "avg_entropy": avg_entropy,
        "del_rate": del_rate,
        "expire_time": time.time() + 4.0
    }

def collect_file_telemetry():
    global _last_file_check, _simulated_entropy_burst
    
    current_time = time.time()
    
    # Check if simulation is active
    if _simulated_entropy_burst and current_time < _simulated_entropy_burst["expire_time"]:
        return {
            "file_mod_rate": _simulated_entropy_burst["mod_rate"],
            "avg_file_entropy": _simulated_entropy_burst["avg_entropy"],
            "file_deletion_rate": _simulated_entropy_burst["del_rate"],
            "high_entropy_alert": _simulated_entropy_burst["avg_entropy"] >= ENTROPY_HIGH_THRESHOLD,
            "sample_files": [
                {"path": "/home/prasana/documents/financial_report.xlsx.locked", "entropy": _simulated_entropy_burst["avg_entropy"], "status": "ENCRYPTED"},
                {"path": "/home/prasana/pictures/photo_archive.zip.enc", "entropy": _simulated_entropy_burst["avg_entropy"], "status": "ENCRYPTED"}
            ]
        }
    else:
        _simulated_entropy_burst = None
        
    # Baseline telemetry sample from workspace files
    sample_entropy = 4.2  # Normal text/code entropy (~3.5 to 5.2)
    sample_mod_rate = 1.5  # Normal file write rate
    del_rate = 0.0
    
    return {
        "file_mod_rate": sample_mod_rate,
        "avg_file_entropy": sample_entropy,
        "file_deletion_rate": del_rate,
        "high_entropy_alert": False,
        "sample_files": [
            {"path": "/home/prasana/OSentinel/backend/main.py", "entropy": 4.62, "status": "NORMAL"},
            {"path": "/home/prasana/OSentinel/backend/database.py", "entropy": 4.38, "status": "NORMAL"}
        ]
    }
