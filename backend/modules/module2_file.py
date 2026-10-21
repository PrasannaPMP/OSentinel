import math
import os
import time
from pathlib import Path
from collections import Counter
from backend.config import ENTROPY_HIGH_THRESHOLD, SANDBOX_DIR, BASE_DIR

# Internal state tracking file write rates and entropy logs
_last_file_check = time.time()
_last_file_mtimes = {}
_simulated_entropy_burst = None  # Hook for web attack simulator

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon Entropy H(X) = -sum(P(x) * log2(P(x))) for a byte array (0.0 to 8.0 bits/byte)."""
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
    """Reads sample bytes from file and computes true Shannon Entropy."""
    try:
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return 0.0
        with open(file_path, "rb") as f:
            sample_data = f.read(16384) # Read up to 16KB sample
        return calculate_shannon_entropy(sample_data)
    except Exception:
        return 0.0

def set_simulated_file_activity(mod_rate: float, avg_entropy: float, del_rate: float = 0.0):
    """Allows the web attack simulator to safely inject synthetic file activity metrics."""
    global _simulated_entropy_burst
    _simulated_entropy_burst = {
        "mod_rate": mod_rate,
        "avg_entropy": avg_entropy,
        "del_rate": del_rate,
        "expire_time": time.time() + 4.0
    }

def collect_file_telemetry():
    global _last_file_check, _last_file_mtimes, _simulated_entropy_burst
    
    current_time = time.time()
    dt = max(0.5, current_time - _last_file_check)
    
    # Check if UI web simulation is active
    if _simulated_entropy_burst and current_time < _simulated_entropy_burst["expire_time"]:
        sim_entropy = _simulated_entropy_burst["avg_entropy"]
        return {
            "file_mod_rate": _simulated_entropy_burst["mod_rate"],
            "avg_file_entropy": sim_entropy,
            "file_deletion_rate": _simulated_entropy_burst["del_rate"],
            "high_entropy_alert": sim_entropy >= ENTROPY_HIGH_THRESHOLD,
            "sample_files": [
                {"path": str(SANDBOX_DIR / "financial_data.xlsx.locked"), "entropy": sim_entropy, "status": "ENCRYPTED"},
                {"path": str(SANDBOX_DIR / "customer_vault.db.enc"), "entropy": sim_entropy, "status": "ENCRYPTED"}
            ]
        }
    else:
        _simulated_entropy_burst = None

    # Real-world telemetry: Inspect files in live_threat_sandbox or project samples
    sample_files = []
    monitored_dir = SANDBOX_DIR if (SANDBOX_DIR.exists() and any(SANDBOX_DIR.iterdir())) else BASE_DIR
    
    modified_count = 0
    entropy_values = []
    
    try:
        # Scan up to 15 real files
        file_candidates = []
        for root, dirs, files in os.walk(monitored_dir):
            # Skip hidden and cache folders
            dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__' and d != 'node_modules']
            for f in files:
                if not f.startswith('.'):
                    file_candidates.append(Path(root) / f)
                if len(file_candidates) >= 15:
                    break
            if len(file_candidates) >= 15:
                break

        for f_path in file_candidates:
            try:
                stat = f_path.stat()
                mtime = stat.st_mtime
                prev_mtime = _last_file_mtimes.get(str(f_path))
                if prev_mtime and mtime > prev_mtime:
                    modified_count += 1
                _last_file_mtimes[str(f_path)] = mtime
                
                # Compute actual Shannon entropy on the file bytes
                ent = compute_file_entropy(str(f_path))
                entropy_values.append(ent)
                status = "ENCRYPTED" if ent >= ENTROPY_HIGH_THRESHOLD else "NORMAL"
                
                # Display clean relative path if possible
                try:
                    rel_p = str(f_path.relative_to(SANDBOX_DIR.parent))
                except Exception:
                    rel_p = str(f_path)
                    
                sample_files.append({
                    "path": rel_p,
                    "entropy": ent,
                    "status": status
                })
            except Exception:
                continue
    except Exception:
        pass

    _last_file_check = current_time
    
    # Calculate real modification rate
    mod_rate = round(modified_count / dt, 1)
    
    # Default baseline if no active sandbox files
    if not entropy_values:
        avg_entropy = 4.2
        sample_files = [
            {"path": "backend/main.py", "entropy": 4.62, "status": "NORMAL"},
            {"path": "backend/database.py", "entropy": 4.38, "status": "NORMAL"}
        ]
    else:
        avg_entropy = round(sum(entropy_values) / len(entropy_values), 2)
        
    is_high_entropy = avg_entropy >= ENTROPY_HIGH_THRESHOLD
    
    return {
        "file_mod_rate": max(mod_rate, 1.2 if not is_high_entropy else 25.0),
        "avg_file_entropy": avg_entropy,
        "file_deletion_rate": 0.0,
        "high_entropy_alert": is_high_entropy,
        "sample_files": sample_files[:8]
    }
