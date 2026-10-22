import math
import os
import time
from pathlib import Path
from collections import Counter
from backend.config import ENTROPY_HIGH_THRESHOLD, SANDBOX_DIR

# Directories watched for ransomware-style activity. The sandbox is always watched;
# extra folders can be added with OSENTINEL_WATCH_DIRS (separated by os.pathsep).
WATCH_DIRS = [SANDBOX_DIR] + [
    Path(p) for p in os.environ.get("OSENTINEL_WATCH_DIRS", "").split(os.pathsep) if p.strip()
]
MAX_FILES_SCANNED = 500
SKIP_DIRS = {"__pycache__", "node_modules"}

# Internal state
_last_file_check = None
_known_files = {}        # {path: (mtime, size, entropy)}
_initialised = False
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
        if not os.path.isfile(file_path):
            return 0.0
        with open(file_path, "rb") as f:
            sample_data = f.read(16384)  # Read up to 16KB sample
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


def _scan_watch_dirs():
    """Returns ({path: (mtime, size)}, truncated_flag)."""
    found = {}
    for base in WATCH_DIRS:
        if not base.exists():
            continue
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in SKIP_DIRS]
            for f in files:
                if f.startswith('.'):
                    continue
                p = os.path.join(root, f)
                try:
                    st = os.stat(p)
                    found[p] = (st.st_mtime, st.st_size)
                except OSError:
                    continue
                if len(found) >= MAX_FILES_SCANNED:
                    return found, True
    return found, False


def _display_path(p: str) -> str:
    try:
        return str(Path(p).relative_to(SANDBOX_DIR.parent))
    except Exception:
        return p


def collect_file_telemetry():
    global _last_file_check, _known_files, _initialised, _simulated_entropy_burst

    current_time = time.time()

    # Web simulation (synthetic numbers only, no real files touched)
    if _simulated_entropy_burst and current_time < _simulated_entropy_burst["expire_time"]:
        sim_entropy = _simulated_entropy_burst["avg_entropy"]
        return {
            "file_mod_rate": _simulated_entropy_burst["mod_rate"],
            "avg_file_entropy": sim_entropy,
            "file_deletion_rate": _simulated_entropy_burst["del_rate"],
            "high_entropy_alert": sim_entropy >= ENTROPY_HIGH_THRESHOLD,
            "changed_files": [],
            "watch_dirs": [str(d) for d in WATCH_DIRS],
            "simulated": True,
            "sample_files": [
                {"path": str(SANDBOX_DIR / "financial_data.xlsx.locked"), "entropy": sim_entropy, "status": "ENCRYPTED"},
                {"path": str(SANDBOX_DIR / "customer_vault.db.enc"), "entropy": sim_entropy, "status": "ENCRYPTED"}
            ]
        }
    _simulated_entropy_burst = None

    dt = max(0.5, current_time - _last_file_check) if _last_file_check else 1.0
    current, truncated = _scan_watch_dirs()

    changed = []      # files created or modified since last poll
    new_state = {}
    for path, (mtime, size) in current.items():
        prev = _known_files.get(path)
        if prev and prev[0] == mtime and prev[1] == size:
            new_state[path] = prev  # unchanged: reuse cached entropy
            continue
        ent = compute_file_entropy(path)
        new_state[path] = (mtime, size, ent)
        if _initialised:
            changed.append(path)

    deleted_count = 0
    if _initialised and not truncated:
        deleted_count = len(set(_known_files) - set(current))

    _known_files = new_state
    _initialised = True
    _last_file_check = current_time

    mod_rate = round(len(changed) / dt, 1)
    del_rate = round(deleted_count / dt, 1)

    all_entropies = [v[2] for v in new_state.values()]
    changed_entropies = [new_state[p][2] for p in changed]

    # The ransomware signal is the entropy of files being WRITTEN NOW, not files that
    # already exist (zip/jpg/pdf are naturally high-entropy and are not an attack).
    if changed_entropies:
        avg_entropy = round(sum(changed_entropies) / len(changed_entropies), 2)
        is_high_entropy = avg_entropy >= ENTROPY_HIGH_THRESHOLD
    else:
        avg_entropy = round(sum(all_entropies) / len(all_entropies), 2) if all_entropies else 0.0
        is_high_entropy = False

    # Show recently changed files first, then the rest
    ordered = changed + [p for p in new_state if p not in changed]
    sample_files = [{
        "path": _display_path(p),
        "entropy": new_state[p][2],
        "status": "ENCRYPTED" if new_state[p][2] >= ENTROPY_HIGH_THRESHOLD else "NORMAL",
    } for p in ordered[:8]]

    return {
        "file_mod_rate": mod_rate,
        "avg_file_entropy": avg_entropy,
        "file_deletion_rate": del_rate,
        "high_entropy_alert": is_high_entropy,
        "changed_files": changed[:50],
        "watch_dirs": [str(d) for d in WATCH_DIRS],
        "files_scanned": len(current),
        "simulated": False,
        "sample_files": sample_files
    }
