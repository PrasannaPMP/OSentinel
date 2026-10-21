import psutil
import time
import os
import sys
from backend.config import SUSPICIOUS_PATHS

_last_process_count = 0
_last_sample_time = time.time()
_simulated_proc_activity = None

BROWSER_KEYWORDS = ["safari", "chrome", "google chrome", "firefox", "msedge", "brave", "webkit"]
IDE_KEYWORDS = ["antigravity", "antigravity-ide", "electron", "code", "cursor", "vscode"]
TRUSTED_PREFIXES = ["/applications", "/usr", "/system", "/library", "c:/program files", "c:/windows/system32"]

def set_simulated_process_activity(total_cpu: float = 98.4, spawn_rate: float = 12.0, is_tmp: bool = True):
    """Allows safe injection of elevated CPU spikes (>95%) and spawn velocity for threat simulations."""
    global _simulated_proc_activity
    _simulated_proc_activity = {
        "total_cpu": total_cpu,
        "spawn_rate": spawn_rate,
        "is_tmp": is_tmp,
        "expire_time": time.time() + 4.0
    }

def collect_process_telemetry():
    global _last_process_count, _last_sample_time, _simulated_proc_activity
    
    processes = []
    tmp_execution_count = 0
    browser_high_cpu_count = 0
    total_cpu = 0.0
    total_mem = 0.0
    
    current_time = time.time()
    dt = max(0.1, current_time - _last_sample_time)
    
    # Check if a simulation hook is currently active
    is_sim_active = bool(_simulated_proc_activity and current_time < _simulated_proc_activity["expire_time"])
    if not is_sim_active:
        _simulated_proc_activity = None
    
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_percent', 'username']):
        try:
            info = proc.info
            pid = info['pid']
            name = info['name'] or f"proc_{pid}"
            name_lower = name.lower()
            exe = (info['exe'] or "").replace("\\", "/").lower()
            cpu = info['cpu_percent'] or 0.0
            mem = info['memory_percent'] or 0.0
            raw_cmdline = " ".join(info['cmdline']) if info['cmdline'] else name
            cmdline_normalized = raw_cmdline.replace("\\", "/").lower()
            
            is_browser = any(b in name_lower or b in cmdline_normalized for b in BROWSER_KEYWORDS)
            is_ide = any(i in name_lower or i in cmdline_normalized for i in IDE_KEYWORDS)
            
            # Browser threshold 70%, Antigravity threshold 95%
            if is_browser and cpu >= 70.0:
                browser_high_cpu_count += 1
            
            # Accurate check: ONLY flag as temp execution if the EXECUTABLE itself or target script was spawned from temp
            # Do NOT flag just because a program passes a temp path argument (e.g. --parent_pipe_path /var/.../T/...)
            is_tmp = False
            is_trusted_exe = any(exe.startswith(prefix) for prefix in TRUSTED_PREFIXES)
            
            if not is_ide and not is_trusted_exe:
                for sp in SUSPICIOUS_PATHS:
                    sp_norm = sp.replace("\\", "/").lower()
                    if exe.startswith(sp_norm):
                        is_tmp = True
                        break
                    # Check first arguments (e.g. python /tmp/malware.py)
                    parts = raw_cmdline.split()
                    if len(parts) > 1 and parts[1].replace("\\", "/").lower().startswith(sp_norm):
                        is_tmp = True
                        break
                    elif parts and parts[0].replace("\\", "/").lower().startswith(sp_norm):
                        is_tmp = True
                        break
            
            # Flag obvious threat simulation / test payloads
            if "osentinel_rogue" in cmdline_normalized or "xmrig" in cmdline_normalized or "nc_shell" in cmdline_normalized:
                is_tmp = True
                
            if is_tmp:
                tmp_execution_count += 1
                
            total_cpu += cpu
            total_mem += mem
            
            processes.append({
                "pid": pid,
                "ppid": info['ppid'],
                "name": name,
                "exe": info['exe'] or "",
                "cmdline": raw_cmdline,
                "cpu_percent": round(cpu, 1),
                "memory_percent": round(mem, 1),
                "user": info['username'] or "system",
                "is_tmp": is_tmp,
                "is_browser": is_browser,
                "is_ide": is_ide
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, PermissionError):
            continue
            
    current_count = len(processes)
    spawn_velocity = max(0.0, (current_count - _last_process_count) / dt) if _last_process_count > 0 else 0.0
    _last_process_count = current_count
    _last_sample_time = current_time
    
    # If simulation is active, inject a rogue high-CPU process and elevate total CPU above 95%
    if is_sim_active:
        sim_cpu = _simulated_proc_activity["total_cpu"]
        sim_spawn = _simulated_proc_activity["spawn_rate"]
        tmp_execution_count = max(1, tmp_execution_count)
        total_cpu = max(sim_cpu, total_cpu)
        spawn_velocity = max(sim_spawn, spawn_velocity)
        
        # Inject top malicious worker process with >95% CPU consumption
        processes.insert(0, {
            "pid": 69420,
            "ppid": 1,
            "name": "xmrig_crypto_miner",
            "exe": "/tmp/xmrig_miner" if sys.platform != "win32" else "C:/Windows/Temp/xmrig_miner.exe",
            "cmdline": "./xmrig --threads=8 --algo=randomx --cpu-priority=5",
            "cpu_percent": round(sim_cpu * 0.96, 1),
            "memory_percent": 18.5,
            "user": "threat_actor",
            "is_tmp": True,
            "is_browser": False,
            "is_ide": False
        })
    
    # Sort top processes by CPU usage
    processes.sort(key=lambda p: p['cpu_percent'], reverse=True)
    
    return {
        "process_count": current_count + (1 if is_sim_active else 0),
        "processes": processes[:40],
        "tmp_execution_count": tmp_execution_count,
        "browser_high_cpu_count": browser_high_cpu_count,
        "avg_cpu_percent": round(total_cpu / max(1, current_count), 2),
        "total_cpu_percent": round(total_cpu, 1),
        "spawn_rate": round(spawn_velocity, 2)
    }
