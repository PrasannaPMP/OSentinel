import psutil
import time
from backend.config import SUSPICIOUS_PATHS

_last_process_count = 0
_last_sample_time = time.time()

def collect_process_telemetry():
    global _last_process_count, _last_sample_time
    
    processes = []
    tmp_execution_count = 0
    total_cpu = 0.0
    total_mem = 0.0
    
    current_time = time.time()
    dt = max(0.1, current_time - _last_sample_time)
    
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_percent', 'username']):
        try:
            info = proc.info
            pid = info['pid']
            name = info['name'] or f"proc_{pid}"
            exe = info['exe'] or ""
            cpu = info['cpu_percent'] or 0.0
            mem = info['memory_percent'] or 0.0
            cmdline = " ".join(info['cmdline']) if info['cmdline'] else name
            
            # Check if running from temporary or suspicious paths
            is_tmp = any(exe.startswith(sp) or "/tmp" in cmdline or "/var/tmp" in cmdline for sp in SUSPICIOUS_PATHS)
            if is_tmp:
                tmp_execution_count += 1
                
            total_cpu += cpu
            total_mem += mem
            
            processes.append({
                "pid": pid,
                "ppid": info['ppid'],
                "name": name,
                "exe": exe,
                "cmdline": cmdline,
                "cpu_percent": round(cpu, 1),
                "memory_percent": round(mem, 1),
                "user": info['username'] or "unknown",
                "is_tmp": is_tmp
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
            
    current_count = len(processes)
    spawn_velocity = max(0.0, (current_count - _last_process_count) / dt) if _last_process_count > 0 else 0.0
    _last_process_count = current_count
    _last_sample_time = current_time
    
    # Sort top processes by CPU usage
    processes.sort(key=lambda p: p['cpu_percent'], reverse=True)
    
    return {
        "process_count": current_count,
        "processes": processes[:40], # Top 40 process snapshot
        "tmp_execution_count": tmp_execution_count,
        "avg_cpu_percent": round(total_cpu / max(1, current_count), 2),
        "total_cpu_percent": round(total_cpu, 1),
        "spawn_rate": round(spawn_velocity, 2)
    }
