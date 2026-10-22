import time
import threading
from backend.modules.module1_process import set_simulated_process_activity
from backend.modules.module2_file import set_simulated_file_activity
from backend.modules.module3_network import set_simulated_network_activity

_active_simulation = None

def trigger_attack_simulation(attack_type: str) -> dict:
    global _active_simulation
    
    attack_type_upper = attack_type.upper()
    timestamp = time.time()
    
    if attack_type_upper == "RANSOMWARE":
        set_simulated_file_activity(mod_rate=85.0, avg_entropy=7.85, del_rate=22.0)
        _active_simulation = {
            "type": "Ransomware Mass Encryption Burst",
            "started_at": timestamp,
            "duration": 5.0,
            "details": "Simulated rapid file encryption & entropy elevation (H=7.85) in isolated sandbox buffer."
        }
    elif attack_type_upper == "REVERSE_SHELL" or attack_type_upper == "C2":
        set_simulated_process_activity(total_cpu=35.0, spawn_rate=4.0, is_tmp=True)
        set_simulated_network_activity(outbound_conns=4, suspicious_port_flag=1, data_exfil_kb_sec=120.0)
        _active_simulation = {
            "type": "Reverse Shell C2 Connection",
            "started_at": timestamp,
            "duration": 5.0,
            "details": "Simulated active connection to C2 port 4444 with spawned binary from /tmp/nc_shell."
        }
    elif attack_type_upper == "EXFILTRATION":
        set_simulated_network_activity(outbound_conns=18, suspicious_port_flag=0, data_exfil_kb_sec=14500.0)
        _active_simulation = {
            "type": "Data Exfiltration Burst",
            "started_at": timestamp,
            "duration": 5.0,
            "details": "Simulated high throughput (14.5 MB/s) outbound data stream across 18 active sockets."
        }
    elif attack_type_upper == "CRYPTOMINER":
        # Elevate CPU usage above 95% (98.5%)
        set_simulated_process_activity(total_cpu=98.5, spawn_rate=14.0, is_tmp=True)
        set_simulated_file_activity(mod_rate=2.0, avg_entropy=4.1, del_rate=0.0)
        set_simulated_network_activity(outbound_conns=2, suspicious_port_flag=1, data_exfil_kb_sec=15.0)
        _active_simulation = {
            "type": "CryptoMiner CPU Hijack",
            "started_at": timestamp,
            "duration": 5.0,
            "details": "Simulated sustained 98.5% CPU spike (>95%) with miner thread pool spawning from /tmp/xmrig."
        }
    elif attack_type_upper in ["RESTRICTED_NETWORK", "RESTRICTED_IP"]:
        set_simulated_process_activity(total_cpu=18.0, spawn_rate=2.0, is_tmp=False)
        set_simulated_network_activity(
            outbound_conns=3,
            suspicious_port_flag=0,
            data_exfil_kb_sec=42.0,
            restricted_ip_flag=1,
            simulated_raddr="198.51.100.45:8080"
        )
        _active_simulation = {
            "type": "Restricted Network Access Attempt",
            "started_at": timestamp,
            "duration": 5.0,
            "details": "Simulated unauthorized socket connection to restricted IP subnet 198.51.100.45:8080 (RFC 5737 Test-Net-2)."
        }
    else:
        return {"success": False, "message": f"Unknown attack simulation type: {attack_type}"}
        
    return {
        "success": True,
        "message": f"Successfully launched safe threat simulation: {_active_simulation['type']}",
        "simulation": _active_simulation
    }

def get_active_simulation():
    global _active_simulation
    if _active_simulation:
        if time.time() - _active_simulation["started_at"] > _active_simulation["duration"]:
            _active_simulation = None
    return _active_simulation
