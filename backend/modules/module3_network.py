import psutil
import time
from backend.config import SUSPICIOUS_PORTS

_simulated_net_activity = None

def set_simulated_network_activity(outbound_conns: int, suspicious_port_flag: int, data_exfil_kb_sec: float):
    global _simulated_net_activity
    _simulated_net_activity = {
        "outbound_conns": outbound_conns,
        "suspicious_port_flag": suspicious_port_flag,
        "data_exfil_kb_sec": data_exfil_kb_sec,
        "expire_time": time.time() + 4.0
    }

def collect_network_telemetry():
    global _simulated_net_activity
    
    current_time = time.time()
    
    if _simulated_net_activity and current_time < _simulated_net_activity["expire_time"]:
        return {
            "outbound_conn_count": _simulated_net_activity["outbound_conns"],
            "suspicious_port_flag": _simulated_net_activity["suspicious_port_flag"],
            "data_exfil_kb_sec": _simulated_net_activity["data_exfil_kb_sec"],
            "connections": [
                {
                    "fd": 12, "family": "IPv4", "type": "TCP",
                    "laddr": "192.168.1.105:49210",
                    "raddr": "185.220.101.5:4444" if _simulated_net_activity["suspicious_port_flag"] else "93.184.216.34:443",
                    "status": "ESTABLISHED",
                    "pid": 9821,
                    "is_suspicious": bool(_simulated_net_activity["suspicious_port_flag"])
                }
            ]
        }
    else:
        _simulated_net_activity = None

    connections = []
    outbound_count = 0
    suspicious_flag = 0
    
    try:
        net_conns = psutil.net_connections(kind='inet')
        for conn in net_conns:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            
            is_susp = 0
            if conn.raddr:
                outbound_count += 1
                if conn.raddr.port in SUSPICIOUS_PORTS:
                    is_susp = 1
                    suspicious_flag = 1
                    
            if conn.status == "ESTABLISHED":
                connections.append({
                    "fd": conn.fd,
                    "family": "IPv4" if conn.family == 2 else "IPv6",
                    "type": "TCP" if conn.type == 1 else "UDP",
                    "laddr": laddr,
                    "raddr": raddr,
                    "status": conn.status,
                    "pid": conn.pid or 0,
                    "is_suspicious": bool(is_susp)
                })
    except Exception:
        # Fallback if non-root net_connections restricted
        pass
        
    return {
        "outbound_conn_count": max(outbound_count, len(connections)),
        "suspicious_port_flag": suspicious_flag,
        "data_exfil_kb_sec": 4.5, # Normal baseline KB/s
        "connections": connections[:25]
    }
