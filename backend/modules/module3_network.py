import psutil
import time
from backend.config import SUSPICIOUS_PORTS

_simulated_net_activity = None
_last_net_io = None
_last_net_time = time.time()

def set_simulated_network_activity(outbound_conns: int, suspicious_port_flag: int, data_exfil_kb_sec: float):
    global _simulated_net_activity
    _simulated_net_activity = {
        "outbound_conns": outbound_conns,
        "suspicious_port_flag": suspicious_port_flag,
        "data_exfil_kb_sec": data_exfil_kb_sec,
        "expire_time": time.time() + 4.0
    }

def get_real_network_io_rate() -> float:
    """Calculates real network outbound upload rate in KB/sec using psutil.net_io_counters()."""
    global _last_net_io, _last_net_time
    now = time.time()
    dt = max(0.2, now - _last_net_time)
    
    try:
        current_io = psutil.net_io_counters()
        if _last_net_io is None:
            _last_net_io = current_io
            _last_net_time = now
            return 3.5 # Normal initial baseline
        
        bytes_sent_delta = max(0, current_io.bytes_sent - _last_net_io.bytes_sent)
        kb_sec = (bytes_sent_delta / 1024.0) / dt
        _last_net_io = current_io
        _last_net_time = now
        return round(kb_sec, 1)
    except Exception:
        return 3.5

def collect_network_telemetry():
    global _simulated_net_activity
    
    current_time = time.time()
    
    # Check if UI web simulation is active
    if _simulated_net_activity and current_time < _simulated_net_activity["expire_time"]:
        return {
            "outbound_conn_count": _simulated_net_activity["outbound_conns"],
            "suspicious_port_flag": _simulated_net_activity["suspicious_port_flag"],
            "data_exfil_kb_sec": _simulated_net_activity["data_exfil_kb_sec"],
            "connections": [
                {
                    "fd": 12, "family": "IPv4", "type": "TCP",
                    "laddr": "127.0.0.1:49210",
                    "raddr": "127.0.0.1:4444" if _simulated_net_activity["suspicious_port_flag"] else "93.184.216.34:443",
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
    real_exfil_rate = get_real_network_io_rate()
    
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
                    
            if conn.status in ["ESTABLISHED", "LISTEN", "SYN_SENT"]:
                connections.append({
                    "fd": conn.fd if hasattr(conn, 'fd') else 0,
                    "family": "IPv4" if conn.family == 2 else "IPv6",
                    "type": "TCP" if conn.type == 1 else "UDP",
                    "laddr": laddr,
                    "raddr": raddr,
                    "status": conn.status,
                    "pid": conn.pid or 0,
                    "is_suspicious": bool(is_susp)
                })
    except (psutil.AccessDenied, PermissionError):
        # Fallback for non-root systems on macOS / Ubuntu / Windows:
        # Check current user process connections
        try:
            for p in psutil.process_iter(['pid', 'name']):
                try:
                    for c in p.connections(kind='inet'):
                        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                        is_susp = 0
                        if c.raddr:
                            outbound_count += 1
                            if c.raddr.port in SUSPICIOUS_PORTS:
                                is_susp = 1
                                suspicious_flag = 1
                        if c.status in ["ESTABLISHED", "LISTEN"]:
                            connections.append({
                                "fd": 0,
                                "family": "IPv4",
                                "type": "TCP",
                                "laddr": laddr,
                                "raddr": raddr,
                                "status": c.status,
                                "pid": p.pid,
                                "is_suspicious": bool(is_susp)
                            })
                except Exception:
                    continue
                if len(connections) >= 30:
                    break
        except Exception:
            pass
    except Exception:
        pass
        
    return {
        "outbound_conn_count": max(outbound_count, len(connections)),
        "suspicious_port_flag": suspicious_flag,
        "data_exfil_kb_sec": max(real_exfil_rate, 4.2),
        "connections": connections[:30]
    }
