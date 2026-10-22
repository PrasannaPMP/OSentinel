import psutil
import socket
import time
import ipaddress
from backend.config import SUSPICIOUS_PORTS
from backend.database import get_restricted_networks

_simulated_net_activity = None
_last_net_bytes = None
_last_net_time = time.time()

LOOPBACK_NAMES = ["lo", "lo0", "loopback", "127.0.0.1"]
SIM_CONN_PID = -9821  # negative: can never match a real process

def extract_ip_address(addr_str: str) -> str:
    """Extracts raw IP address without port or interface identifier."""
    if not addr_str:
        return ""
    if ":" in addr_str:
        if addr_str.startswith("[") and "]:" in addr_str:
            return addr_str[1:].split("]:")[0]
        parts = addr_str.split(":")
        if len(parts) == 2:
            return parts[0]
        return addr_str
    return addr_str

def match_restricted_ip(ip_str: str, restricted_list: list) -> tuple:
    """
    Checks if an IP address belongs to any configured restricted network or IP.
    Returns (is_restricted: bool, matched_cidr: str, description: str, action: str)
    """
    clean_ip = extract_ip_address(ip_str)
    if not clean_ip:
        return False, "", "", ""
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return False, "", "", ""
        
    for item in restricted_list:
        if not item.get("is_active", 1):
            continue
        cidr = item.get("network_cidr", "").strip()
        if not cidr:
            continue
        try:
            net_obj = ipaddress.ip_network(cidr, strict=False)
            if ip_obj in net_obj:
                return True, cidr, item.get("description", ""), item.get("action", "BLOCK")
        except ValueError:
            continue
            
    return False, "", "", ""

def set_simulated_network_activity(
    outbound_conns: int,
    suspicious_port_flag: int,
    data_exfil_kb_sec: float,
    restricted_ip_flag: int = 0,
    simulated_raddr: str = None
):
    global _simulated_net_activity
    _simulated_net_activity = {
        "outbound_conns": outbound_conns,
        "suspicious_port_flag": suspicious_port_flag,
        "data_exfil_kb_sec": data_exfil_kb_sec,
        "restricted_ip_flag": restricted_ip_flag,
        "simulated_raddr": simulated_raddr,
        "expire_time": time.time() + 4.0
    }

def get_real_external_network_io_rate() -> float:
    """Calculates real network outbound upload rate in KB/sec excluding localhost loopback."""
    global _last_net_bytes, _last_net_time
    now = time.time()
    dt = max(0.2, now - _last_net_time)
    
    try:
        per_nic = psutil.net_io_counters(pernic=True)
        # Sum only real external network interfaces (exclude lo0, loopback)
        total_external_sent = 0
        for nic_name, stats in per_nic.items():
            if not any(lb in nic_name.lower() for lb in LOOPBACK_NAMES):
                total_external_sent += stats.bytes_sent
                
        if _last_net_bytes is None:
            _last_net_bytes = total_external_sent
            _last_net_time = now
            return 0.0
        
        bytes_sent_delta = max(0, total_external_sent - _last_net_bytes)
        kb_sec = (bytes_sent_delta / 1024.0) / dt
        _last_net_bytes = total_external_sent
        _last_net_time = now
        return round(kb_sec, 1)
    except Exception:
        return 0.0

def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def _analyse_connection(conn, pid, restricted_list, state):
    """Classifies one socket and updates the aggregate counters in `state`."""
    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""

    is_susp = False
    if conn.raddr:
        if not _is_loopback(conn.raddr.ip) and conn.status == "ESTABLISHED":
            state["outbound"] += 1
        if conn.raddr.port in SUSPICIOUS_PORTS:
            is_susp = True
    # A local LISTENER on a threat port (e.g. a reverse-shell handler on 4444)
    if conn.laddr and conn.status == "LISTEN" and conn.laddr.port in SUSPICIOUS_PORTS:
        is_susp = True
    if is_susp:
        state["suspicious"] = 1

    # Only the REMOTE address is matched against restricted networks. Matching the
    # local address would flag every process if the user's own LAN were listed.
    is_restr, restr_cidr, restr_desc, restr_act = (False, "", "", "")
    if conn.raddr:
        is_restr, restr_cidr, restr_desc, restr_act = match_restricted_ip(conn.raddr.ip, restricted_list)
    if is_restr:
        state["restricted"] = 1
        state["restricted_count"] += 1

    if conn.status in ["ESTABLISHED", "LISTEN", "SYN_SENT"]:
        state["connections"].append({
            "fd": getattr(conn, "fd", 0) or 0,
            "family": "IPv4" if conn.family == socket.AF_INET else "IPv6",
            "type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
            "laddr": laddr,
            "raddr": raddr,
            "status": conn.status,
            "pid": pid or 0,
            "is_suspicious": is_susp,
            "is_restricted": is_restr,
            "matched_network": restr_cidr if is_restr else "",
            "restricted_reason": restr_desc if is_restr else "",
            "restriction_action": restr_act if is_restr else "",
            "simulated": False,
        })


def collect_network_telemetry():
    global _simulated_net_activity

    current_time = time.time()
    try:
        restricted_list = get_restricted_networks()
    except Exception:
        restricted_list = []

    active_restricted_count = len([r for r in restricted_list if r.get("is_active", 1)])

    # Web simulation (synthetic numbers only)
    if _simulated_net_activity and current_time < _simulated_net_activity["expire_time"]:
        sim_restricted = bool(_simulated_net_activity.get("restricted_ip_flag", 0))
        sim_raddr = _simulated_net_activity.get("simulated_raddr") or (
            "198.51.100.45:8080" if sim_restricted else
            ("127.0.0.1:4444" if _simulated_net_activity["suspicious_port_flag"] else "93.184.216.34:443"))

        sim_conn = {
            "fd": 12, "family": "IPv4", "type": "TCP",
            "laddr": "127.0.0.1:49210",
            "raddr": sim_raddr,
            "status": "ESTABLISHED",
            "pid": SIM_CONN_PID,
            "is_suspicious": bool(_simulated_net_activity["suspicious_port_flag"]),
            "is_restricted": sim_restricted,
            "matched_network": "198.51.100.0/24" if sim_restricted else "",
            "restricted_reason": "RFC 5737 Test-Net-2 (Restricted External Subnet)" if sim_restricted else "",
            "restriction_action": "BLOCK" if sim_restricted else "",
            "simulated": True,
        }

        return {
            "outbound_conn_count": _simulated_net_activity["outbound_conns"],
            "suspicious_port_flag": _simulated_net_activity["suspicious_port_flag"],
            "restricted_ip_flag": 1 if sim_restricted else 0,
            "restricted_conns_count": 1 if sim_restricted else 0,
            "data_exfil_kb_sec": _simulated_net_activity["data_exfil_kb_sec"],
            "connections": [sim_conn],
            "restricted_networks_count": active_restricted_count,
            "simulated": True,
        }
    _simulated_net_activity = None

    state = {"outbound": 0, "suspicious": 0, "restricted": 0, "restricted_count": 0, "connections": []}
    upload_rate = get_real_external_network_io_rate()

    try:
        for conn in psutil.net_connections(kind='inet'):
            _analyse_connection(conn, conn.pid, restricted_list, state)
    except (psutil.AccessDenied, PermissionError):
        # Non-root fallback (macOS): enumerate per process
        for p in psutil.process_iter(['pid']):
            try:
                for c in p.net_connections(kind='inet') if hasattr(p, "net_connections") else p.connections(kind='inet'):
                    _analyse_connection(c, p.pid, restricted_list, state)
            except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
                continue
            except Exception:
                continue
    except Exception:
        pass

    # Keep suspicious/restricted sockets visible even if the list is long
    conns = sorted(state["connections"], key=lambda c: (not c["is_restricted"], not c["is_suspicious"]))

    return {
        "outbound_conn_count": state["outbound"],
        "suspicious_port_flag": state["suspicious"],
        "restricted_ip_flag": state["restricted"],
        "restricted_conns_count": state["restricted_count"],
        # Machine-wide upload rate (psutil cannot attribute bytes to a process)
        "data_exfil_kb_sec": upload_rate,
        "connections": conns[:40],
        "restricted_networks_count": active_restricted_count,
        "simulated": False,
    }
