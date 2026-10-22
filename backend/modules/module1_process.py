import psutil
import time
import sys
from backend.config import (
    is_suspicious_temp_path,
    normalize_path,
    BROWSER_TAB_CPU_THRESHOLD,
    BROWSER_SUSTAINED_SAMPLES,
    TAB_BURST_THRESHOLD,
)

_known_pids = set()
_last_sample_time = time.time()
_last_proc_cpu_times = {}  # {pid: (user_time, sys_time, timestamp)}
_known_browser_tab_pids = set()
_browser_high_cpu_streak = {}  # {pid: consecutive polls above threshold}
_simulated_proc_activity = None
_simulated_browser_activity = None

CPU_COUNT = psutil.cpu_count(logical=True) or 1

# Simulated processes use NEGATIVE PIDs so they can never collide with a real
# process. Containment code must also skip anything marked "simulated".
SIM_MINER_PID = -69420
SIM_TAB_PID_BASE = -77000

BROWSER_NAME_KEYWORDS = ["chrome", "safari", "firefox", "msedge", "edge", "brave", "opera", "webkit"]
BROWSER_EXE_KEYWORDS = ["google chrome", "safari.app", "firefox", "msedge", "brave", "opera", "webkit"]

# Interpreters whose *script argument* decides where the code really came from.
INTERPRETER_NAMES = ["python", "python3", "pythonw", "node", "bash", "sh", "zsh", "perl", "ruby",
                     "powershell", "pwsh", "cmd", "wscript", "cscript"]

# Signature names used by the demo / common miner and shell tools.
KNOWN_ROGUE_MARKERS = ["osentinel_rogue", "xmrig", "nc_shell"]


def is_browser_process(process_name: str, cmdline: str = "", exe: str = "") -> bool:
    """Detects web browser processes (Chrome, Safari, Firefox, Edge, Opera, Brave)."""
    name_clean = (process_name or "").lower()
    exe_clean = (exe or "").lower()

    # AntiGravity IDE is never a web browser
    if "antigravity" in name_clean or "antigravity" in exe_clean:
        return False

    if any(b in name_clean for b in BROWSER_NAME_KEYWORDS):
        return True
    if any(b in exe_clean for b in BROWSER_EXE_KEYWORDS):
        return True
    return False


def is_browser_tab(process_name: str, cmdline: str = "", exe: str = "") -> bool:
    """
    Identifies browser TAB renderer processes only. Killing one of these closes a
    tab without crashing the browser. The main browser process, GPU, network and
    utility helpers and extension processes are NOT tabs and are never matched.
    """
    if not is_browser_process(process_name, cmdline, exe):
        return False
    name_clean = (process_name or "").lower()
    cmd_clean = (cmdline or "").lower()

    # Extensions run as renderers too, but they are not tabs
    if "--extension-process" in cmd_clean:
        return False
    # Chrome / Edge / Brave renderer (all platforms)
    if "--type=renderer" in cmd_clean or "(renderer)" in name_clean:
        return True
    # Safari: each tab runs in a WebContent process
    if "webcontent" in name_clean:
        return True
    # Firefox content processes for tabs
    if "-contentproc" in cmd_clean and " tab" in f" {cmd_clean}":
        return True
    return False


def is_ide_process(process_name: str, cmdline: str = "", exe: str = "") -> bool:
    """
    AntiGravity IDE is the SOLE PERMITTED EXCEPTION.

    Matching is done on the process NAME and EXECUTABLE PATH only. The command
    line is intentionally ignored: any program can put "antigravity" in its
    arguments, which would let malware exempt itself from termination.
    Generic runtimes (python, node, electron) are NOT exempt.
    """
    name_clean = (process_name or "").lower()
    exe_clean = normalize_path(exe)
    return "antigravity" in name_clean or "antigravity" in exe_clean


def detect_temp_execution(exe: str, cmdline_parts: list, process_name: str) -> bool:
    """
    True if the binary itself, or the script handed to an interpreter, lives in a
    temp/scratch directory. A trusted interpreter (/usr/bin/python3) running
    /tmp/payload.py is still flagged.
    """
    if is_suspicious_temp_path(exe):
        return True

    if cmdline_parts:
        if is_suspicious_temp_path(cmdline_parts[0]):
            return True
        base = normalize_path(cmdline_parts[0]).rsplit("/", 1)[-1].replace(".exe", "")
        name = (process_name or "").lower().replace(".exe", "")
        if any(base.startswith(i) or name.startswith(i) for i in INTERPRETER_NAMES):
            # First non-flag argument is the script being run
            for arg in cmdline_parts[1:]:
                if arg.startswith("-"):
                    if arg in ("-m", "-c", "-e", "-Command", "-EncodedCommand"):
                        break  # module / inline code, not a file
                    continue
                return is_suspicious_temp_path(arg)
    return False


def set_simulated_process_activity(total_cpu: float = 98.4, spawn_rate: float = 12.0, is_tmp: bool = True):
    """Allows safe injection of elevated CPU spikes (>95%) and spawn velocity for threat simulations."""
    global _simulated_proc_activity
    _simulated_proc_activity = {
        "total_cpu": total_cpu,
        "spawn_rate": spawn_rate,
        "is_tmp": is_tmp,
        "expire_time": time.time() + 4.0
    }


def set_simulated_browser_activity(cpu: float = 78.5, tab_count: int = 4):
    """Allows safe simulation of runaway browser tabs (>=70% CPU) or multiple tabs burst."""
    global _simulated_browser_activity
    _simulated_browser_activity = {
        "cpu": cpu,
        "tab_count": tab_count,
        "expire_time": time.time() + 4.0
    }


def get_accurate_process_cpu(proc, pid: int, current_time: float) -> float:
    """Per-process CPU % from time deltas between samples (100% = one full core)."""
    global _last_proc_cpu_times
    try:
        t = proc.cpu_times()
        if pid in _last_proc_cpu_times:
            prev_u, prev_s, prev_t = _last_proc_cpu_times[pid]
            dt = max(0.1, current_time - prev_t)
            delta = (t.user - prev_u) + (t.system - prev_s)
            cpu_pct = round((delta / dt) * 100.0, 1)
        else:
            # Newly seen process: estimate from lifetime average
            try:
                proc_age = max(0.1, current_time - proc.create_time())
                cpu_pct = round(((t.user + t.system) / proc_age) * 100.0, 1)
            except Exception:
                cpu_pct = 0.0

        _last_proc_cpu_times[pid] = (t.user, t.system, current_time)
        return max(0.0, cpu_pct)
    except Exception:
        return 0.0


def _simulated_process(pid, name, exe, cmdline, cpu, mem, user, is_tmp, is_browser, is_tab):
    return {
        "pid": pid, "ppid": 1, "name": name, "exe": exe, "cmdline": cmdline,
        "cpu_percent": round(cpu, 1), "memory_percent": mem, "user": user,
        "is_tmp": is_tmp, "is_browser": is_browser, "is_browser_tab": is_tab,
        "is_ide": False,
        "browser_cpu_streak": BROWSER_SUSTAINED_SAMPLES if (is_browser and cpu >= BROWSER_TAB_CPU_THRESHOLD) else 0,
        "simulated": True,
    }


def collect_process_telemetry():
    global _known_pids, _last_sample_time, _simulated_proc_activity, _simulated_browser_activity
    global _last_proc_cpu_times, _known_browser_tab_pids, _browser_high_cpu_streak

    processes = []
    tmp_execution_count = 0
    browser_high_cpu_count = 0
    current_tab_pids = set()
    total_cpu = 0.0

    current_time = time.time()
    dt = max(0.1, current_time - _last_sample_time)

    is_sim_active = bool(_simulated_proc_activity and current_time < _simulated_proc_activity["expire_time"])
    if not is_sim_active:
        _simulated_proc_activity = None

    is_browser_sim_active = bool(_simulated_browser_activity and current_time < _simulated_browser_activity["expire_time"])
    if not is_browser_sim_active:
        _simulated_browser_activity = None

    active_pids = set()
    new_streaks = {}

    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'memory_percent', 'username', 'create_time']):
        try:
            info = proc.info
            pid = info['pid']
            active_pids.add(pid)
            name = info['name'] or f"proc_{pid}"
            exe = (info['exe'] or "").replace("\\", "/")
            mem = info['memory_percent'] or 0.0
            cmd_parts = info['cmdline'] or []
            raw_cmdline = " ".join(cmd_parts) if cmd_parts else name
            cmdline_normalized = normalize_path(raw_cmdline)

            cpu = get_accurate_process_cpu(proc, pid, current_time)

            is_ide = is_ide_process(name, raw_cmdline, exe)
            is_browser = is_browser_process(name, raw_cmdline, exe)
            is_tab = is_browser_tab(name, raw_cmdline, exe) if is_browser else False

            if is_tab:
                current_tab_pids.add(pid)

            # Track how long a browser process has stayed above the CPU threshold
            streak = 0
            if is_browser and not is_ide and cpu >= BROWSER_TAB_CPU_THRESHOLD:
                streak = _browser_high_cpu_streak.get(pid, 0) + 1
                new_streaks[pid] = streak
                if streak >= BROWSER_SUSTAINED_SAMPLES:
                    browser_high_cpu_count += 1

            is_tmp = False
            if not is_ide:
                is_tmp = detect_temp_execution(exe, cmd_parts, name)
                if any(m in cmdline_normalized for m in KNOWN_ROGUE_MARKERS):
                    is_tmp = True

            if is_tmp:
                tmp_execution_count += 1

            total_cpu += cpu

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
                "is_browser_tab": is_tab,
                "is_ide": is_ide,
                "browser_cpu_streak": streak,
                "create_time": info.get('create_time'),
                "simulated": False,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, PermissionError):
            continue

    # Purge exited PIDs from trackers
    _last_proc_cpu_times = {pid: v for pid, v in _last_proc_cpu_times.items() if pid in active_pids}
    _browser_high_cpu_streak = new_streaks

    # Tab burst: many NEW renderer processes appearing within one poll window
    new_tab_pids = set()
    multiple_tabs_burst = False
    if _known_browser_tab_pids:
        new_tab_pids = current_tab_pids - _known_browser_tab_pids
        if len(new_tab_pids) >= TAB_BURST_THRESHOLD:
            multiple_tabs_burst = True
    _known_browser_tab_pids = current_tab_pids
    if not multiple_tabs_burst:
        new_tab_pids = set()

    # Spawn rate = genuinely new PIDs per second (process exits no longer cancel it out)
    spawn_velocity = (len(active_pids - _known_pids) / dt) if _known_pids else 0.0
    _known_pids = active_pids
    _last_sample_time = current_time

    current_count = len(processes)
    # Normalise to 0-100% of total machine capacity (summed per-process % can reach 100 x cores)
    system_cpu = min(100.0, total_cpu / CPU_COUNT)
    try:
        mem_percent = psutil.virtual_memory().percent
    except Exception:
        mem_percent = 0.0

    simulated_pids = []

    if is_sim_active:
        sim_cpu = _simulated_proc_activity["total_cpu"]
        sim_spawn = _simulated_proc_activity["spawn_rate"]
        if _simulated_proc_activity["is_tmp"]:
            tmp_execution_count = max(1, tmp_execution_count)
        system_cpu = max(sim_cpu, system_cpu)
        spawn_velocity = max(sim_spawn, spawn_velocity)
        processes.insert(0, _simulated_process(
            SIM_MINER_PID, "xmrig_crypto_miner",
            "/tmp/xmrig_miner" if sys.platform != "win32" else "C:/Windows/Temp/xmrig_miner.exe",
            "./xmrig --threads=8 --algo=randomx --cpu-priority=5",
            sim_cpu * 0.96, 18.5, "threat_actor",
            _simulated_proc_activity["is_tmp"], False, False,
        ))
        simulated_pids.append(SIM_MINER_PID)

    if is_browser_sim_active:
        sim_b_cpu = _simulated_browser_activity["cpu"]
        sim_tab_count = _simulated_browser_activity["tab_count"]
        browser_high_cpu_count = max(1, browser_high_cpu_count)
        multiple_tabs_burst = True
        for i in range(sim_tab_count):
            sim_pid = SIM_TAB_PID_BASE - i
            processes.insert(0, _simulated_process(
                sim_pid, "Google Chrome Helper (Renderer)",
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                f"--type=renderer --simulation-tab={i}",
                sim_b_cpu if i == 0 else 45.0, 12.0, "browser_user",
                False, True, True,
            ))
            new_tab_pids.add(sim_pid)
            simulated_pids.append(sim_pid)

    processes.sort(key=lambda p: p['cpu_percent'], reverse=True)

    # Priority selection: never drop browser tabs, runaway processes or temp executions
    actionable_pids = set()
    actionable_processes = []

    def take(p):
        if p["pid"] not in actionable_pids:
            actionable_pids.add(p["pid"])
            actionable_processes.append(p)

    for p in processes:
        if p["cpu_percent"] >= 50.0 or p.get("simulated"):
            take(p)
    for p in processes:
        if p["is_browser"]:
            take(p)
    for p in processes:
        if p["is_tmp"]:
            take(p)
    for p in processes:
        if len(actionable_processes) >= 60:
            break
        take(p)

    return {
        "process_count": current_count + len(simulated_pids),
        "processes": actionable_processes,
        "tmp_execution_count": tmp_execution_count,
        "browser_high_cpu_count": browser_high_cpu_count,
        "multiple_tabs_burst": multiple_tabs_burst,
        "new_tab_count": len(new_tab_pids),
        "new_tab_pids": list(new_tab_pids),
        "simulated_pids": simulated_pids,
        "avg_cpu_percent": round(total_cpu / max(1, current_count), 2),
        "total_cpu_percent": round(system_cpu, 1),
        "mem_percent": round(mem_percent, 1),
        "cpu_count": CPU_COUNT,
        "spawn_rate": round(spawn_velocity, 2)
    }
