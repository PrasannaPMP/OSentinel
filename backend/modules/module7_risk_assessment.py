import os
import time
import psutil
from backend.config import (
    RISK_THRESHOLD_LOW,
    RISK_THRESHOLD_HIGH,
    WEIGHT_RULE,
    WEIGHT_ANOMALY,
    WEIGHT_CLASSIFIER,
    BROWSER_SUSTAINED_SAMPLES,
    INCIDENT_COOLDOWN_SEC,
    is_under_path,
)
from backend.database import create_alert, create_incident
from backend.modules.module1_process import is_ide_process

# Last time an alert/incident was raised per key, used to stop the database from
# being flooded with a new incident every 2 seconds while the same threat persists.
_last_raised = {}


def _cooldown_ok(key: str, now: float = None) -> bool:
    now = now or time.time()
    if now - _last_raised.get(key, 0.0) >= INCIDENT_COOLDOWN_SEC:
        _last_raised[key] = now
        return True
    return False


def is_protected_system_process(pid: int, process_name: str) -> bool:
    """Prevents terminating operating system core processes and OSentinel itself."""
    if pid <= 100:
        return True
    if pid in (os.getpid(), os.getppid()):
        return True
    name_clean = (process_name or "").lower()
    return name_clean in ["kernel_task", "launchd", "systemd", "windowserver", "init",
                          "csrss.exe", "wininit.exe", "winlogon.exe", "lsass.exe",
                          "services.exe", "smss.exe", "explorer.exe", "loginwindow", "finder"]


def calculate_risk_score(rule_result: dict, ml_result: dict) -> dict:
    rule_score = float(rule_result.get("rule_score", 0.0))
    anomaly_score = float(ml_result.get("anomaly_score", 0.0))

    threat_category = ml_result.get("predicted_category", "Normal")
    confidence = float(ml_result.get("confidence", 0.0))

    classifier_score = (confidence * 100.0) if threat_category != "Normal" else 0.0

    raw_risk = (WEIGHT_RULE * rule_score) + (WEIGHT_ANOMALY * anomaly_score) + (WEIGHT_CLASSIFIER * classifier_score)
    final_risk_score = min(100.0, max(0.0, raw_risk))

    # Prioritize specific rule categories if triggered
    triggered_rules = rule_result.get("triggered_rules", [])
    if any(r.get("id") == "RULE-NET-RESTRICTED-01" for r in triggered_rules):
        threat_category = "Restricted Network Access"
    elif any(r.get("id") in ["RULE-BROWSER-01", "RULE-BROWSER-TABS-01"] for r in triggered_rules):
        threat_category = "Browser Cryptojacking"
    elif threat_category == "Normal" and triggered_rules:
        threat_category = triggered_rules[0].get("category", "Normal")

    if final_risk_score >= RISK_THRESHOLD_HIGH:
        severity = "HIGH"
    elif final_risk_score >= RISK_THRESHOLD_LOW:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "risk_score": round(final_risk_score, 1),
        "severity": severity,
        "threat_category": threat_category if final_risk_score >= RISK_THRESHOLD_LOW else "Normal",
        "score_breakdown": {
            "rule_component": round(WEIGHT_RULE * rule_score, 1),
            "anomaly_component": round(WEIGHT_ANOMALY * anomaly_score, 1),
            "classifier_component": round(WEIGHT_CLASSIFIER * classifier_score, 1)
        }
    }


def terminate_process_safe(
    pid: int,
    process_name: str,
    is_tmp: bool = False,
    cpu_percent: float = 0.0,
    cmdline: str = "",
    force: bool = False,
    expected_create_time: float = None,
    exe: str = "",
) -> dict:
    """
    Terminates a rogue process or runaway browser tab.
    AntiGravity is the ONLY application exempt from termination.
    """
    # Simulated processes use negative PIDs and must never touch a real process
    if pid is None or pid <= 0:
        return {"success": True, "simulated": True,
                "message": f"Simulated containment of {process_name} (no real process affected)."}

    if is_protected_system_process(pid, process_name):
        return {"success": False, "message": f"System core process {process_name} (PID {pid}) cannot be terminated."}

    try:
        if not psutil.pid_exists(pid):
            return {"success": True, "message": f"Process PID {pid} already stopped."}
        p = psutil.Process(pid)

        # Check the AntiGravity exemption against the REAL process, not only the
        # name the caller supplied (the API caller could send any name).
        try:
            real_name, real_exe = p.name(), p.exe() or ""
        except (psutil.AccessDenied, psutil.ZombieProcess):
            real_name, real_exe = process_name, exe
        if is_ide_process(process_name, cmdline, exe) or is_ide_process(real_name, "", real_exe):
            return {"success": False,
                    "message": f"AntiGravity IDE ({real_name}, PID {pid}) is exempted from termination (sole permitted exception)."}
        if is_protected_system_process(pid, real_name):
            return {"success": False, "message": f"System core process {real_name} (PID {pid}) cannot be terminated."}

        # PID reuse guard: the process that was detected may have exited and its PID
        # been given to an unrelated program between detection and this call.
        if expected_create_time is not None:
            try:
                if abs(p.create_time() - expected_create_time) > 1.0:
                    return {"success": False,
                            "message": f"PID {pid} now belongs to a different process; termination skipped."}
            except psutil.Error:
                pass

        p.terminate()
        try:
            p.wait(timeout=1.5)
        except psutil.TimeoutExpired:
            p.kill()  # Force kill if stubborn
        return {"success": True, "message": f"Successfully terminated target process: {real_name} (PID {pid})"}
    except psutil.NoSuchProcess:
        return {"success": True, "message": f"Process PID {pid} already stopped."}
    except (psutil.AccessDenied, PermissionError):
        return {"success": False, "message": f"Permission denied terminating PID {pid}."}
    except Exception as e:
        return {"success": False, "message": str(e)}


def find_file_writers(watch_dirs: list) -> list:
    """
    Attributes file activity to processes: a process is a candidate writer if it
    currently holds an open file inside a watched folder, has its working
    directory there, or names the folder in its command line. Only called when
    the ransomware signal is already active, because open_files() is expensive.
    """
    writers = []
    me = {os.getpid(), os.getppid()}
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
        info = proc.info
        if info['pid'] in me or is_ide_process(info['name'], "", info['exe'] or ""):
            continue
        reason = None
        try:
            for f in proc.open_files():
                if any(is_under_path(f.path, d) for d in watch_dirs):
                    reason = f"open file {f.path}"
                    break
            if not reason:
                cwd = proc.cwd()
                if any(is_under_path(cwd, d) for d in watch_dirs):
                    reason = f"working directory {cwd}"
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            pass
        if not reason and info['cmdline']:
            cmd = " ".join(info['cmdline']).replace("\\", "/").lower()
            if any(str(d).replace("\\", "/").lower() in cmd for d in watch_dirs):
                reason = "command line references watched folder"
        if reason:
            writers.append({
                "pid": info['pid'], "name": info['name'] or "", "exe": info['exe'] or "",
                "cmdline": " ".join(info['cmdline'] or []), "create_time": info['create_time'],
                "reason": reason,
            })
    return writers


def triage_and_respond(proc_telemetry: dict, file_telemetry: dict, net_telemetry: dict, rule_result: dict, ml_result: dict, risk_assessment: dict):
    risk_score = risk_assessment["risk_score"]
    severity = risk_assessment["severity"]
    threat_cat = risk_assessment["threat_category"]

    triggered_rules = rule_result.get("triggered_rules", [])
    processes = proc_telemetry.get("processes", [])
    by_pid = {p.get("pid"): p for p in processes}

    terminated_processes = []
    offenders = []  # (pid, name) of processes actually acted on, first = primary
    seen_pids = set()

    def contain(p: dict, label: str, alert_title: str, alert_desc: str, alert_risk: float, rule_id: str, category: str):
        """Kills (or, for simulated entries, pretends to kill) a process and raises an alert."""
        pid = p.get("pid", 0)
        if pid in seen_pids:
            return
        name = p.get("name", "unknown")
        if p.get("simulated") or pid <= 0:
            res = {"success": True, "simulated": True}
        else:
            res = terminate_process_safe(pid, name, is_tmp=p.get("is_tmp", False),
                                         cpu_percent=p.get("cpu_percent", 0.0), cmdline=p.get("cmdline", ""),
                                         force=True, expected_create_time=p.get("create_time"),
                                         exe=p.get("exe", ""))
        if not res.get("success"):
            return
        seen_pids.add(pid)
        offenders.append((pid, name))
        tag = " [SIMULATED]" if res.get("simulated") else ""
        terminated_processes.append(f"{label}{tag}")
        create_alert(
            severity="HIGH",
            title=alert_title + tag,
            description=alert_desc + (" (Simulation: no real process was terminated.)" if tag else ""),
            risk_score=alert_risk,
            triggered_rules=[rule_id],
            threat_category=category,
        )

    # ---------------------------------------------------------------------
    # RULE A1: Runaway browser TAB (>= 70% CPU sustained for ~6s)
    # Only tab renderer processes are killed. The main browser process is
    # alerted on but never killed, since that would close the whole browser.
    # ---------------------------------------------------------------------
    for p in processes:
        if not p.get("is_browser") or p.get("is_ide"):
            continue
        if p.get("browser_cpu_streak", 0) < BROWSER_SUSTAINED_SAMPLES:
            continue
        p_pid, p_name, p_cpu = p.get("pid", 0), p.get("name", ""), p.get("cpu_percent", 0.0)
        if p.get("is_browser_tab"):
            contain(p, f"Browser Tab '{p_name}' (PID {p_pid}, CPU {p_cpu}%)",
                    f"Runaway Browser Tab Auto-Terminated (PID {p_pid})",
                    f"Browser tab '{p_name}' (PID {p_pid}) stayed above the 70% CPU threshold ({p_cpu}%). "
                    f"Auto-terminated to protect system performance.",
                    75.0, "RULE-BROWSER-01", "Browser Cryptojacking")
        elif _cooldown_ok(f"browser-main-{p_pid}"):
            create_alert(
                severity="MEDIUM",
                title=f"Browser Process High CPU (PID {p_pid})",
                description=f"Browser process '{p_name}' (PID {p_pid}) is above 70% CPU ({p_cpu}%). "
                            f"It is not a tab process, so it was NOT terminated.",
                risk_score=55.0, triggered_rules=["RULE-BROWSER-01"], threat_category="Browser Cryptojacking")

    # ---------------------------------------------------------------------
    # RULE A2: Burst of new tab processes
    # ---------------------------------------------------------------------
    if proc_telemetry.get("multiple_tabs_burst"):
        for p_pid in proc_telemetry.get("new_tab_pids", []):
            p = by_pid.get(p_pid)
            if not p or not p.get("is_browser_tab"):
                continue  # only kill processes we positively identified as tabs
            contain(p, f"Runaway Tab '{p['name']}' (PID {p_pid})",
                    f"Multiple Tabs Opening: Tab Auto-Terminated (PID {p_pid})",
                    f"Detected a burst of new browser tab processes. Offending tab '{p['name']}' (PID {p_pid}) "
                    f"was auto-terminated to prevent resource exhaustion.",
                    70.0, "RULE-BROWSER-TABS-01", "Browser Runaway Tabs")

    # ---------------------------------------------------------------------
    # RULE B: Ransomware-style file activity
    # Only processes that can actually be tied to the watched folders are killed.
    # If no writer can be identified, an alert is raised instead of guessing.
    # ---------------------------------------------------------------------
    is_file_attack = file_telemetry.get("file_mod_rate", 0) >= 15.0 and file_telemetry.get("high_entropy_alert", False)
    is_file_attack = is_file_attack or file_telemetry.get("file_deletion_rate", 0) >= 10.0
    if is_file_attack and not file_telemetry.get("simulated"):
        writers = find_file_writers(file_telemetry.get("watch_dirs", []))
        for w in writers:
            contain({**w, "is_tmp": False, "cpu_percent": 0.0},
                    f"Rogue File Writer '{w['name']}' (PID {w['pid']})",
                    f"Rogue Process Auto-Terminated: Rapid File Modification (PID {w['pid']})",
                    f"Process '{w['name']}' was linked to high-entropy file writes ({w['reason']}). "
                    f"AntiGravity is the only allowed exception. Process auto-terminated.",
                    85.0, "RULE-RANSOMWARE-01", "Ransomware")
        if not writers and _cooldown_ok("ransomware-unattributed"):
            create_alert(
                severity="HIGH",
                title="Ransomware-like File Activity (writer not identified)",
                description=f"Rapid high-entropy file changes detected "
                            f"({file_telemetry.get('file_mod_rate')} files/s, H={file_telemetry.get('avg_file_entropy')}) "
                            f"but no process could be linked to the watched folders. No process was terminated.",
                risk_score=85.0, triggered_rules=["RULE-RANSOMWARE-01"], threat_category="Ransomware")
    elif is_file_attack and file_telemetry.get("simulated"):
        # Simulation: show the containment flow against the simulated miner/worker if present
        sim = next((p for p in processes if p.get("simulated")), None)
        sim = sim or {"pid": -1, "name": "simulated_ransomware.exe", "simulated": True}
        contain(sim, f"Rogue File Writer '{sim['name']}'",
                "Rogue Process Auto-Terminated: Rapid File Modification",
                "Simulated ransomware encryption burst detected in the sandbox.",
                85.0, "RULE-RANSOMWARE-01", "Ransomware")

    # ---------------------------------------------------------------------
    # RULE C: Executables / scripts running from temp directories
    # ---------------------------------------------------------------------
    for p in processes:
        if p.get("is_tmp") and not p.get("is_ide"):
            p_pid, p_name = p.get("pid", 0), p.get("name", "")
            contain(p, f"Rogue Worker '{p_name}' (PID {p_pid})",
                    f"Unwanted Rogue Dependency Auto-Terminated (PID {p_pid})",
                    f"Process '{p_name}' launched from an unauthorized scratch/temp directory. Auto-terminated immediately.",
                    80.0, "RULE-EXEC-01", "Malicious Execution")

    # ---------------------------------------------------------------------
    # RULE D: Connections to restricted networks (remote address only)
    # ---------------------------------------------------------------------
    for c in net_telemetry.get("connections", []):
        if not c.get("is_restricted"):
            continue
        p_pid = c.get("pid", 0)
        if p_pid == 0:
            continue  # owner unknown (needs admin rights to see); cannot act
        p = by_pid.get(p_pid) or {"pid": p_pid, "name": "network_process", "simulated": c.get("simulated", False)}
        if p.get("is_ide"):
            continue
        contain({**p, "simulated": p.get("simulated") or c.get("simulated", False)},
                f"Restricted Network Socket on '{p.get('name')}' (PID {p_pid} -> {c.get('raddr')})",
                f"Restricted Network Connection Severed & Auto-Terminated (PID {p_pid})",
                f"Process '{p.get('name')}' (PID {p_pid}) communicated with restricted network "
                f"{c.get('matched_network')} ({c.get('raddr')} - {c.get('restricted_reason')}). "
                f"Policy: AUTO-BLOCK. Process terminated.",
                90.0, "RULE-NET-RESTRICTED-01", "Restricted Network Access")

    incident_id = None
    incident_code = None
    alert_id = None
    response_action = "LOG"
    category = threat_cat if threat_cat != "Normal" else "Runaway Process"

    # Primary process for the incident record: something we acted on, else the
    # most suspicious process in view, else none.
    if offenders:
        inc_pid, inc_name = offenders[0]
    else:
        suspect = next((p for p in processes if p.get("is_tmp")), None)
        inc_pid, inc_name = (suspect["pid"], suspect["name"]) if suspect else (0, "unknown")

    if terminated_processes or (severity == "HIGH" and _cooldown_ok(f"incident-{category}")):
        response_action = "CONTAIN_AND_INCIDENT"
        contain_summary = f"AUTO-TERMINATED: {', '.join(terminated_processes)}" if terminated_processes else "ISOLATE_MONITOR"
        incident_id, incident_code = create_incident(
            severity="HIGH",
            risk_score=max(75.0, risk_score) if terminated_processes else risk_score,
            threat_category=category,
            pid=inc_pid,
            process_name=inc_name,
            evidence_dict={
                "score_breakdown": risk_assessment["score_breakdown"],
                "triggered_rules": triggered_rules,
                "ml_inference": ml_result,
                "terminated_processes": terminated_processes,
                "file_activity": file_telemetry,
                "network_activity": net_telemetry
            },
            status="CONTAINED" if terminated_processes else "OPEN",
            containment_action=contain_summary
        )
    elif severity == "HIGH":
        response_action = "INCIDENT_ONGOING"  # same threat still active, already recorded
    elif severity == "MEDIUM":
        response_action = "ALERT"
        if _cooldown_ok(f"alert-{category}"):
            alert_id = create_alert(
                severity="MEDIUM",
                title=f"Elevated Activity Flagged ({threat_cat})",
                description=f"Elevated risk score ({risk_score}) detected. {len(triggered_rules)} rule(s) active.",
                risk_score=risk_score,
                triggered_rules=triggered_rules,
                threat_category=threat_cat
            )

    return {
        "risk_score": risk_score,
        "severity": severity,
        "threat_category": threat_cat,
        "response_action": response_action,
        "terminated_count": len(terminated_processes),
        "terminated_details": terminated_processes,
        "incident_id": incident_id,
        "incident_code": incident_code,
        "alert_id": alert_id
    }
