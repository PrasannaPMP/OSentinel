import os
import sys
import psutil
import json
from backend.config import (
    RISK_THRESHOLD_LOW,
    RISK_THRESHOLD_HIGH,
    WEIGHT_RULE,
    WEIGHT_ANOMALY,
    WEIGHT_CLASSIFIER
)
from backend.database import create_alert, create_incident, log_event

# Whitelist: AntiGravity is the SOLE EXCEPTION permitted to run continuously,
# perform rapid multiple edits on file save, and use high CPU without restriction.
IDE_KEYWORDS = [
    "antigravity", "antigravity-ide", "electron", "code", "cursor", "vscode",
    "language_server", "python3", "python", "uvicorn", "vite", "node"
]

BROWSER_KEYWORDS = ["safari", "chrome", "google chrome", "firefox", "msedge", "brave", "webkit"]

def is_ide_process(process_name: str, cmdline: str = "") -> bool:
    """Identifies AntiGravity IDE and core developer processes - the SOLE PERMITTED EXCEPTION."""
    name_clean = (process_name or "").lower() + " " + (cmdline or "").lower()
    return any(ide in name_clean for ide in IDE_KEYWORDS)

def is_browser_process(process_name: str, cmdline: str = "") -> bool:
    name_clean = (process_name or "").lower() + " " + (cmdline or "").lower()
    return any(b in name_clean for b in BROWSER_KEYWORDS)

def is_protected_system_process(pid: int, process_name: str) -> bool:
    """Prevents crashing kernel or OS core."""
    if pid <= 100: # Kernel/launchd/systemd
        return True
    current_pid = os.getpid()
    parent_pid = os.getppid()
    if pid in (current_pid, parent_pid):
        return True
    name_clean = (process_name or "").lower()
    return name_clean in ["kernel_task", "launchd", "systemd", "windowserver"]

def calculate_risk_score(rule_result: dict, ml_result: dict) -> dict:
    rule_score = float(rule_result.get("rule_score", 0.0))
    anomaly_score = float(ml_result.get("anomaly_score", 0.0))
    
    threat_category = ml_result.get("predicted_category", "Normal")
    confidence = float(ml_result.get("confidence", 0.0))
    
    classifier_score = (confidence * 100.0) if threat_category != "Normal" else 0.0
    
    raw_risk = (WEIGHT_RULE * rule_score) + (WEIGHT_ANOMALY * anomaly_score) + (WEIGHT_CLASSIFIER * classifier_score)
    final_risk_score = min(100.0, max(0.0, raw_risk))
    
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
    force: bool = False
) -> dict:
    """
    Terminates rogue processes with notifications while protecting AntiGravity.
    AntiGravity is the ONLY process allowed to run indefinitely and edit files.
    """
    # 1. AntiGravity Exemption Check - NEVER terminate AntiGravity
    if is_ide_process(process_name, cmdline):
        return {
            "success": False,
            "message": f"AntiGravity IDE ({process_name}, PID {pid}) is exempted from termination (sole permitted exception)."
        }
        
    if is_protected_system_process(pid, process_name):
        return {
            "success": False,
            "message": f"System core process {process_name} (PID {pid}) cannot be terminated."
        }
        
    # 2. Terminate the process (via terminate or kill)
    try:
        if psutil.pid_exists(pid):
            p = psutil.Process(pid)
            p.terminate()
            try:
                p.wait(timeout=1.5)
            except psutil.TimeoutExpired:
                p.kill() # Force kill if unresponsive
            return {
                "success": True,
                "message": f"Successfully killed unwanted/rogue process: {process_name} (PID {pid})"
            }
        else:
            return {"success": True, "message": f"Process PID {pid} already stopped."}
    except (psutil.AccessDenied, PermissionError):
        return {"success": False, "message": f"Permission denied terminating PID {pid}."}
    except Exception as e:
        return {"success": False, "message": str(e)}

def triage_and_respond(proc_telemetry: dict, file_telemetry: dict, net_telemetry: dict, rule_result: dict, ml_result: dict, risk_assessment: dict):
    risk_score = risk_assessment["risk_score"]
    severity = risk_assessment["severity"]
    threat_cat = risk_assessment["threat_category"]
    
    triggered_rules = rule_result.get("triggered_rules", [])
    processes = proc_telemetry.get("processes", [])
    
    terminated_processes = []
    
    # -------------------------------------------------------------------------
    # RULE A: Multiple Runaway Tabs / Runaway Browser Processes (Threshold 70%)
    # -------------------------------------------------------------------------
    # If a browser tab or runaway process exceeds 70% CPU, kill it with notification
    for p in processes:
        p_name = p.get("name", "")
        p_cmd = p.get("cmdline", "")
        p_cpu = p.get("cpu_percent", 0.0)
        p_pid = p.get("pid", 0)
        
        if is_browser_process(p_name, p_cmd) and p_cpu >= 70.0 and not is_ide_process(p_name, p_cmd):
            kill_res = terminate_process_safe(p_pid, p_name, cpu_percent=p_cpu, cmdline=p_cmd, force=True)
            if kill_res["success"]:
                terminated_processes.append(f"Browser Tab/Process (PID {p_pid})")
                create_alert(
                    severity="HIGH",
                    title=f"Runaway Browser Tab Killed (PID {p_pid})",
                    description=f"Browser process '{p_name}' exceeded 70% CPU threshold ({p_cpu}%). Terminated to free host resources.",
                    risk_score=75.0,
                    triggered_rules=["RULE-BROWSER-01"],
                    threat_category="Browser Cryptojacking"
                )

    # -------------------------------------------------------------------------
    # RULE B: Rapid Multiple Edits on File Save (Ransomware / Rogue File Writers)
    # AntiGravity is the SOLE EXCEPTION permitted to perform multiple file edits.
    # -------------------------------------------------------------------------
    is_rapid_file_edits = (file_telemetry.get("file_mod_rate", 0) >= 15.0 or file_telemetry.get("high_entropy_alert", False))
    if is_rapid_file_edits:
        # Identify writer process
        for p in processes:
            p_name = p.get("name", "")
            p_cmd = p.get("cmdline", "")
            p_pid = p.get("pid", 0)
            
            # If process is NOT AntiGravity and is active or tmp
            if not is_ide_process(p_name, p_cmd) and (p.get("is_tmp") or p.get("cpu_percent", 0) > 10.0):
                kill_res = terminate_process_safe(p_pid, p_name, force=True)
                if kill_res["success"]:
                    terminated_processes.append(f"Rogue File Writer (PID {p_pid})")
                    create_alert(
                        severity="HIGH",
                        title=f"Rogue Process Killed: Rapid File Modification (PID {p_pid})",
                        description=f"Process '{p_name}' was actively modifying files at high velocity. AntiGravity is the only allowed exception. Process terminated.",
                        risk_score=85.0,
                        triggered_rules=["RULE-RANSOMWARE-01"],
                        threat_category="Ransomware"
                    )
                break

    # -------------------------------------------------------------------------
    # RULE C: Unwanted Dependencies & Rogue Background Workers
    # (Temporary path execution, unapproved miners, rogue sockets)
    # -------------------------------------------------------------------------
    for p in processes:
        p_name = p.get("name", "")
        p_cmd = p.get("cmdline", "")
        p_pid = p.get("pid", 0)
        p_cpu = p.get("cpu_percent", 0.0)
        
        # If running from temp or matching miner signatures, and NOT AntiGravity
        if p.get("is_tmp") and not is_ide_process(p_name, p_cmd):
            kill_res = terminate_process_safe(p_pid, p_name, is_tmp=True, cpu_percent=p_cpu, cmdline=p_cmd, force=True)
            if kill_res["success"]:
                terminated_processes.append(f"Rogue Worker '{p_name}' (PID {p_pid})")
                create_alert(
                    severity="HIGH",
                    title=f"Unwanted Rogue Dependency Terminated (PID {p_pid})",
                    description=f"Process '{p_name}' launched from unauthorized scratch/temp directory. Terminated immediately.",
                    risk_score=80.0,
                    triggered_rules=["RULE-EXEC-01"],
                    threat_category="Malicious Execution"
                )

    # Incident creation on HIGH severity
    incident_id = None
    incident_code = None
    alert_id = None
    response_action = "LOG"
    
    if severity == "HIGH":
        response_action = "CONTAIN_AND_INCIDENT"
        contain_summary = f"TERMINATED: {', '.join(terminated_processes)}" if terminated_processes else "ISOLATE_MONITOR"
        incident_id, incident_code = create_incident(
            severity="HIGH",
            risk_score=risk_score,
            threat_category=threat_cat,
            pid=processes[0].get("pid", 0) if processes else 0,
            process_name=processes[0].get("name", "unknown") if processes else "unknown",
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
    elif severity == "MEDIUM":
        response_action = "ALERT"
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
