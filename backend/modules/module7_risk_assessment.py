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

def calculate_risk_score(rule_result: dict, ml_result: dict) -> dict:
    rule_score = float(rule_result.get("rule_score", 0.0))
    anomaly_score = float(ml_result.get("anomaly_score", 0.0))
    
    threat_category = ml_result.get("predicted_category", "Normal")
    confidence = float(ml_result.get("confidence", 0.0))
    
    # ML threat score component is 0 if Normal, else confidence * 100
    classifier_score = (confidence * 100.0) if threat_category != "Normal" else 0.0
    
    raw_risk = (WEIGHT_RULE * rule_score) + (WEIGHT_ANOMALY * anomaly_score) + (WEIGHT_CLASSIFIER * classifier_score)
    final_risk_score = min(100.0, max(0.0, raw_risk))
    
    # Determine Severity Level
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

def terminate_process_safe(pid: int, process_name: str) -> dict:
    """Attempts process termination safely with permission checks."""
    if pid <= 1000: # Protect system PIDs
        return {"success": False, "message": f"Protected system PID {pid} cannot be terminated."}
    try:
        if psutil.pid_exists(pid):
            p = psutil.Process(pid)
            p.terminate()
            p.wait(timeout=2)
            return {"success": True, "message": f"Process {process_name} (PID {pid}) terminated successfully."}
        else:
            return {"success": True, "message": f"Process PID {pid} already exited."}
    except (psutil.AccessDenied, PermissionError):
        return {"success": False, "message": f"Permission denied terminating PID {pid}. Safe simulation mode recorded."}
    except Exception as e:
        return {"success": False, "message": str(e)}

def triage_and_respond(proc_telemetry: dict, file_telemetry: dict, net_telemetry: dict, rule_result: dict, ml_result: dict, risk_assessment: dict):
    risk_score = risk_assessment["risk_score"]
    severity = risk_assessment["severity"]
    threat_cat = risk_assessment["threat_category"]
    
    triggered_rules = rule_result.get("triggered_rules", [])
    top_proc = proc_telemetry.get("processes", [{}])[0] if proc_telemetry.get("processes") else {}
    target_pid = top_proc.get("pid", 0)
    target_name = top_proc.get("name", "unknown_process")
    
    response_action = "LOG"
    incident_id = None
    incident_code = None
    alert_id = None
    
    # 1. LOW RISK (0-39): Log event only
    if severity == "LOW":
        log_event(
            event_type="NORMAL_TELEMETRY",
            process_count=proc_telemetry.get("process_count", 0),
            file_mod_rate=file_telemetry.get("file_mod_rate", 0.0),
            avg_entropy=file_telemetry.get("avg_file_entropy", 0.0),
            outbound_conns=net_telemetry.get("outbound_conn_count", 0),
            risk_score=risk_score,
            details_dict=risk_assessment
        )
        
    # 2. MEDIUM RISK (40-69): Generate Security Alert
    elif severity == "MEDIUM":
        response_action = "ALERT"
        alert_id = create_alert(
            severity="MEDIUM",
            title=f"Suspicious Behavior Detected ({threat_cat})",
            description=f"Elevated risk score of {risk_score} detected. {len(triggered_rules)} rule(s) triggered.",
            risk_score=risk_score,
            triggered_rules=triggered_rules,
            threat_category=threat_cat
        )
        
    # 3. HIGH RISK (70-100): Raise Incident & Apply Controlled Containment
    elif severity == "HIGH":
        response_action = "CONTAIN_AND_INCIDENT"
        evidence_dict = {
            "score_breakdown": risk_assessment["score_breakdown"],
            "triggered_rules": triggered_rules,
            "ml_inference": ml_result,
            "target_process": top_proc,
            "file_activity": file_telemetry,
            "network_activity": net_telemetry
        }
        
        # Containment attempt (Safe process kill / isolation)
        contain_result = terminate_process_safe(target_pid, target_name)
        contain_action_str = f"PROCESS_KILL (PID {target_pid})" if contain_result["success"] else f"ISOLATE_ALERT (PID {target_pid})"
        
        incident_id, incident_code = create_incident(
            severity="HIGH",
            risk_score=risk_score,
            threat_category=threat_cat,
            pid=target_pid,
            process_name=target_name,
            evidence_dict=evidence_dict,
            status="OPEN",
            containment_action=contain_action_str
        )
        
    return {
        "risk_score": risk_score,
        "severity": severity,
        "threat_category": threat_cat,
        "response_action": response_action,
        "incident_id": incident_id,
        "incident_code": incident_code,
        "alert_id": alert_id
    }
