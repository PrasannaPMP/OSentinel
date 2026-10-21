import asyncio
import json
import time
import threading
from typing import List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.config import POLL_INTERVAL_SEC
from backend.database import (
    init_db,
    get_recent_events,
    get_incidents,
    get_alerts,
    update_incident_status,
    create_incident
)
from backend.modules.module1_process import collect_process_telemetry
from backend.modules.module2_file import collect_file_telemetry
from backend.modules.module3_network import collect_network_telemetry
from backend.modules.module4_feature_extraction import extract_feature_vector
from backend.modules.module5_rule_engine import evaluate_rules
from backend.modules.module6_ml_engine import run_ml_inference, get_ml_metrics, load_ml_models
from backend.modules.module7_risk_assessment import calculate_risk_score, triage_and_respond, terminate_process_safe
from backend.modules.attack_simulator import trigger_attack_simulation, get_active_simulation
from backend.modules.train_models import train_and_save_models

app = FastAPI(
    title="OSentinel Security Framework API",
    description="Intelligent Host-Based Security Framework with 2-Stage ML & Real-Time SOC Telemetry",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global State Container
current_telemetry_state = {
    "status": "ONLINE",
    "timestamp": time.time(),
    "process_telemetry": {},
    "file_telemetry": {},
    "network_telemetry": {},
    "feature_dict": {},
    "rule_result": {},
    "ml_result": {},
    "risk_assessment": {},
    "triage_result": {},
    "active_simulation": None
}

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

def telemetry_polling_loop():
    """Background thread polling system telemetry and executing OSentinel detection pipeline."""
    global current_telemetry_state
    
    # Initialize DB & ML models
    init_db()
    load_ml_models()
    
    while True:
        try:
            # 1. Collect Telemetry
            proc_data = collect_process_telemetry()
            file_data = collect_file_telemetry()
            net_data = collect_network_telemetry()
            
            # 2. Extract Behavioral Feature Vector
            feat_out = extract_feature_vector(proc_data, file_data, net_data)
            feat_dict = feat_out["feature_dict"]
            feat_vec = feat_out["vector"]
            
            # 3. Rule Engine Evaluation
            rule_res = evaluate_rules(feat_dict)
            
            # 4. ML Engine Inference (Isolation Forest + Random Forest)
            ml_res = run_ml_inference(feat_vec, feat_dict)
            
            # 5. Risk Assessment (0-100 Score)
            risk_res = calculate_risk_score(rule_res, ml_res)
            
            # 6. Response Triage & Incident Engine
            triage_res = triage_and_respond(proc_data, file_data, net_data, rule_res, ml_res, risk_res)
            
            active_sim = get_active_simulation()
            
            # Update Global Telemetry Cache
            current_telemetry_state = {
                "status": "ONLINE",
                "timestamp": time.time(),
                "process_telemetry": proc_data,
                "file_telemetry": file_data,
                "network_telemetry": net_data,
                "feature_dict": feat_dict,
                "rule_result": rule_res,
                "ml_result": ml_res,
                "risk_assessment": risk_res,
                "triage_result": triage_res,
                "active_simulation": active_sim
            }
            
        except Exception as e:
            print(f"[OSentinel Loop Error] {e}")
            
        time.sleep(POLL_INTERVAL_SEC)

# Start background monitoring loop thread on startup
@app.on_event("startup")
def startup_event():
    t = threading.Thread(target=telemetry_polling_loop, daemon=True)
    t.start()

# --- REST ENDPOINTS ---

@app.get("/api/status")
def get_system_status():
    return current_telemetry_state

@app.get("/api/processes")
def get_processes():
    return current_telemetry_state.get("process_telemetry", {})

@app.get("/api/incidents")
def fetch_incidents():
    return get_incidents(50)

@app.get("/api/alerts")
def fetch_alerts():
    return get_alerts(50)

@app.get("/api/events")
def fetch_events():
    return get_recent_events(50)

@app.get("/api/metrics")
def fetch_ml_metrics():
    return get_ml_metrics()

class AttackSimRequest(BaseModel):
    attack_type: str

@app.post("/api/simulate")
def simulate_attack(req: AttackSimRequest):
    res = trigger_attack_simulation(req.attack_type)
    return res

class ContainRequest(BaseModel):
    incident_id: int
    pid: int
    process_name: str
    action: str  # "TERMINATE" or "IGNORE"

@app.post("/api/contain")
def contain_incident(req: ContainRequest):
    if req.action == "TERMINATE":
        res = terminate_process_safe(req.pid, req.process_name)
        update_incident_status(req.incident_id, "RESOLVED", f"MANUAL_TERMINATE (PID {req.pid})")
        return {"success": True, "message": res["message"]}
    else:
        update_incident_status(req.incident_id, "DISMISSED", "MANUAL_IGNORE")
        return {"success": True, "message": "Incident marked as dismissed."}

@app.post("/api/retrain")
def retrain_models(background_tasks: BackgroundTasks):
    background_tasks.add_task(train_and_save_models)
    return {"success": True, "message": "Model retraining job queued in background."}

# --- WEBSOCKET ENDPOINT ---

@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.send_json(current_telemetry_state)
            await asyncio.sleep(POLL_INTERVAL_SEC)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
