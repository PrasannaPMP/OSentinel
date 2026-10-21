import sqlite3
import json
import time
from datetime import datetime
from backend.config import DB_PATH

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Table 1: Events Log (System Telemetry snapshots)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        event_type TEXT,
        process_count INTEGER,
        file_mod_rate REAL,
        avg_entropy REAL,
        outbound_conns INTEGER,
        risk_score REAL,
        details TEXT
    );
    """)

    # Table 2: Security Alerts (Medium & High Risk alerts)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        severity TEXT,
        title TEXT,
        description TEXT,
        risk_score REAL,
        triggered_rules TEXT,
        threat_category TEXT,
        is_read INTEGER DEFAULT 0
    );
    """)

    # Table 3: Security Incidents (High Risk incidents requiring triage/action)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        incident_code TEXT UNIQUE,
        severity TEXT,
        risk_score REAL,
        threat_category TEXT,
        pid INTEGER,
        process_name TEXT,
        evidence TEXT,
        status TEXT DEFAULT 'OPEN',
        containment_action TEXT
    );
    """)

    # Table 4: Containment Logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS containments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        incident_id INTEGER,
        target_pid INTEGER,
        target_name TEXT,
        action_taken TEXT,
        status TEXT,
        details TEXT
    );
    """)

    # Table 5: ML Metrics History
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ml_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        accuracy REAL,
        precision REAL,
        recall REAL,
        f1_score REAL,
        model_version TEXT
    );
    """)

    conn.commit()
    conn.close()

def log_event(event_type, process_count, file_mod_rate, avg_entropy, outbound_conns, risk_score, details_dict):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO events (event_type, process_count, file_mod_rate, avg_entropy, outbound_conns, risk_score, details)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (event_type, process_count, file_mod_rate, avg_entropy, outbound_conns, risk_score, json.dumps(details_dict))
    )
    conn.commit()
    conn.close()

def create_alert(severity, title, description, risk_score, triggered_rules, threat_category):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO alerts (severity, title, description, risk_score, triggered_rules, threat_category)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (severity, title, description, risk_score, json.dumps(triggered_rules), threat_category)
    )
    conn.commit()
    alert_id = cursor.lastrowid
    conn.close()
    return alert_id

def create_incident(severity, risk_score, threat_category, pid, process_name, evidence_dict, status="OPEN", containment_action="NONE"):
    conn = get_db()
    cursor = conn.cursor()
    inc_code = f"INC-{int(time.time()*1000)%1000000:06d}"
    cursor.execute(
        """INSERT INTO incidents (incident_code, severity, risk_score, threat_category, pid, process_name, evidence, status, containment_action)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (inc_code, severity, risk_score, threat_category, pid, process_name, json.dumps(evidence_dict), status, containment_action)
    )
    conn.commit()
    inc_id = cursor.lastrowid
    conn.close()
    return inc_id, inc_code

def get_recent_events(limit=50):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_incidents(limit=50):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_alerts(limit=50):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def update_incident_status(incident_id, status, containment_action=None):
    conn = get_db()
    cursor = conn.cursor()
    if containment_action:
        cursor.execute("UPDATE incidents SET status = ?, containment_action = ? WHERE id = ?", (status, containment_action, incident_id))
    else:
        cursor.execute("UPDATE incidents SET status = ? WHERE id = ?", (status, incident_id))
    conn.commit()
    conn.close()
