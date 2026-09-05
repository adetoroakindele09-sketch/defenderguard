from flask import Flask, jsonify, send_file
from flask_cors import CORS

import database
import sqlite3
import os
import csv
import hashlib
from datetime import datetime

from routes.auth_routes import auth
from routes.scan_routes import scan
from routes.activity_routes import activity


# ==========================================
# CREATE FLASK APPLICATION
# ==========================================

app = Flask(__name__)

# Create/migrate the SQLite schema at startup.
database.create_database()

CORS(app)


# ==========================================
# REGISTER ROUTES
# ==========================================

app.register_blueprint(auth)
app.register_blueprint(scan)
app.register_blueprint(activity)


# ==========================================
# SHOW REGISTERED ROUTES
# ==========================================

print("\n==========================================")
print("REGISTERED FLASK ROUTES")
print("==========================================")

print(app.url_map)

print("==========================================\n")


# ==========================================
# HOME
# ==========================================

@app.route("/")
def home():

    return jsonify({

        "message":
        "Malware Detection Backend Running"

    })


# ==========================================
# REAL-TIME DASHBOARD STATISTICS
# ==========================================

# Dashboard session starts when Flask starts. This prevents old/demo database
# records from appearing as if they were live events in the current session.
from datetime import datetime, timezone
DASHBOARD_SESSION_START = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


@app.get("/api/dashboard/stats")
def dashboard_stats():
    """Return current-session, user-specific scan and agent activity statistics."""
    import os
    import sqlite3

    email = request.args.get("email", "").strip().lower()

    database_path = os.path.join(os.path.dirname(__file__), "database.db")
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row

    user_id = None
    if email:
        user_row = conn.execute(
            "SELECT id FROM users WHERE LOWER(email)=?",
            (email,)
        ).fetchone()
        if user_row:
            user_id = user_row["id"]
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Only scans created after this Flask session started count on the dashboard.
    if user_id is not None:
        scans = cur.execute("""
            SELECT file_name, prediction, confidence, threat_level, scan_time
            FROM scan_history
            WHERE scan_time >= ? AND user_id=?
            ORDER BY id DESC
        """, (DASHBOARD_SESSION_START, user_id)).fetchall()
    else:
        scans = []

    scan_safe = sum(str(r["prediction"] or "").lower() in ("safe", "benign") for r in scans)
    scan_malware = sum(str(r["prediction"] or "").lower() in ("malware", "malicious") for r in scans)
    scan_alerts = sum(
        str(r["prediction"] or "").lower() in ("malware", "malicious", "suspicious", "warning")
        or str(r["threat_level"] or "").lower() in ("high", "medium", "suspicious", "warning")
        for r in scans
    )

    # IMPORTANT: do not use the process-global local monitor for dashboard counts.
    # Dashboard statistics must be isolated per user.
    # Real-time monitoring data comes from the authenticated remote agent events below.
    live_monitoring = False
    monitor_folder = None
    live_events = []
    live_features = {
        "status": "Safe", "score": 0, "total_events": 0,
        "write_count": 0, "delete_count": 0, "create_count": 0,
        "rename_count": 0, "write_entropy": 0, "ext_diversity": 0,
        "sensitive_path_access": 0, "read_write_ratio": 0,
        "reasons": []
    }

    live_safe = sum(str(e.get("status", "")).lower() == "safe" for e in live_events)
    live_warning = sum(str(e.get("status", "")).lower() in ("warning", "suspicious") for e in live_events)

    # We never label a behavioural Warning/Suspicious event as confirmed malware.
    # Confirmed malware comes only from an actual file scan prediction.
    malware_detected = scan_malware
    threat_alerts = scan_alerts + live_warning

    total_files = len({str(e.get("path") or e.get("filename")) for e in live_events}) + len(scans)
    safe_files = live_safe + scan_safe

    if malware_detected > 0:
        threat_level = "HIGH RISK"
        notification = "A scanned file was classified as malware. Review the latest scan result."
    elif live_warning > 0 or scan_alerts > 0:
        threat_level = "MEDIUM RISK"
        notification = "Suspicious or warning-level activity is being observed."
    else:
        threat_level = "LOW RISK"
        notification = "No elevated threat activity has been observed in this session."

    # Include events received from the authorized Monitoring Agent.
    remote_events = []
    agent_connected = False
    agent_monitoring_enabled = False
    monitor_folder = None
    try:
        if user_id is not None:
            device = cur.execute("""
                SELECT id, device_name, last_seen, monitoring_enabled
                FROM agent_devices
                WHERE user_id=?
                ORDER BY id DESC
                LIMIT 1
            """, (user_id,)).fetchone()
            if device:
                last_seen = device["last_seen"]
                agent_monitoring_enabled = bool(device["monitoring_enabled"])
                if last_seen:
                    try:
                        seen_dt = datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
                        if seen_dt.tzinfo is None:
                            seen_dt = seen_dt.replace(tzinfo=timezone.utc)
                        agent_connected = (datetime.now(timezone.utc) - seen_dt).total_seconds() <= 45
                    except ValueError:
                        agent_connected = True
                monitor_folder = "all accessible Windows drives" if agent_monitoring_enabled else "monitoring paused"

            remote_query = cur.execute("""
                SELECT e.filename, e.activity, e.status, e.event_time, e.process, e.path, d.device_name
                FROM agent_events e
                JOIN agent_devices d ON d.id=e.device_id
                WHERE e.user_id=?
                ORDER BY e.id DESC LIMIT 100
            """, (user_id,)).fetchall()
        else:
            remote_query = []
        remote_events = [dict(r) for r in remote_query]
    except sqlite3.Error:
        remote_events = []

    remote_warning = sum(str(e.get("status", "")).lower() in ("warning", "suspicious", "malware", "malicious") for e in remote_events)
    remote_safe = sum(str(e.get("status", "")).lower() == "safe" for e in remote_events)
    threat_alerts += remote_warning
    safe_files += remote_safe
    total_files += len(remote_events)
    live_monitoring = agent_connected and agent_monitoring_enabled

    # Show the newest user-specific remote agent events and scan results.
    combined_events = []
    for e in live_events:
        combined_events.append({
            "file": e.get("filename", "Unknown"),
            "status": e.get("status", "Safe"),
            "time": e.get("time"),
            "activity": e.get("activity"),
            "process": e.get("process", "Unknown")
        })
    for e in remote_events:
        combined_events.append({
            "file": e.get("filename", "Unknown"),
            "status": e.get("status", "Safe"),
            "time": e.get("event_time"),
            "activity": e.get("activity"),
            "process": e.get("process", "Unknown"),
            "device": e.get("device_name", "Remote PC")
        })
    combined_events.sort(key=lambda x: str(x.get("time") or ""), reverse=True)

    if combined_events:
        recent_activity = combined_events[:8]
    else:
        recent_activity = [
            {
                "file": r["file_name"] or "Unknown",
                "status": r["prediction"] or "Pending",
                "time": r["scan_time"]
            }
            for r in scans[:8]
        ]

    chart = {
        "safe": safe_files,
        "warning": live_warning + max(0, scan_alerts - scan_malware),
        "malware": malware_detected
    }

    conn.close()
    return jsonify(success=True, stats={
        "total_files": total_files,
        "safe_files": safe_files,
        "malware_detected": malware_detected,
        "threat_alerts": threat_alerts,
        "threat_level": threat_level,
        "notification": notification,
        "recent_activity": recent_activity,
        "chart": chart,
        "live_monitoring": live_monitoring,
        "monitor_folder": monitor_folder,
        "live_features": live_features,
        "session_started": DASHBOARD_SESSION_START
    })



# ==========================================
# REAL REPORT STATISTICS
# ==========================================

@app.get("/report/stats")
def report_stats():
    """Return current-session report statistics for the logged-in account."""
    database_path = os.path.join(os.path.dirname(__file__), "database.db")
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row
    email = request.args.get("email", "").strip().lower()
    user = conn.execute("SELECT id FROM users WHERE LOWER(email)=?", (email,)).fetchone() if email else None
    if not user:
        conn.close()
        return jsonify(success=False, message="User account not found."), 404
    rows = conn.execute("""
        SELECT id, file_name, prediction, confidence, threat_level, scan_time,
               detection_score, write_count, delete_count, create_count, rename_count
        FROM scan_history
        WHERE scan_time >= ? AND user_id=?
        ORDER BY id DESC
    """, (DASHBOARD_SESSION_START, user["id"])).fetchall()
    conn.close()

    total = len(rows)
    malware = sum(str(r["prediction"] or "").lower() in ("malware", "malicious") for r in rows)
    safe = sum(str(r["prediction"] or "").lower() in ("safe", "benign") for r in rows)
    warning = max(0, total - malware - safe)
    threat_rate = round(((malware + warning) / total) * 100, 1) if total else 0

    history = []
    for r in rows[:100]:
        prediction = str(r["prediction"] or "Pending")
        status = "Malware Detected" if prediction.lower() in ("malware", "malicious") else ("Warning" if prediction.lower() in ("warning", "suspicious") else "Safe")
        history.append({
            "id": r["id"],
            "file": r["file_name"],
            "date": r["scan_time"],
            "files": 1,
            "threats": 1 if status != "Safe" else 0,
            "status": status,
            "prediction": prediction,
            "confidence": r["confidence"],
            "risk": r["threat_level"],
            "score": r["detection_score"],
            "write_count": r["write_count"],
            "delete_count": r["delete_count"],
            "create_count": r["create_count"],
            "rename_count": r["rename_count"]
        })

    return jsonify(success=True, stats={
        "total_scans": total,
        "files_checked": total,
        "malware_detected": malware,
        "warnings": warning,
        "threat_rate": threat_rate,
        "last_scan": history[0]["date"] if history else None,
        "history": history,
        "chart": {"safe": safe, "warning": warning, "malware": malware},
        "session_started": DASHBOARD_SESSION_START
    })


@app.get("/report/export.csv")
def report_export_csv():
    """Export current-session scan records for the logged-in account."""
    database_path = os.path.join(os.path.dirname(__file__), "database.db")
    conn = sqlite3.connect(database_path)
    email = request.args.get("email", "").strip().lower()
    user = conn.execute("SELECT id FROM users WHERE LOWER(email)=?", (email,)).fetchone() if email else None
    if not user:
        conn.close()
        return jsonify(success=False, message="User account not found."), 404
    rows = conn.execute("""
        SELECT id,file_name,file_path,prediction,confidence,threat_level,scan_time,
               write_count,delete_count,create_count,rename_count,write_entropy,
               ext_diversity,sensitive_path_access,read_write_ratio,detection_score,
               detection_reasons
        FROM scan_history WHERE scan_time >= ? AND user_id=? ORDER BY id DESC
    """, (DASHBOARD_SESSION_START, user["id"])).fetchall()
    conn.close()

    out=os.path.join(os.path.dirname(__file__),"uploads","security_report.csv")
    os.makedirs(os.path.dirname(out),exist_ok=True)
    with open(out,"w",newline="",encoding="utf-8-sig") as f:
        w=csv.writer(f)
        w.writerow(["Scan ID","File Name","Path","Prediction","Confidence","Risk","Time",
                    "Write Count","Delete Count","Create Count","Rename Count","Write Entropy",
                    "Extension Diversity","Sensitive Path Access","Read/Write Ratio","Detection Score","Reasons"])
        w.writerows(rows)
    return send_file(out,as_attachment=True,download_name="security_report.csv",mimetype="text/csv")

# ==========================================
# REAL DETECTION RESULTS
# ==========================================

@app.get("/detection/results")
def detection_results():
    """Return only this account's scans created during the current session."""
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), "database.db"))
    conn.row_factory = sqlite3.Row
    email = request.args.get("email", "").strip().lower()
    user = conn.execute("SELECT id FROM users WHERE LOWER(email)=?", (email,)).fetchone() if email else None
    if not user:
        conn.close()
        return jsonify(success=False, message="User account not found."), 404
    rows = conn.execute("""
        SELECT id, file_name, file_path, file_size, prediction, confidence,
               threat_level, scan_time, write_count, delete_count, create_count,
               rename_count, write_entropy, ext_diversity, sensitive_path_access,
               read_write_ratio, hidden_file_activity, execution_attempts,
               detection_score, detection_reasons
        FROM scan_history
        WHERE scan_time >= ? AND user_id=?
        ORDER BY id DESC
        LIMIT 500
    """, (DASHBOARD_SESSION_START, user["id"])).fetchall()
    conn.close()

    results=[]
    for r in rows:
        item=dict(r)
        path=item.get("file_path") or ""
        item["extension"] = os.path.splitext(item.get("file_name") or "")[1].lower() or "none"
        item["reasons"] = [x.strip() for x in (item.get("detection_reasons") or "").split(";") if x.strip()]
        item["sha256"] = None
        if path and os.path.isfile(path):
            try:
                h=hashlib.sha256()
                with open(path,"rb") as f:
                    for chunk in iter(lambda: f.read(1024*1024), b""):
                        h.update(chunk)
                item["sha256"] = h.hexdigest()
            except OSError:
                pass
        results.append(item)

    summary={
        "total": len(results),
        "safe": sum(str(x.get("prediction","")).lower() in ("safe","benign") for x in results),
        "malware": sum(str(x.get("prediction","")).lower()=="malware" for x in results),
        "high_risk": sum(str(x.get("threat_level","")).upper() in ("HIGH","CRITICAL","HIGH RISK") for x in results),
        "last_scan": results[0]["scan_time"] if results else None,
    }
    return jsonify(success=True, session_started=DASHBOARD_SESSION_START, summary=summary, results=results)


@app.get("/detection/export.csv")
def detection_export_csv():
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), "database.db"))
    email = request.args.get("email", "").strip().lower()
    user = conn.execute("SELECT id FROM users WHERE LOWER(email)=?", (email,)).fetchone() if email else None
    if not user:
        conn.close()
        return jsonify(success=False, message="User account not found."), 404
    rows = conn.execute("""
        SELECT id,file_name,file_path,prediction,confidence,threat_level,scan_time,
               write_count,delete_count,create_count,rename_count,write_entropy,
               ext_diversity,sensitive_path_access,read_write_ratio,detection_score,
               detection_reasons
        FROM scan_history WHERE scan_time >= ? AND user_id=? ORDER BY id DESC
    """, (DASHBOARD_SESSION_START, user["id"])).fetchall()
    conn.close()
    out=os.path.join(os.path.dirname(__file__),"uploads","detection_results.csv")
    os.makedirs(os.path.dirname(out),exist_ok=True)
    with open(out,"w",newline="",encoding="utf-8-sig") as f:
        w=csv.writer(f)
        w.writerow(["Scan ID","File Name","Path","Prediction","Confidence","Risk","Time",
                    "Write Count","Delete Count","Create Count","Rename Count","Write Entropy",
                    "Extension Diversity","Sensitive Path Access","Read/Write Ratio","Detection Score","Reasons"])
        w.writerows(rows)
    return send_file(out,as_attachment=True,download_name="detection_results.csv",mimetype="text/csv")

# ==========================================
# AGENT DOWNLOAD AND REMOTE EVENT API
# ==========================================

from flask import request, Response
import io
import json
import secrets
import zipfile

AGENT_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "agent_template")


def _agent_db():
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), "database.db"))
    conn.row_factory = sqlite3.Row
    return conn


@app.post("/api/agent/pair")
def pair_agent():
    """Create a device token for a logged-in dashboard user."""
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    device_name = str(data.get("device_name", "")).strip() or "Windows-PC"
    if not email:
        return jsonify(success=False, message="User email is required."), 400

    conn = _agent_db()
    user = conn.execute("SELECT id, email FROM users WHERE email=?", (email,)).fetchone()
    if not user:
        conn.close()
        return jsonify(success=False, message="User account not found."), 404

    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO agent_devices(user_id, device_name, token, monitoring_enabled) VALUES(?,?,?,1)",
        (user["id"], device_name, token)
    )
    conn.commit()
    conn.close()
    return jsonify(success=True, token=token, device_name=device_name)


@app.get("/api/agent/download")
def download_agent():
    """Return a personalized agent ZIP using the device token supplied by the dashboard."""
    token = request.args.get("token", "").strip()
    if not token:
        return jsonify(success=False, message="Missing device token."), 400

    conn = _agent_db()
    device = conn.execute("SELECT id, token FROM agent_devices WHERE token=?", (token,)).fetchone()
    conn.close()
    if not device:
        return jsonify(success=False, message="Invalid device token."), 403

    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w", zipfile.ZIP_DEFLATED) as z:
        for name in ("agent.py", "requirements.txt", "run_agent.bat", "README.md"):
            path = os.path.join(AGENT_TEMPLATE_DIR, name)
            if os.path.isfile(path):
                z.write(path, name)
        config = {
            "server_url": request.host_url.rstrip("/"),
            "device_token": token,
            "watch_folder": "",
            "watch_all_drives": True
        }
        z.writestr("config.json", json.dumps(config, indent=2))
    memory.seek(0)
    return send_file(memory, as_attachment=True, download_name="DAVE-Monitor-Agent.zip", mimetype="application/zip")


@app.post("/api/agent/events")
def receive_agent_event():
    """Receive authorized file-event metadata and classify unusual activity conservatively."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
    if not token:
        return jsonify(success=False, message="Agent authorization required."), 401

    data = request.get_json(silent=True) or {}
    conn = _agent_db()
    device = conn.execute(
        "SELECT id, user_id, device_name FROM agent_devices WHERE token=?", (token,)
    ).fetchone()
    if not device:
        conn.close()
        return jsonify(success=False, message="Invalid agent token."), 403

    activity = str(data.get("event", "unknown")).strip().lower()
    filename = str(data.get("name", "Unknown"))
    extension = str(data.get("extension", "")).lower()
    path = str(data.get("path", ""))
    process = str(data.get("process", "Unknown"))

    # Conservative behavioural score. This is an anomaly warning, not proof
    # that malware exists. Confirmed malware comes from the static file scan.
    recent = conn.execute("""
        SELECT activity, extension, path
        FROM agent_events
        WHERE device_id=? AND datetime(event_time) >= datetime('now','-10 seconds')
        ORDER BY id DESC LIMIT 100
    """, (device["id"],)).fetchall()

    create_n = sum(str(r["activity"]).lower() == "created" for r in recent)
    modify_n = sum(str(r["activity"]).lower() == "modified" for r in recent)
    delete_n = sum(str(r["activity"]).lower() == "deleted" for r in recent)
    rename_n = sum(str(r["activity"]).lower() == "renamed" for r in recent)

    score = 0.0
    reasons = []
    if delete_n >= 8:
        score += 30; reasons.append("high delete activity")
    elif delete_n >= 4:
        score += 15; reasons.append("elevated delete activity")
    if create_n >= 12:
        score += 25; reasons.append("high file creation activity")
    elif create_n >= 6:
        score += 12; reasons.append("elevated file creation activity")
    if rename_n >= 8:
        score += 20; reasons.append("high rename activity")
    if modify_n >= 25:
        score += 20; reasons.append("high modification activity")
    if extension in {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi"}:
        score += 15; reasons.append("executable or script file activity")

    score = min(100.0, score)
    if score >= 70:
        status = "Suspicious"
    elif score >= 40:
        status = "Warning"
    else:
        status = "Safe"
    if not reasons:
        reasons = ["no strong elevated activity pattern detected"]

    event_time = data.get("timestamp") or datetime.utcnow().isoformat()
    conn.execute("""
        INSERT INTO agent_events
        (user_id, device_id, device_name, filename, extension, activity, path, process, status, score, event_time, reasons)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        device["user_id"], device["id"], data.get("device_name") or device["device_name"],
        filename, extension, activity, path, process, status, score, event_time, "; ".join(reasons)
    ))
    conn.execute("UPDATE agent_devices SET last_seen=CURRENT_TIMESTAMP WHERE id=?", (device["id"],))
    conn.commit()
    conn.close()
    return jsonify(success=True, message="Event received.", status=status, score=score, reasons=reasons)


@app.post("/api/agent/heartbeat")
def agent_heartbeat():
    """Keep the agent connection alive even when no file event is occurring."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
    if not token:
        return jsonify(success=False, message="Agent authorization required."), 401

    conn = _agent_db()
    device = conn.execute(
        "SELECT id FROM agent_devices WHERE token=?",
        (token,)
    ).fetchone()

    if not device:
        conn.close()
        return jsonify(success=False, message="Invalid agent token."), 403

    conn.execute(
        "UPDATE agent_devices SET last_seen=CURRENT_TIMESTAMP WHERE id=?",
        (device["id"],)
    )
    conn.commit()
    conn.close()

    return jsonify(success=True, message="Heartbeat received.")


@app.route("/api/agent/control", methods=["GET", "POST"])
def agent_control():
    """Read or change monitoring state without terminating the agent process."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
    if not token:
        return jsonify(success=False, message="Agent authorization required."), 401

    conn = _agent_db()
    device = conn.execute(
        "SELECT id, device_name, monitoring_enabled FROM agent_devices WHERE token=?",
        (token,)
    ).fetchone()

    if not device:
        conn.close()
        return jsonify(success=False, message="Invalid agent token."), 403

    if request.method == "GET":
        enabled = bool(device["monitoring_enabled"])
        conn.close()
        return jsonify(success=True, monitoring_enabled=enabled, device_name=device["device_name"])

    data = request.get_json(silent=True) or {}
    action = str(data.get("action", "")).strip().lower()
    if action not in {"start", "stop"}:
        conn.close()
        return jsonify(success=False, message="Action must be start or stop."), 400

    enabled = 1 if action == "start" else 0
    conn.execute(
        "UPDATE agent_devices SET monitoring_enabled=? WHERE id=?",
        (enabled, device["id"])
    )
    conn.commit()
    conn.close()

    return jsonify(
        success=True,
        monitoring_enabled=bool(enabled),
        message=("Monitoring started." if enabled else "Monitoring stopped.")
    )


@app.post("/api/agent/clear-log")
def agent_clear_log():
    """Clear saved file-activity events for the authenticated agent/account."""
    data = request.get_json(silent=True) or {}
    token = str(data.get("token", "")).strip()
    email = str(data.get("email", "")).strip().lower()

    conn = _agent_db()

    if token:
        device = conn.execute(
            "SELECT id, user_id FROM agent_devices WHERE token=?",
            (token,)
        ).fetchone()
        if not device:
            conn.close()
            return jsonify(success=False, message="Invalid agent token."), 403
        cursor = conn.execute(
            "DELETE FROM agent_events WHERE device_id=?",
            (device["id"],)
        )
    elif email:
        user = conn.execute(
            "SELECT id FROM users WHERE LOWER(email)=?",
            (email,)
        ).fetchone()
        if not user:
            conn.close()
            return jsonify(success=False, message="User account not found."), 404
        cursor = conn.execute(
            "DELETE FROM agent_events WHERE user_id=?",
            (user["id"],)
        )
    else:
        conn.close()
        return jsonify(success=False, message="Agent token or email is required."), 400

    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return jsonify(success=True, deleted=int(deleted), message="Activity log cleared.")


@app.get("/api/agent/status")
def agent_status():
    """Return agent connection state plus recent events for the logged-in user."""
    email = request.args.get("email", "").strip().lower()
    if not email:
        return jsonify(success=False, message="Email is required."), 400

    conn = _agent_db()

    user = conn.execute(
        "SELECT id FROM users WHERE LOWER(email)=?",
        (email,)
    ).fetchone()

    if not user:
        conn.close()
        return jsonify(
            success=True,
            connected=False,
            device=None,
            events=[],
            totals={
                "Created": 0, "Modified": 0,
                "Deleted": 0, "Renamed": 0
            }
        )

    device = conn.execute("""
        SELECT id, device_name, last_seen, monitoring_enabled
        FROM agent_devices
        WHERE user_id=?
        ORDER BY id DESC
        LIMIT 1
    """, (user["id"],)).fetchone()

    rows = conn.execute("""
        SELECT filename, extension, activity, path, process,
               status, score, event_time, reasons
        FROM agent_events
        WHERE user_id=?
        ORDER BY id DESC
        LIMIT 100
    """, (user["id"],)).fetchall()
    event_count = conn.execute(
        "SELECT COUNT(*) FROM agent_events WHERE user_id=?", (user["id"],)
    ).fetchone()[0]

    connected = bool(device and device["last_seen"])
    if connected:
        fresh = conn.execute(
            "SELECT 1 WHERE datetime(?) >= datetime('now', '-45 seconds')",
            (device["last_seen"],)
        ).fetchone()
        connected = bool(fresh)

    monitoring_enabled = bool(device and device["monitoring_enabled"])

    conn.close()

    events = []
    for r in rows:
        events.append({
            "filename": r["filename"] or "Unknown",
            "extension": r["extension"] or "none",
            "activity": r["activity"] or "unknown",
            "path": r["path"] or "",
            "process": r["process"] or "Unknown",
            "status": r["status"] or "Safe",
            "score": r["score"] or 0,
            "time": r["event_time"] or "",
            "reasons": [x.strip() for x in (r["reasons"] or "").split(";") if x.strip()]
        })

    totals = {
        "Created": sum(str(e["activity"]).lower() == "created" for e in events),
        "Modified": sum(str(e["activity"]).lower() in ("modified", "changed", "write") for e in events),
        "Deleted": sum(str(e["activity"]).lower() == "deleted" for e in events),
        "Renamed": sum(str(e["activity"]).lower() == "renamed" for e in events),
    }

    return jsonify(
        success=True,
        connected=connected,
        running=monitoring_enabled,
        monitoring_enabled=monitoring_enabled,
        device={**dict(device), "event_count": int(event_count)} if device else None,
        events=events,
        totals=totals,
        folder="All accessible Windows drives",
        features={
            "write_count": totals["Modified"],
            "rename_count": totals["Renamed"],
            "delete_count": totals["Deleted"],
            "create_count": totals["Created"],
            "ext_diversity": len({e["extension"] for e in events if e["extension"]}),
            "sensitive_path_access": 0,
            "read_write_ratio": 0,
            "score": max((float(e["score"] or 0) for e in events), default=0),
            "write_entropy": 0,
            "window_seconds": 10,
            "ml_status": "ANOMALY" if any(str(e["status"]).lower() in ("suspicious", "malware", "malicious") for e in events) else "LEARNING BASELINE",
            "ml_anomaly_score": max((float(e["score"] or 0) for e in events), default=0)
        }
    )


# Start server only after ALL routes have been registered.
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
