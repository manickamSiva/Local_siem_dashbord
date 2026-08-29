from fastapi import FastAPI, Query, HTTPException  # type: ignore[import-not-found]
from pydantic import BaseModel  # type: ignore[import-not-found]
from fastapi.middleware.cors import CORSMiddleware  # type: ignore[import-not-found]
import sqlite3


DATABASE = "siem.db"


# ==========================================================
# FASTAPI APPLICATION
# ==========================================================

app = FastAPI(
    title="MiniSIEM API",
    description="Local Windows SIEM API",
    version="1.1.0",
    redirect_slashes=False
)


# ==========================================================
# CORS
# ==========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=False,
    allow_methods=["GET", "PUT", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ==========================================================
# DATABASE CONNECTION
# ==========================================================

def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


# ==========================================================
# MODELS
# ==========================================================

class AlertStatusUpdate(BaseModel):
    status: str


# ==========================================================
# ROOT
# ==========================================================

@app.get("/")
def root():
    return {
        "name": "MiniSIEM",
        "status": "online",
        "version": "1.1.0"
    }


# ==========================================================
# SIEM STATISTICS
# ==========================================================

@app.get("/api/stats")
def get_stats():
    connection = get_connection()
    cursor = connection.cursor()

    # Total events
    cursor.execute("SELECT COUNT(*) FROM events")
    total_events = cursor.fetchone()[0]

    # Failed logins
    cursor.execute("""
        SELECT COUNT(*)
        FROM events
        WHERE event_id = 4625
    """)
    failed_logins = cursor.fetchone()[0]

    # Successful logins
    cursor.execute("""
        SELECT COUNT(*)
        FROM events
        WHERE event_id = 4624
    """)
    successful_logins = cursor.fetchone()[0]

    # Active alerts
    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE status IN ('NEW', 'INVESTIGATING')
    """)
    active_alerts = cursor.fetchone()[0]

    # Unique source IPs
    cursor.execute("""
        SELECT COUNT(DISTINCT source_ip)
        FROM events
        WHERE source_ip IS NOT NULL
        AND source_ip != ''
    """)
    unique_ips = cursor.fetchone()[0]

    connection.close()

    return {
        "total_events": total_events,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "active_alerts": active_alerts,
        "unique_source_ips": unique_ips
    }


# ==========================================================
# EVENTS
# ==========================================================

@app.get("/api/events")
def get_events(limit: int = Query(default=50, ge=1, le=500)):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            record_id,
            event_id,
            event_type,
            event_name,
            category,
            severity,
            mitre_technique,
            description,
            source,
            computer,
            username,
            domain,
            logon_type,
            source_ip,
            authentication_package,
            message
        FROM events
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()

    connection.close()

    return {
        "count": len(rows),
        "events": [dict(row) for row in rows]
    }


# ==========================================================
# SINGLE EVENT
# ==========================================================

@app.get("/api/events/{event_id}")
def get_event(event_id: int):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            record_id,
            event_id,
            event_type,
            event_name,
            category,
            severity,
            mitre_technique,
            description,
            source,
            computer,
            username,
            domain,
            logon_type,
            source_ip,
            authentication_package,
            message
        FROM events
        WHERE id = ?
        LIMIT 1
    """, (event_id,))

    row = cursor.fetchone()

    connection.close()

    if row is None:
        raise HTTPException(status_code=404, detail="Event not found")

    return {"event": dict(row)}


# ==========================================================
# ALERTS
# ==========================================================

@app.get("/api/alerts")
def get_alerts(status: str = Query(default="ACTIVE")):
    connection = get_connection()
    cursor = connection.cursor()

    if status.upper() == "ACTIVE":
        cursor.execute("""
            SELECT
                id,
                created_at,
                alert_type,
                severity,
                source_ip,
                username,
                description,
                mitre_technique,
                status
            FROM alerts
            WHERE status != 'RESOLVED'
            ORDER BY id DESC
        """)
    else:
        cursor.execute("""
            SELECT
                id,
                created_at,
                alert_type,
                severity,
                source_ip,
                username,
                description,
                mitre_technique,
                status
            FROM alerts
            WHERE status = ?
            ORDER BY id DESC
        """, (status.upper(),))

    rows = cursor.fetchall()

    connection.close()

    return {
        "count": len(rows),
        "alerts": [dict(row) for row in rows]
    }


# ==========================================================
# SINGLE ALERT
# ==========================================================

@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: int):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            created_at,
            alert_type,
            severity,
            source_ip,
            username,
            description,
            mitre_technique,
            status
        FROM alerts
        WHERE id = ?
    """, (alert_id,))

    row = cursor.fetchone()

    connection.close()

    if row is None:
        return {"error": "Alert not found"}

    return dict(row)


# ==========================================================
# RELATED EVENTS FOR AN ALERT
# ==========================================================

@app.get("/api/alerts/{alert_id}/events")
def get_alert_events(alert_id: int):
    connection = get_connection()
    cursor = connection.cursor()

    # Get alert information
    cursor.execute("""
        SELECT
            source_ip,
            username,
            created_at
        FROM alerts
        WHERE id = ?
    """, (alert_id,))

    alert = cursor.fetchone()

    if alert is None:
        connection.close()
        return {"error": "Alert not found"}

    source_ip = alert["source_ip"]
    username = alert["username"]

    # Find related events
    cursor.execute("""
        SELECT
            id,
            timestamp,
            record_id,
            event_id,
            event_type,
            event_name,
            category,
            severity,
            mitre_technique,
            username,
            domain,
            logon_type,
            source_ip,
            authentication_package,
            message
        FROM events
        WHERE
            (
                source_ip = ?
                OR username = ?
            )
        ORDER BY id DESC
        LIMIT 100
    """, (source_ip, username))

    rows = cursor.fetchall()

    connection.close()

    return {
        "alert_id": alert_id,
        "count": len(rows),
        "events": [dict(row) for row in rows]
    }


# ==========================================================
# UPDATE ALERT STATUS
# ==========================================================

@app.put("/api/alerts/{alert_id}/status")
def update_alert_status(alert_id: int, data: AlertStatusUpdate):
    allowed_statuses = {"NEW", "INVESTIGATING", "RESOLVED"}

    status = data.status.upper()

    if status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="Invalid status. Use NEW, INVESTIGATING or RESOLVED."
        )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT id FROM alerts WHERE id = ?", (alert_id,))
    alert = cursor.fetchone()

    if not alert:
        connection.close()
        raise HTTPException(status_code=404, detail="Alert not found")

    cursor.execute("""
        UPDATE alerts
        SET status = ?
        WHERE id = ?
    """, (status, alert_id))

    connection.commit()
    connection.close()

    return {
        "success": True,
        "alert_id": alert_id,
        "status": status
    }


# ==========================================================
# ACTIVE ALERTS ONLY
# ==========================================================

@app.get("/api/alerts/active")
def get_active_alerts():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            created_at,
            alert_type,
            severity,
            source_ip,
            username,
            description,
            mitre_technique,
            status
        FROM alerts
        WHERE status = 'NEW'
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    return {
        "count": len(rows),
        "alerts": [dict(row) for row in rows]
    }


# ==========================================================
# EVENT CATEGORY SUMMARY
# ==========================================================

@app.get("/api/categories")
def get_categories():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            COALESCE(category, 'Other') AS category,
            COUNT(*) AS count
        FROM events
        GROUP BY category
        ORDER BY count DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    return {
        "categories": [dict(row) for row in rows]
    }


# ==========================================================
# EVENT SEVERITY SUMMARY
# ==========================================================

@app.get("/api/severity")
def get_severity():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            COALESCE(severity, 'UNKNOWN') AS severity,
            COUNT(*) AS count
        FROM events
        GROUP BY severity
        ORDER BY count DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    return {
        "severity": [dict(row) for row in rows]
    }