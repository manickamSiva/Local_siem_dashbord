from fastapi import FastAPI, Query, HTTPException  # type: ignore[import-not-found]
from pydantic import BaseModel  # type: ignore[import-not-found]
from fastapi.middleware.cors import CORSMiddleware  # type: ignore[import-not-found]
from typing import Optional
from datetime import date, timedelta
import sqlite3

import database


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


@app.on_event("startup")
def ensure_schema():
    # Runs the same migration collector.py runs, but from the API itself,
    # so starting uvicorn alone (without ever running collector.py) still
    # gets you a schema with log_type, alerts, and alert_events. This is
    # what fixed the earlier "Failed to load events" 500s.
    database.create_database()
    database.create_alerts_table()
    database.create_alert_events_table()


# ==========================================================
# CORS
# ==========================================================

# Wide open on purpose: local single-user tool, no login/session to
# protect, and a fixed origin list breaks the moment the dashboard is
# opened a different way (file://, a different dev-server port, etc).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
def get_events(
    limit: int = Query(default=20, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    category: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    source_ip: Optional[str] = Query(default=None),
    username: Optional[str] = Query(default=None),
    log_type: Optional[str] = Query(default=None),
):
    connection = get_connection()
    cursor = connection.cursor()

    conditions = []
    params = []

    # /api/categories and /api/severity report NULL rows under the labels
    # "Other" / "UNKNOWN", so clicking through on those labels needs to
    # match NULL here too, not just the literal string.
    if category:
        if category == "Other":
            conditions.append("(category IS NULL OR category = ?)")
            params.append(category)
        else:
            conditions.append("category = ?")
            params.append(category)

    if severity:
        if severity == "UNKNOWN":
            conditions.append("(severity IS NULL OR severity = ?)")
            params.append(severity)
        else:
            conditions.append("severity = ?")
            params.append(severity)

    if source_ip:
        conditions.append("source_ip = ?")
        params.append(source_ip)

    if username:
        conditions.append("username = ?")
        params.append(username)

    if log_type:
        conditions.append("log_type = ?")
        params.append(log_type)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    # Total count under the same filters, so the frontend can compute how
    # many pages exist without ever fetching every matching row.
    cursor.execute(f"""
        SELECT COUNT(*)
        FROM events
        {where_clause}
    """, params)
    total = cursor.fetchone()[0]

    cursor.execute(f"""
        SELECT
            id,
            log_type,
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
        {where_clause}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """, (*params, limit, offset))

    rows = cursor.fetchall()

    connection.close()

    return {
        "count": len(rows),
        "total": total,
        "limit": limit,
        "offset": offset,
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
            log_type,
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
# ALERT TREND (alerts per day, by severity)
# ==========================================================

@app.get("/api/alerts/trend")
def get_alert_trend(days: int = Query(default=14, ge=1, le=90)):
    connection = get_connection()
    cursor = connection.cursor()

    # alerts.created_at is stored as "YYYY-MM-DD HH:MM:SS", which SQLite's
    # date() function parses natively (unlike events.timestamp).
    cursor.execute("""
        SELECT
            date(created_at) AS day,
            COALESCE(severity, 'UNKNOWN') AS severity,
            COUNT(*) AS count
        FROM alerts
        WHERE created_at IS NOT NULL
          AND date(created_at) >= date('now', ?)
        GROUP BY day, severity
        ORDER BY day ASC
    """, (f"-{days - 1} days",))

    rows = cursor.fetchall()
    connection.close()

    # Build a dense, zero-filled day list so the frontend gets one entry
    # per day in range even if no alerts fired that day.
    today = date.today()
    day_list = [(today - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]

    by_day = {d: {} for d in day_list}
    for row in rows:
        d = row["day"]
        if d in by_day:
            by_day[d][row["severity"]] = row["count"]

    return {
        "days": day_list,
        "trend": [
            {"day": d, "severities": by_day[d]}
            for d in day_list
        ]
    }


# ==========================================================
# SECURITY EVENT TREND (collected Windows events per day)
# ==========================================================
# Deliberately named /api/event-trend (not /api/events/trend) — that's
# what avoids the FastAPI routing collision with /api/events/{event_id}
# below. Keep app.js pointed at this exact path.

@app.get("/api/event-trend")
def get_event_trend(days: int = Query(default=14, ge=1, le=90)):
    """Return the severity trend for events collected from Windows.

    Windows event timestamps are stored in the pywin32 format
    ``Fri Aug 28 14:25:04 2026``.  Convert that value to SQLite's ISO date
    format before grouping, rather than using the alert creation time.

    Day-of-month is pulled through TRIM + printf('%02d', ...) rather than
    a bare substr(), because pywin32's TimeGenerated.Format() pads
    single-digit days with a space (e.g. "Sep  3", two spaces) rather
    than a zero. A bare substr(timestamp, 9, 2) on such a row yields
    " 3", which SQLite's date() can't parse — it silently returns NULL,
    and that row drops out of every day in the window. Trimming the
    space and re-padding with printf fixes both single- and double-digit
    days.
    """
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        WITH dated_events AS (
            SELECT
                date(
                    substr(timestamp, 21, 4) || '-' ||
                    CASE substr(timestamp, 5, 3)
                        WHEN 'Jan' THEN '01' WHEN 'Feb' THEN '02'
                        WHEN 'Mar' THEN '03' WHEN 'Apr' THEN '04'
                        WHEN 'May' THEN '05' WHEN 'Jun' THEN '06'
                        WHEN 'Jul' THEN '07' WHEN 'Aug' THEN '08'
                        WHEN 'Sep' THEN '09' WHEN 'Oct' THEN '10'
                        WHEN 'Nov' THEN '11' WHEN 'Dec' THEN '12'
                    END || '-' || printf('%02d', CAST(TRIM(substr(timestamp, 9, 2)) AS INTEGER))
                ) AS day,
                COALESCE(severity, 'UNKNOWN') AS severity
            FROM events
            WHERE timestamp IS NOT NULL
        )
        SELECT day, severity, COUNT(*) AS count
        FROM dated_events
        WHERE day >= date('now', ?)
        GROUP BY day, severity
        ORDER BY day ASC
    """, (f"-{days - 1} days",))

    rows = cursor.fetchall()
    connection.close()

    today = date.today()
    day_list = [
        (today - timedelta(days=i)).isoformat()
        for i in range(days - 1, -1, -1)
    ]
    by_day = {day: {} for day in day_list}

    for row in rows:
        if row["day"] in by_day:
            by_day[row["day"]][row["severity"]] = row["count"]

    return {
        "days": day_list,
        "trend": [
            {"day": day, "severities": by_day[day]}
            for day in day_list
        ]
    }


# ==========================================================
# ACTIVE ALERTS ONLY
# ==========================================================
# Registered before /api/alerts/{alert_id} on purpose — same reasoning
# as /api/event-trend's placement relative to /api/events/{event_id}.
# Not currently called by the frontend (it uses /api/alerts?status=...
# instead), but fixed preemptively since it's the same bug class as the
# one that caused the earlier 422s.

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
            log_type,
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


# ==========================================================
# LOG SOURCE SUMMARY (Security vs Application, etc.)
# ==========================================================

@app.get("/api/log-sources")
def get_log_sources():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            COALESCE(log_type, 'Security') AS log_type,
            COUNT(*) AS count
        FROM events
        GROUP BY log_type
        ORDER BY count DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    return {
        "log_sources": [dict(row) for row in rows]
    }