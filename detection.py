import sqlite3
from datetime import datetime, timedelta

import database

DATABASE = "siem.db"

FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5

# Failed-attempt counts at or above these cutoffs escalate the alert's
# severity, so a brief lockout doesn't look the same as a sustained attack.
BRUTE_FORCE_HIGH_THRESHOLD = 10
BRUTE_FORCE_CRITICAL_THRESHOLD = 20

# Successful logons (event 4624) outside this window trigger the
# After-Hours Logon rule. 24-hour clock, local time.
BUSINESS_HOURS_START = 8
BUSINESS_HOURS_END = 18

# Format produced by pywin32's event.TimeGenerated.Format(), e.g.
# "Fri Aug 28 14:25:04 2026".
TIMESTAMP_FORMAT = "%a %b %d %H:%M:%S %Y"


def get_connection():
    return sqlite3.connect(DATABASE)


def brute_force_severity(count):
    """Scale brute-force alert severity with how many attempts fired it."""

    if count >= BRUTE_FORCE_CRITICAL_THRESHOLD:
        return "CRITICAL"

    if count >= BRUTE_FORCE_HIGH_THRESHOLD:
        return "HIGH"

    return "MEDIUM"


def is_after_hours(timestamp):
    """True if the given event timestamp falls outside business hours."""

    if not timestamp:
        return False

    try:
        parsed = datetime.strptime(timestamp, TIMESTAMP_FORMAT)
    except ValueError:
        return False

    return (
        parsed.hour < BUSINESS_HOURS_START
        or parsed.hour >= BUSINESS_HOURS_END
    )


def get_failed_login_events(cursor, source_ip, username, window_start):
    cursor.execute("""
        SELECT id
        FROM events
        WHERE event_id = 4625
          AND source_ip = ?
          AND username = ?
          AND datetime(
                substr(timestamp, 21, 4) || '-' ||
                CASE substr(timestamp, 5, 3)
                    WHEN 'Jan' THEN '01'
                    WHEN 'Feb' THEN '02'
                    WHEN 'Mar' THEN '03'
                    WHEN 'Apr' THEN '04'
                    WHEN 'May' THEN '05'
                    WHEN 'Jun' THEN '06'
                    WHEN 'Jul' THEN '07'
                    WHEN 'Aug' THEN '08'
                    WHEN 'Sep' THEN '09'
                    WHEN 'Oct' THEN '10'
                    WHEN 'Nov' THEN '11'
                    WHEN 'Dec' THEN '12'
                END || '-' ||
                printf('%02d', CAST(TRIM(substr(timestamp, 9, 2)) AS INTEGER)) || ' ' ||
                substr(timestamp, 12, 8)
          ) >= ?
        ORDER BY id ASC
    """, (
        source_ip,
        username,
        window_start.strftime("%Y-%m-%d %H:%M:%S")
    ))

    return [row[0] for row in cursor.fetchall()]


def create_brute_force_alert(
    cursor,
    source_ip,
    username,
    count,
    event_ids,
    now,
    severity
):
    description = (
        f"Possible brute force attack detected. "
        f"{count} failed login attempts from "
        f"{source_ip} against user {username} "
        f"within {TIME_WINDOW_MINUTES} minutes."
    )

    cursor.execute("""
        INSERT INTO alerts (
            created_at,
            alert_type,
            severity,
            source_ip,
            username,
            description,
            mitre_technique,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        now.strftime("%Y-%m-%d %H:%M:%S"),
        "Brute Force",
        severity,
        source_ip,
        username,
        description,
        "T1110",
        "NEW"
    ))

    alert_id = cursor.lastrowid

    for event_id in event_ids:
        cursor.execute("""
            INSERT OR IGNORE INTO alert_events (
                alert_id,
                event_id
            )
            VALUES (?, ?)
        """, (alert_id, event_id))

    return alert_id


def create_after_hours_alert(
    cursor,
    source_ip,
    username,
    timestamp,
    event_db_id,
    now
):
    description = (
        f"Successful logon by "
        f"{username or 'an unknown user'} from "
        f"{source_ip or 'an unknown host'} occurred outside business "
        f"hours ({BUSINESS_HOURS_START:02d}:00–{BUSINESS_HOURS_END:02d}:00)."
    )

    cursor.execute("""
        INSERT INTO alerts (
            created_at,
            alert_type,
            severity,
            source_ip,
            username,
            description,
            mitre_technique,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        now.strftime("%Y-%m-%d %H:%M:%S"),
        "After-Hours Logon",
        "MEDIUM",
        source_ip,
        username,
        description,
        "T1078",
        "NEW"
    ))

    alert_id = cursor.lastrowid

    if event_db_id:
        cursor.execute("""
            INSERT OR IGNORE INTO alert_events (
                alert_id,
                event_id
            )
            VALUES (?, ?)
        """, (alert_id, event_db_id))

    return alert_id


def detect_brute_force():
    connection = get_connection()
    cursor = connection.cursor()

    now = datetime.now()
    window_start = now - timedelta(minutes=TIME_WINDOW_MINUTES)

    cursor.execute("""
        SELECT
            source_ip,
            username,
            COUNT(*)
        FROM events
        WHERE event_id = 4625
          AND source_ip IS NOT NULL
          AND datetime(
                substr(timestamp, 21, 4) || '-' ||
                CASE substr(timestamp, 5, 3)
                    WHEN 'Jan' THEN '01'
                    WHEN 'Feb' THEN '02'
                    WHEN 'Mar' THEN '03'
                    WHEN 'Apr' THEN '04'
                    WHEN 'May' THEN '05'
                    WHEN 'Jun' THEN '06'
                    WHEN 'Jul' THEN '07'
                    WHEN 'Aug' THEN '08'
                    WHEN 'Sep' THEN '09'
                    WHEN 'Oct' THEN '10'
                    WHEN 'Nov' THEN '11'
                    WHEN 'Dec' THEN '12'
                END || '-' ||
                printf('%02d', CAST(TRIM(substr(timestamp, 9, 2)) AS INTEGER)) || ' ' ||
                substr(timestamp, 12, 8)
          ) >= ?
        GROUP BY source_ip, username
        HAVING COUNT(*) >= ?
    """, (
        window_start.strftime("%Y-%m-%d %H:%M:%S"),
        FAILED_LOGIN_THRESHOLD
    ))

    results = cursor.fetchall()
    alerts_created = 0

    for source_ip, username, count in results:
        cursor.execute("""
            SELECT id
            FROM alerts
            WHERE alert_type = ?
              AND source_ip = ?
              AND username = ?
              AND status = 'NEW'
        """, (
            "Brute Force",
            source_ip,
            username
        ))

        if cursor.fetchone():
            continue

        event_ids = get_failed_login_events(
            cursor,
            source_ip,
            username,
            window_start
        )

        create_brute_force_alert(
            cursor,
            source_ip,
            username,
            count,
            event_ids,
            now,
            brute_force_severity(count)
        )

        alerts_created += 1

    connection.commit()
    connection.close()

    return alerts_created


def _process_failed_logon(source_ip, username):
    """Brute-force detection for a single new 4625 (failed logon) event."""

    if not source_ip:
        return

    connection = get_connection()
    cursor = connection.cursor()

    now = datetime.now()
    window_start = now - timedelta(minutes=TIME_WINDOW_MINUTES)

    cursor.execute("""
        SELECT COUNT(*)
        FROM events
        WHERE event_id = 4625
          AND source_ip = ?
          AND username = ?
          AND datetime(
                substr(timestamp, 21, 4) || '-' ||
                CASE substr(timestamp, 5, 3)
                    WHEN 'Jan' THEN '01'
                    WHEN 'Feb' THEN '02'
                    WHEN 'Mar' THEN '03'
                    WHEN 'Apr' THEN '04'
                    WHEN 'May' THEN '05'
                    WHEN 'Jun' THEN '06'
                    WHEN 'Jul' THEN '07'
                    WHEN 'Aug' THEN '08'
                    WHEN 'Sep' THEN '09'
                    WHEN 'Oct' THEN '10'
                    WHEN 'Nov' THEN '11'
                    WHEN 'Dec' THEN '12'
                END || '-' ||
                printf('%02d', CAST(TRIM(substr(timestamp, 9, 2)) AS INTEGER)) || ' ' ||
                substr(timestamp, 12, 8)
          ) >= ?
    """, (
        source_ip,
        username,
        window_start.strftime("%Y-%m-%d %H:%M:%S")
    ))

    count = cursor.fetchone()[0]

    if count < FAILED_LOGIN_THRESHOLD:
        connection.close()
        return

    cursor.execute("""
        SELECT id
        FROM alerts
        WHERE alert_type = ?
          AND source_ip = ?
          AND username = ?
          AND status = 'NEW'
    """, (
        "Brute Force",
        source_ip,
        username
    ))

    if cursor.fetchone():
        connection.close()
        return

    event_ids = get_failed_login_events(
        cursor,
        source_ip,
        username,
        window_start
    )

    severity = brute_force_severity(count)

    alert_id = create_brute_force_alert(
        cursor,
        source_ip,
        username,
        count,
        event_ids,
        now,
        severity
    )

    connection.commit()
    connection.close()

    print()
    print("🚨 ALERT GENERATED")
    print("=" * 50)
    print("Alert ID : {}".format(alert_id))
    print("Type     : Brute Force")
    print(f"Severity : {severity}")
    print(f"Source   : {source_ip}")
    print(f"User     : {username}")
    print(f"Attempts : {count}")
    print("MITRE    : T1110")
    print(f"Events   : {len(event_ids)}")
    print("=" * 50)
    print()


def _process_after_hours_logon(source_ip, username, timestamp, event_db_id):
    """After-Hours Logon detection for a single new 4624 (successful
    logon) event."""

    if not is_after_hours(timestamp):
        return

    connection = get_connection()
    cursor = connection.cursor()

    now = datetime.now()
    today = now.strftime("%Y-%m-%d")

    # Avoid re-alerting on every after-hours logon from the same user and
    # source within the same day.
    cursor.execute("""
        SELECT id
        FROM alerts
        WHERE alert_type = ?
          AND source_ip = ?
          AND username = ?
          AND status = 'NEW'
          AND date(created_at) = ?
    """, (
        "After-Hours Logon",
        source_ip,
        username,
        today
    ))

    if cursor.fetchone():
        connection.close()
        return

    alert_id = create_after_hours_alert(
        cursor,
        source_ip,
        username,
        timestamp,
        event_db_id,
        now
    )

    connection.commit()
    connection.close()

    print()
    print("🚨 ALERT GENERATED")
    print("=" * 50)
    print("Alert ID : {}".format(alert_id))
    print("Type     : After-Hours Logon")
    print("Severity : MEDIUM")
    print(f"Source   : {source_ip}")
    print(f"User     : {username}")
    print(f"Time     : {timestamp}")
    print("MITRE    : T1078")
    print("=" * 50)
    print()


def process_event(event_id, source_ip, username, timestamp=None, event_db_id=None):
    """Run detection rules for a newly stored event."""

    if event_id == 4625:
        _process_failed_logon(source_ip, username)
    elif event_id == 4624:
        _process_after_hours_logon(source_ip, username, timestamp, event_db_id)


def show_alerts():
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
        ORDER BY id DESC
    """)

    alerts = cursor.fetchall()

    print("\n" + "=" * 70)
    print("                         ALERTS")
    print("=" * 70)

    if not alerts:
        print("No alerts detected.")
    else:
        for alert in alerts:
            (
                alert_id,
                created_at,
                alert_type,
                severity,
                source_ip,
                username,
                description,
                mitre,
                status
            ) = alert

            print(f"\nAlert ID   : {alert_id}")
            print(f"Time       : {created_at}")
            print(f"Type       : {alert_type}")
            print(f"Severity   : {severity}")
            print(f"Source IP  : {source_ip}")
            print(f"Username   : {username}")
            print(f"MITRE      : {mitre}")
            print(f"Status     : {status}")
            print(f"Description: {description}")

    connection.close()


def main():
    print("=" * 70)
    print("                  MiniSIEM Detection Engine")
    print("=" * 70)

    database.create_alerts_table()
    database.create_alert_events_table()

    alerts = detect_brute_force()

    print(f"\nNew alerts created: {alerts}")

    show_alerts()


if __name__ == "__main__":
    main()