import sqlite3
from datetime import datetime, timedelta

import database

DATABASE = "siem.db"

FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5


def get_connection():
    return sqlite3.connect(DATABASE)


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
                substr(timestamp, 9, 2) || ' ' ||
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
    now
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
        "HIGH",
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
                substr(timestamp, 9, 2) || ' ' ||
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
            now
        )

        alerts_created += 1

    connection.commit()
    connection.close()

    return alerts_created


def process_event(event_id, source_ip, username):
    """Run detection rules for a newly stored event."""

    if event_id != 4625 or not source_ip:
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
                substr(timestamp, 9, 2) || ' ' ||
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

    alert_id = create_brute_force_alert(
        cursor,
        source_ip,
        username,
        count,
        event_ids,
        now
    )

    connection.commit()
    connection.close()

    print()
    print("🚨 ALERT GENERATED")
    print("=" * 50)
    print("Alert ID : {}".format(alert_id))
    print("Type     : Brute Force")
    print("Severity : HIGH")
    print(f"Source   : {source_ip}")
    print(f"User     : {username}")
    print(f"Attempts : {count}")
    print("MITRE    : T1110")
    print(f"Events   : {len(event_ids)}")
    print("=" * 50)
    print()


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