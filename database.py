import sqlite3

DATABASE = "siem.db"


def _rebuild_events_table_for_log_type(cursor):
    """One-time migration for pre-existing databases.

    The original schema had `record_id INTEGER UNIQUE` as a column-level
    constraint. That's fine as long as every event comes from one log
    (Security), but Security and Application logs number their records
    independently — a Security event #500 and an Application event #500
    are unrelated, yet the old constraint would treat the second insert
    as a duplicate of the first and silently drop it.

    ALTER TABLE can add the log_type column, but it can't remove the old
    column-level UNIQUE(record_id). The only way to fix the constraint's
    scope is to rebuild the table with UNIQUE(log_type, record_id)
    instead, preserving every row's `id` (alert_events references it).
    """

    cursor.execute("""
        CREATE TABLE events_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_type TEXT NOT NULL DEFAULT 'Security',
            timestamp TEXT,
            record_id INTEGER,
            event_id INTEGER,
            event_type TEXT,
            event_name TEXT,
            category TEXT,
            severity TEXT,
            mitre_technique TEXT,
            description TEXT,
            source TEXT,
            computer TEXT,
            username TEXT,
            domain TEXT,
            logon_type TEXT,
            source_ip TEXT,
            authentication_package TEXT,
            message TEXT,
            UNIQUE(log_type, record_id)
        )
    """)

    cursor.execute("""
        INSERT INTO events_new (
            id, log_type, timestamp, record_id, event_id, event_type,
            event_name, category, severity, mitre_technique, description,
            source, computer, username, domain, logon_type, source_ip,
            authentication_package, message
        )
        SELECT
            id, log_type, timestamp, record_id, event_id, event_type,
            event_name, category, severity, mitre_technique, description,
            source, computer, username, domain, logon_type, source_ip,
            authentication_package, message
        FROM events
    """)

    cursor.execute("DROP TABLE events")
    cursor.execute("ALTER TABLE events_new RENAME TO events")


def create_database():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    # Fresh installs get the correct schema straight away.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_type TEXT NOT NULL DEFAULT 'Security',
            timestamp TEXT,
            record_id INTEGER,
            event_id INTEGER,
            event_type TEXT,
            event_name TEXT,
            category TEXT,
            severity TEXT,
            mitre_technique TEXT,
            description TEXT,
            source TEXT,
            computer TEXT,
            username TEXT,
            domain TEXT,
            logon_type TEXT,
            source_ip TEXT,
            authentication_package TEXT,
            message TEXT,
            UNIQUE(log_type, record_id)
        )
    """)

    connection.commit()

    # --------------------------------------------------
    # Migration for pre-existing MiniSIEM databases
    # --------------------------------------------------

    cursor.execute("PRAGMA table_info(events)")
    existing_columns = {
        row[1] for row in cursor.fetchall()
    }

    new_columns = {
        "category": "TEXT",
        "severity": "TEXT",
        "mitre_technique": "TEXT",
        "description": "TEXT"
    }

    for column, column_type in new_columns.items():

        if column not in existing_columns:

            cursor.execute(
                f"ALTER TABLE events ADD COLUMN {column} {column_type}"
            )

    if "log_type" not in existing_columns:

        # Every row that predates this migration came from the Security
        # log (that was the only one collected), so backfill it as such.
        cursor.execute(
            "ALTER TABLE events ADD COLUMN log_type TEXT NOT NULL DEFAULT 'Security'"
        )
        connection.commit()

        _rebuild_events_table_for_log_type(cursor)

    connection.commit()
    connection.close()


def insert_event(event):

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    parsed = event.get("parsed", {})
    log_type = event.get("log_type", "Security")

    cursor.execute("""
        INSERT OR IGNORE INTO events (
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
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        log_type,
        event.get("timestamp"),
        event.get("record_id"),
        event.get("event_id"),
        event.get("event_type"),
        parsed.get("event_name"),
        parsed.get("category"),
        parsed.get("severity"),
        parsed.get("mitre_technique"),
        parsed.get("description"),
        event.get("source"),
        event.get("computer"),
        parsed.get("username"),
        parsed.get("domain"),
        parsed.get("logon_type"),
        parsed.get("source_ip"),
        parsed.get("authentication_package"),
        event.get("message")
    ))

    # cursor.lastrowid is stale/0 when INSERT OR IGNORE skips a duplicate
    # (same log_type + record_id already stored) rather than inserting.
    # Look the existing row up so callers still get a usable event id.
    if cursor.rowcount == 0:
        cursor.execute(
            "SELECT id FROM events WHERE log_type = ? AND record_id = ?",
            (log_type, event.get("record_id"))
        )
        row = cursor.fetchone()
        event_db_id = row[0] if row else None
    else:
        event_db_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return event_db_id


def create_alerts_table():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT,
            alert_type TEXT,
            severity TEXT,
            source_ip TEXT,
            username TEXT,
            description TEXT,
            mitre_technique TEXT,
            status TEXT DEFAULT 'NEW'
        )
    """)

    connection.commit()
    connection.close()


def create_alert_events_table():
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            event_id INTEGER NOT NULL,
            UNIQUE(alert_id, event_id),
            FOREIGN KEY(alert_id) REFERENCES alerts(id),
            FOREIGN KEY(event_id) REFERENCES events(id)
        )
    """)

    connection.commit()
    connection.close()


def link_alert_to_event(alert_id, event_id):
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO alert_events (
            alert_id,
            event_id
        )
        VALUES (?, ?)
    """, (alert_id, event_id))

    connection.commit()
    connection.close()