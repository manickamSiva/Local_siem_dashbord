import sqlite3

DATABASE = "siem.db"

def create_database():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            record_id INTEGER UNIQUE,
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
            message TEXT
        )
    """)

    connection.commit()

    # --------------------------------------------------
    # Database migration for existing MiniSIEM database
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

    connection.commit()
    connection.close()

def insert_event(event):

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    parsed = event.get("parsed", {})

    cursor.execute("""
        INSERT OR IGNORE INTO events (
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
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
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

    connection.commit()
    connection.close()

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