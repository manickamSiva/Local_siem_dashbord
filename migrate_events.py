import sqlite3


DATABASE = "siem.db"


# ==========================================================
# EVENT INTELLIGENCE
# ==========================================================

EVENT_INTELLIGENCE = {

    4624: {
        "category": "Authentication",
        "severity": "LOW",
        "mitre": None,
        "description": "A successful user logon was recorded."
    },

    4625: {
        "category": "Authentication",
        "severity": "MEDIUM",
        "mitre": "T1110",
        "description": "A failed user logon was recorded."
    },

    4634: {
        "category": "Authentication",
        "severity": "LOW",
        "mitre": None,
        "description": "A user logoff was recorded."
    },

    4648: {
        "category": "Credential Access",
        "severity": "MEDIUM",
        "mitre": "T1078",
        "description": "Explicit credentials were used for logon."
    },

    4672: {
        "category": "Privilege",
        "severity": "HIGH",
        "mitre": None,
        "description": "Special privileges were assigned to a logon session."
    },

    4688: {
        "category": "Execution",
        "severity": "MEDIUM",
        "mitre": "T1059",
        "description": "A new process was created."
    },

    4798: {
        "category": "Discovery",
        "severity": "MEDIUM",
        "mitre": "T1087",
        "description": "User account enumeration was detected."
    },

    4799: {
        "category": "Discovery",
        "severity": "MEDIUM",
        "mitre": "T1069",
        "description": "Security group enumeration was detected."
    },

    5379: {
        "category": "Credential Access",
        "severity": "MEDIUM",
        "mitre": "T1555.004",
        "description": "Credentials stored in Windows Credential Manager were accessed."
    }
}


# ==========================================================
# MIGRATION
# ==========================================================

def migrate():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    print("=" * 70)
    print("                 MiniSIEM Database Migration")
    print("=" * 70)
    print()

    updated = 0
    skipped = 0
    unknown = 0


    # ------------------------------------------------------
    # Get existing events
    # ------------------------------------------------------

    cursor.execute("""
        SELECT
            id,
            event_id,
            category,
            severity,
            mitre_technique,
            description
        FROM events
        ORDER BY id
    """)

    events = cursor.fetchall()


    # ------------------------------------------------------
    # Process events
    # ------------------------------------------------------

    for event in events:

        row_id = event[0]
        event_id = event[1]
        category = event[2]
        severity = event[3]
        mitre = event[4]
        description = event[5]


        intelligence = EVENT_INTELLIGENCE.get(event_id)


        # Unknown Event ID

        if intelligence is None:

            unknown += 1

            continue


        # --------------------------------------------------
        # Only migrate missing intelligence
        # --------------------------------------------------

        new_category = (
            category
            if category
            else intelligence["category"]
        )

        new_severity = (
            severity
            if severity
            else intelligence["severity"]
        )

        new_mitre = (
            mitre
            if mitre
            else intelligence["mitre"]
        )

        new_description = (
            description
            if description
            else intelligence["description"]
        )


        # --------------------------------------------------
        # Update database
        # --------------------------------------------------

        cursor.execute("""
            UPDATE events

            SET
                category = ?,
                severity = ?,
                mitre_technique = ?,
                description = ?

            WHERE id = ?
        """, (
            new_category,
            new_severity,
            new_mitre,
            new_description,
            row_id
        ))


        if cursor.rowcount > 0:

            updated += 1


    connection.commit()
    connection.close()


    # ------------------------------------------------------
    # Result
    # ------------------------------------------------------

    print("Migration completed.")
    print()

    print(f"Events processed : {len(events)}")
    print(f"Events updated   : {updated}")
    print(f"Unknown events   : {unknown}")
    print()

    print("=" * 70)


# ==========================================================
# MAIN
# ==========================================================

if __name__ == "__main__":

    migrate()