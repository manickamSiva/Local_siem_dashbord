import sqlite3
from datetime import datetime


DATABASE = "siem.db"


def insert_test_events():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    now = datetime.now()

    print("Creating 5 test failed-login events...")

    for i in range(5):

        cursor.execute("""
            INSERT INTO events (
                timestamp,
                record_id,
                event_id,
                event_type,
                event_name,
                source,
                computer,
                username,
                domain,
                logon_type,
                source_ip,
                authentication_package,
                message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            now.strftime("%a %b %d %H:%M:%S %Y"),
            900000 + i,
            4625,
            "AUDIT_FAILURE",
            "Failed Logon",
            "TEST",
            "TEST-PC",
            "TestUser",
            "TEST",
            "3",
            "192.168.100.50",
            "NTLM",
            "TEST EVENT - Simulated failed login"
        ))

    connection.commit()
    connection.close()

    print("5 test events inserted successfully.")


if __name__ == "__main__":
    insert_test_events()