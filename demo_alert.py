import sqlite3
from datetime import datetime

DATABASE = "siem.db"


def create_demo_alert():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

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
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Brute Force",
        "HIGH",
        "192.168.100.50",
        "TestUser",
        "Possible brute force attack detected. 5 failed login attempts.",
        "T1110",
        "NEW"
    ))

    connection.commit()

    alert_id = cursor.lastrowid

    connection.close()

    print(f"Demo alert created successfully. ID = {alert_id}")


if __name__ == "__main__":
    create_demo_alert()