import sqlite3


connection = sqlite3.connect("siem.db")

cursor = connection.cursor()

cursor.execute("""
    SELECT
        event_id,
        event_name,
        username,
        source_ip
    FROM events
    ORDER BY id DESC
    LIMIT 10
""")

rows = cursor.fetchall()

for row in rows:
    print(row)

connection.close()