import sqlite3


connection = sqlite3.connect("siem.db")

cursor = connection.cursor()

cursor.execute("""
    SELECT
        source_ip,
        COUNT(*)
    FROM events
    WHERE event_id = 4625
    GROUP BY source_ip
""")

results = cursor.fetchall()

print("\nFailed Logons by Source IP")
print("-" * 40)

for source_ip, count in results:

    print(
        f"IP: {source_ip:<20} "
        f"Attempts: {count}"
    )

connection.close()