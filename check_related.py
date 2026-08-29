import sqlite3
c = sqlite3.connect("siem.db")
rows = c.execute(
    "SELECT id, event_id, event_name, username, source_ip, timestamp "
    "FROM events WHERE source_ip=? OR username=? ORDER BY id DESC",
    ("192.168.100.50", "TestUser")
).fetchall()
for row in rows:
    print(row)
c.close()
