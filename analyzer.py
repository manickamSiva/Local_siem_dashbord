import sqlite3


DATABASE = "siem.db"


def get_connection():
    return sqlite3.connect(DATABASE)


def show_summary():

    connection = get_connection()
    cursor = connection.cursor()

    print("\n" + "=" * 60)
    print("                  SIEM SUMMARY")
    print("=" * 60)

    cursor.execute("SELECT COUNT(*) FROM events")

    total_events = cursor.fetchone()[0]

    print(f"Total Events       : {total_events}")

    cursor.execute("""
        SELECT COUNT(*)
        FROM events
        WHERE event_id = 4625
    """)

    failed_logins = cursor.fetchone()[0]

    print(f"Failed Logons      : {failed_logins}")

    cursor.execute("""
        SELECT COUNT(*)
        FROM events
        WHERE event_id = 4624
    """)

    successful_logins = cursor.fetchone()[0]

    print(f"Successful Logons  : {successful_logins}")

    cursor.execute("""
        SELECT COUNT(DISTINCT source_ip)
        FROM events
        WHERE source_ip IS NOT NULL
    """)

    unique_ips = cursor.fetchone()[0]

    print(f"Unique Source IPs  : {unique_ips}")

    connection.close()


def show_event_counts():

    connection = get_connection()
    cursor = connection.cursor()

    print("\n" + "=" * 60)
    print("              EVENTS BY TYPE")
    print("=" * 60)

    cursor.execute("""
        SELECT
            event_id,
            event_name,
            COUNT(*) AS total
        FROM events
        GROUP BY event_id, event_name
        ORDER BY total DESC
    """)

    rows = cursor.fetchall()

    print(
        f"{'ID':<8}"
        f"{'Event':<35}"
        f"{'Count':<10}"
    )

    print("-" * 60)

    for event_id, event_name, total in rows:

        print(
            f"{event_id:<8}"
            f"{event_name:<35}"
            f"{total:<10}"
        )

    connection.close()


def show_failed_logins():

    connection = get_connection()
    cursor = connection.cursor()

    print("\n" + "=" * 60)
    print("               FAILED LOGONS")
    print("=" * 60)

    cursor.execute("""
        SELECT
            timestamp,
            username,
            source_ip,
            logon_type
        FROM events
        WHERE event_id = 4625
        ORDER BY id DESC
        LIMIT 20
    """)

    rows = cursor.fetchall()

    if not rows:

        print("No failed logons found.")

    else:

        for timestamp, username, source_ip, logon_type in rows:

            print(
                f"{timestamp} | "
                f"User={username} | "
                f"IP={source_ip} | "
                f"LogonType={logon_type}"
            )

    connection.close()


def show_top_source_ips():

    connection = get_connection()
    cursor = connection.cursor()

    print("\n" + "=" * 60)
    print("              TOP SOURCE IPs")
    print("=" * 60)

    cursor.execute("""
        SELECT
            source_ip,
            COUNT(*) AS total
        FROM events
        WHERE source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY total DESC
        LIMIT 10
    """)

    rows = cursor.fetchall()

    for ip, total in rows:

        print(
            f"{ip:<20} {total} events"
        )

    connection.close()


def main():

    show_summary()

    show_event_counts()

    show_failed_logins()

    show_top_source_ips()


if __name__ == "__main__":
    main()