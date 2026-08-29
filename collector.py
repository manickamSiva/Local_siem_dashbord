import win32evtlog
import win32evtlogutil
import json
import os
import time
import re

import database
import detection


SERVER = "localhost"
LOG_TYPE = "Security"

OUTPUT_DIR = "logs"
OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "events.json"
)

POLL_INTERVAL = 2


# ==========================================================
# EVENT METADATA
# ==========================================================

EVENT_METADATA = {

    4624: {
        "name": "Successful Logon",
        "category": "Authentication",
        "severity": "LOW",
        "mitre": None,
        "description": "A successful logon occurred."
    },

    4625: {
        "name": "Failed Logon",
        "category": "Authentication",
        "severity": "MEDIUM",
        "mitre": "T1110",
        "description": "A logon attempt failed."
    },

    4634: {
        "name": "Logoff",
        "category": "Authentication",
        "severity": "LOW",
        "mitre": None,
        "description": "A user session was terminated."
    },

    4648: {
        "name": "Explicit Credential Logon",
        "category": "Credential Access",
        "severity": "MEDIUM",
        "mitre": "T1078",
        "description": "A logon was attempted using explicit credentials."
    },

    4672: {
        "name": "Special Privileges Assigned",
        "category": "Privilege",
        "severity": "HIGH",
        "mitre": None,
        "description": "Special privileges were assigned to a new logon."
    },

    4688: {
        "name": "Process Creation",
        "category": "Execution",
        "severity": "MEDIUM",
        "mitre": None,
        "description": "A new process was created."
    },

    4798: {
        "name": "User Account Enumeration",
        "category": "Discovery",
        "severity": "MEDIUM",
        "mitre": "T1087",
        "description": "A process enumerated user accounts."
    },

    4799: {
        "name": "Security Group Enumeration",
        "category": "Discovery",
        "severity": "MEDIUM",
        "mitre": "T1069",
        "description": "A process enumerated security groups."
    },

    5379: {
        "name": "Credential Manager Access",
        "category": "Credential Access",
        "severity": "MEDIUM",
        "mitre": "T1555.004",
        "description": "Credentials stored in Windows Credential Manager were accessed."
    }
}


# Keep compatibility with your existing code
EVENT_NAMES = {
    event_id: metadata["name"]
    for event_id, metadata in EVENT_METADATA.items()
}


# ==========================================================
# EXISTING EVENTS
# ==========================================================

def load_existing_events():

    if not os.path.exists(OUTPUT_FILE):
        return 0

    try:

        with open(
            OUTPUT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            events = json.load(file)

        if events:
            return events[-1]["record_id"]

    except (
        json.JSONDecodeError,
        OSError,
        KeyError
    ):
        pass

    return 0


def save_json_event(event_data):

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    events = []

    if os.path.exists(OUTPUT_FILE):

        try:

            with open(
                OUTPUT_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                events = json.load(file)

        except (
            json.JSONDecodeError,
            OSError
        ):

            events = []

    events.append(event_data)

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            events,
            file,
            indent=4,
            ensure_ascii=False
        )


# ==========================================================
# EVENT TYPE
# ==========================================================

def get_event_type(event_type):

    event_types = {
        1: "ERROR",
        2: "WARNING",
        4: "INFO",
        8: "AUDIT_SUCCESS",
        16: "AUDIT_FAILURE"
    }

    return event_types.get(
        event_type,
        "UNKNOWN"
    )


# ==========================================================
# STRING INSERTIONS
# ==========================================================

def get_insertions(event):

    try:

        if event.StringInserts:

            return [
                str(value).strip()
                for value in event.StringInserts
            ]

    except Exception:
        pass

    return []


# ==========================================================
# IP DETECTION
# ==========================================================

def find_ip(values):

    for value in values:

        if re.fullmatch(
            r"(?:\d{1,3}\.){3}\d{1,3}",
            value
        ):

            return value

    return None


# ==========================================================
# EVENT PARSERS
# ==========================================================

def parse_4624(values):

    data = {
        "event_name": "Successful Logon",
        "category": "Authentication",
        "severity": "LOW",
        "mitre_technique": None,
        "description": "A successful logon occurred.",
        "username": None,
        "domain": None,
        "logon_type": None,
        "source_ip": find_ip(values),
        "authentication_package": None
    }

    if len(values) > 5:
        data["username"] = values[5]

    if len(values) > 6:
        data["domain"] = values[6]

    if len(values) > 8:
        data["logon_type"] = values[8]

    if len(values) > 10:
        data["authentication_package"] = values[10]

    return data


def parse_4625(values):

    data = {
        "event_name": "Failed Logon",
        "category": "Authentication",
        "severity": "MEDIUM",
        "mitre_technique": "T1110",
        "description": "A logon attempt failed.",
        "username": None,
        "domain": None,
        "logon_type": None,
        "source_ip": find_ip(values),
        "failure_reason": None
    }

    if len(values) > 5:
        data["username"] = values[5]

    if len(values) > 6:
        data["domain"] = values[6]

    if len(values) > 10:
        data["logon_type"] = values[10]

    return data


def parse_4634(values):

    return {
        "event_name": "Logoff",
        "category": "Authentication",
        "severity": "LOW",
        "mitre_technique": None,
        "description": "A user session was terminated.",
        "username": values[1] if len(values) > 1 else None,
        "domain": values[2] if len(values) > 2 else None
    }


def parse_4648(values):

    return {
        "event_name": "Explicit Credential Logon",
        "category": "Credential Access",
        "severity": "MEDIUM",
        "mitre_technique": "T1078",
        "description": "A logon was attempted using explicit credentials.",
        "username": values[5] if len(values) > 5 else None,
        "domain": values[6] if len(values) > 6 else None
    }


def parse_4672(values):

    data = {
        "event_name": "Special Privileges Assigned",
        "category": "Privilege",
        "severity": "HIGH",
        "mitre_technique": None,
        "description": "Special privileges were assigned to a new logon.",
        "username": None,
        "domain": None,
        "privileges": []
    }

    if len(values) > 1:
        data["username"] = values[1]

    if len(values) > 2:
        data["domain"] = values[2]

    if len(values) > 4:

        for value in values[4:]:

            value = value.strip()

            if value:
                data["privileges"].append(value)

    return data


def parse_4688(values):

    return {
        "event_name": "Process Creation",
        "category": "Execution",
        "severity": "MEDIUM",
        "mitre_technique": None,
        "description": "A new process was created.",
        "username": values[1] if len(values) > 1 else None,
        "domain": values[2] if len(values) > 2 else None
    }


def parse_4798(values):

    return {
        "event_name": "User Account Enumeration",
        "category": "Discovery",
        "severity": "MEDIUM",
        "mitre_technique": "T1087",
        "description": "A process enumerated user accounts.",
        "username": values[1] if len(values) > 1 else None,
        "domain": values[2] if len(values) > 2 else None
    }


def parse_4799(values):

    return {
        "event_name": "Security Group Enumeration",
        "category": "Discovery",
        "severity": "MEDIUM",
        "mitre_technique": "T1069",
        "description": "A process enumerated security groups.",
        "username": values[1] if len(values) > 1 else None,
        "domain": values[2] if len(values) > 2 else None
    }


def parse_5379(values):

    return {
        "event_name": "Credential Manager Access",
        "category": "Credential Access",
        "severity": "MEDIUM",
        "mitre_technique": "T1555.004",
        "description": "Credentials stored in Windows Credential Manager were accessed.",
        "username": values[1] if len(values) > 1 else None,
        "domain": values[2] if len(values) > 2 else None
    }


# ==========================================================
# EVENT DISPATCHER
# ==========================================================

def parse_event(event_id, values):

    parsers = {
        4624: parse_4624,
        4625: parse_4625,
        4634: parse_4634,
        4648: parse_4648,
        4672: parse_4672,
        4688: parse_4688,
        4798: parse_4798,
        4799: parse_4799,
        5379: parse_5379
    }

    parser = parsers.get(event_id)

    if parser:
        return parser(values)

    metadata = EVENT_METADATA.get(
        event_id,
        {
            "name": "Other",
            "category": "Other",
            "severity": "INFO",
            "mitre": None,
            "description": "Windows event recorded."
        }
    )

    return {
        "event_name": metadata["name"],
        "category": metadata["category"],
        "severity": metadata["severity"],
        "mitre_technique": metadata["mitre"],
        "description": metadata["description"]
    }


# ==========================================================
# NORMALIZE EVENT
# ==========================================================

def normalize_event(event):

    event_id = event.EventID & 0xFFFF

    insertions = get_insertions(event)

    try:

        message = win32evtlogutil.SafeFormatMessage(
            event,
            SERVER
        ).strip()

    except Exception:

        message = ""

    parsed = parse_event(
        event_id,
        insertions
    )

    return {
        "timestamp": event.TimeGenerated.Format(),
        "record_id": event.RecordNumber,
        "event_id": event_id,
        "event_type": get_event_type(
            event.EventType
        ),
        "source": event.SourceName,
        "computer": event.ComputerName,
        "message": message,
        "parsed": parsed
    }


# ==========================================================
# COLLECT EVENTS
# ==========================================================

def collect_events(last_record_id):

    handle = win32evtlog.OpenEventLog(
        SERVER,
        LOG_TYPE
    )

    flags = (
        win32evtlog.EVENTLOG_BACKWARDS_READ
        | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    )

    events = win32evtlog.ReadEventLog(
        handle,
        flags,
        0
    )

    win32evtlog.CloseEventLog(handle)

    if not events:
        return last_record_id

    events.reverse()

    for event in events:

        if event.RecordNumber <= last_record_id:
            continue

        event_data = normalize_event(event)

        # -----------------------------------------
        # Save JSON
        # -----------------------------------------

        save_json_event(event_data)

        # -----------------------------------------
        # Save SQLite
        # -----------------------------------------

        database.insert_event(
            event_data
        )

        parsed = event_data["parsed"]

        event_id = event_data["event_id"]

        event_name = parsed.get(
            "event_name",
            "Other"
        )

        # -----------------------------------------
        # Detection Engine
        # -----------------------------------------

        detection.process_event(
            event_id,
            parsed.get("source_ip"),
            parsed.get("username")
        )

        print(
            f"[NEW EVENT] "
            f"ID={event_id} "
            f"NAME={event_name} "
            f"RECORD={event.RecordNumber}"
        )

        last_record_id = event.RecordNumber

    return last_record_id


# ==========================================================
# MAIN
# ==========================================================

def main():

    print("=" * 70)
    print("              MiniSIEM - Log Collector")
    print("=" * 70)

    print(f"Monitoring : {LOG_TYPE}")
    print(f"JSON       : {OUTPUT_FILE}")
    print("Database   : siem.db")
    print(f"Interval   : {POLL_INTERVAL}s")
    print()

    database.create_database()
    database.create_alerts_table()
    database.create_alert_events_table()

    last_record_id = load_existing_events()

    print(
        f"Starting from Record ID: "
        f"{last_record_id}"
    )

    print(
        "Waiting for new events..."
    )

    print(
        "Press CTRL+C to stop."
    )

    print()

    try:

        while True:

            last_record_id = collect_events(
                last_record_id
            )

            time.sleep(
                POLL_INTERVAL
            )

    except KeyboardInterrupt:

        print()
        print("Collector stopped.")


if __name__ == "__main__":
    main()