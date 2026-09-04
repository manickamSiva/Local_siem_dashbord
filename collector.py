import win32evtlog
import win32evtlogutil
import json
import os
import time
import re

import database
import detection


SERVER = "localhost"

# Every log in this list gets polled each cycle. Record numbers are
# scoped per log (Security's #500 and Application's #500 are unrelated),
# so state is tracked per log_type — see load_state()/save_state().
LOG_TYPES = ["Security", "Application"]

OUTPUT_DIR = "logs"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "events.json")
STATE_FILE = os.path.join(OUTPUT_DIR, "collector_state.json")

POLL_INTERVAL = 2


# ==========================================================
# EVENT METADATA — Security log
# ==========================================================
# MITRE ATT&CK mappings below follow the widely-used community mapping
# of Windows Security audit event IDs to techniques (Microsoft/Elastic/
# Sigma detection rule references). Anything not listed here falls back
# to a generic entry with no MITRE technique rather than a guess.

SECURITY_EVENT_METADATA = {

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
    4657: {
        "name": "Registry Value Modified",
        "category": "Defense Evasion",
        "severity": "MEDIUM",
        "mitre": "T1112",
        "description": "A registry value was created, modified, or deleted."
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
    4697: {
        "name": "Service Installed",
        "category": "Persistence",
        "severity": "HIGH",
        "mitre": "T1543.003",
        "description": "A new service was installed on the system."
    },
    4698: {
        "name": "Scheduled Task Created",
        "category": "Persistence",
        "severity": "HIGH",
        "mitre": "T1053.005",
        "description": "A scheduled task was created."
    },
    4699: {
        "name": "Scheduled Task Deleted",
        "category": "Defense Evasion",
        "severity": "MEDIUM",
        "mitre": "T1053.005",
        "description": "A scheduled task was deleted."
    },
    4702: {
        "name": "Scheduled Task Updated",
        "category": "Persistence",
        "severity": "MEDIUM",
        "mitre": "T1053.005",
        "description": "A scheduled task was updated."
    },
    4719: {
        "name": "Audit Policy Changed",
        "category": "Defense Evasion",
        "severity": "HIGH",
        "mitre": "T1562.002",
        "description": "The system audit policy was changed."
    },
    4720: {
        "name": "User Account Created",
        "category": "Persistence",
        "severity": "MEDIUM",
        "mitre": "T1136.001",
        "description": "A new user account was created."
    },
    4722: {
        "name": "User Account Enabled",
        "category": "Persistence",
        "severity": "MEDIUM",
        "mitre": "T1098",
        "description": "A user account was enabled."
    },
    4724: {
        "name": "Password Reset Attempt",
        "category": "Credential Access",
        "severity": "MEDIUM",
        "mitre": "T1098",
        "description": "An attempt was made to reset an account's password."
    },
    4728: {
        "name": "Member Added to Security Group",
        "category": "Persistence",
        "severity": "MEDIUM",
        "mitre": "T1098",
        "description": "A member was added to a security-enabled global group."
    },
    4732: {
        "name": "Member Added to Local Group",
        "category": "Persistence",
        "severity": "MEDIUM",
        "mitre": "T1098",
        "description": "A member was added to a security-enabled local group."
    },
    4738: {
        "name": "User Account Changed",
        "category": "Account Management",
        "severity": "LOW",
        "mitre": "T1098",
        "description": "A user account was changed."
    },
    4740: {
        "name": "Account Locked Out",
        "category": "Authentication",
        "severity": "MEDIUM",
        "mitre": "T1110",
        "description": "A user account was locked out after repeated failed logons."
    },
    4756: {
        "name": "Member Added to Universal Group",
        "category": "Persistence",
        "severity": "MEDIUM",
        "mitre": "T1098",
        "description": "A member was added to a security-enabled universal group."
    },
    4767: {
        "name": "Account Unlocked",
        "category": "Account Management",
        "severity": "LOW",
        "mitre": None,
        "description": "A user account was unlocked."
    },
    4771: {
        "name": "Kerberos Pre-Authentication Failed",
        "category": "Authentication",
        "severity": "MEDIUM",
        "mitre": "T1110",
        "description": "Kerberos pre-authentication failed for a logon attempt."
    },
    4776: {
        "name": "Credential Validation",
        "category": "Authentication",
        "severity": "LOW",
        "mitre": "T1110",
        "description": "The domain controller attempted to validate credentials."
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
    5140: {
        "name": "Network Share Accessed",
        "category": "Lateral Movement",
        "severity": "MEDIUM",
        "mitre": "T1021.002",
        "description": "A network share was accessed."
    },
    5145: {
        "name": "Detailed File Share Access",
        "category": "Lateral Movement",
        "severity": "MEDIUM",
        "mitre": "T1021.002",
        "description": "A network share object was checked for access."
    },
    5379: {
        "name": "Credential Manager Access",
        "category": "Credential Access",
        "severity": "MEDIUM",
        "mitre": "T1555.004",
        "description": "Credentials stored in Windows Credential Manager were accessed."
    },
    1102: {
        "name": "Audit Log Cleared",
        "category": "Defense Evasion",
        "severity": "HIGH",
        "mitre": "T1070.001",
        "description": "The security audit log was cleared."
    },
}


# Keep compatibility with any existing code that imports EVENT_NAMES.
EVENT_NAMES = {
    event_id: metadata["name"]
    for event_id, metadata in SECURITY_EVENT_METADATA.items()
}


# ==========================================================
# EVENT METADATA — Application log
# ==========================================================
# Application-log event IDs come from whatever software emitted them, so
# there's no universal registry the way there is for Security auditing.
# This covers the common Windows-generated ones. Most of these describe
# ordinary software behavior, not adversarial techniques — MITRE is left
# unset rather than guessed.

APPLICATION_EVENT_METADATA = {
    1000: {
        "name": "Application Error",
        "category": "Application",
        "severity": "MEDIUM",
        "mitre": None,
        "description": "An application crashed unexpectedly."
    },
    1001: {
        "name": "Windows Error Reporting",
        "category": "Application",
        "severity": "INFO",
        "mitre": None,
        "description": "Windows Error Reporting logged a fault report."
    },
    1002: {
        "name": "Application Hang",
        "category": "Application",
        "severity": "MEDIUM",
        "mitre": None,
        "description": "An application stopped responding."
    },
    1026: {
        "name": ".NET Runtime Error",
        "category": "Application",
        "severity": "MEDIUM",
        "mitre": None,
        "description": "A .NET runtime error was reported."
    },
    11707: {
        "name": "Software Install Succeeded",
        "category": "Software Management",
        "severity": "LOW",
        "mitre": None,
        "description": "An MSI installation completed successfully."
    },
    11708: {
        "name": "Software Install Failed",
        "category": "Software Management",
        "severity": "MEDIUM",
        "mitre": None,
        "description": "An MSI installation failed."
    },
    11724: {
        "name": "Software Uninstall Succeeded",
        "category": "Software Management",
        "severity": "LOW",
        "mitre": None,
        "description": "Software was uninstalled."
    },
}


# ==========================================================
# STATE (per log type — replaces the old single-file resume logic)
# ==========================================================

def load_state():

    if not os.path.exists(STATE_FILE):
        return {log_type: 0 for log_type in LOG_TYPES}

    try:
        with open(STATE_FILE, "r", encoding="utf-8") as file:
            state = json.load(file)
    except (json.JSONDecodeError, OSError):
        state = {}

    return {log_type: state.get(log_type, 0) for log_type in LOG_TYPES}


def save_state(state):

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open(STATE_FILE, "w", encoding="utf-8") as file:
        json.dump(state, file, indent=4)


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
# EVENT PARSERS (Security log — these events carry structured
# username/domain/logon insertion strings; Application log events don't
# follow this schema, so they go through metadata lookup only)
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


SECURITY_PARSERS = {
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


# ==========================================================
# EVENT DISPATCHER
# ==========================================================

def parse_event(event_id, values, log_type, message=""):

    if log_type == "Security":

        parser = SECURITY_PARSERS.get(event_id)

        if parser:
            return parser(values)

        metadata = SECURITY_EVENT_METADATA.get(event_id)

        if metadata:
            return {
                "event_name": metadata["name"],
                "category": metadata["category"],
                "severity": metadata["severity"],
                "mitre_technique": metadata["mitre"],
                "description": metadata["description"]
            }

        # Genuinely unmapped Security event — surface the real event ID
        # and whatever message Windows provided instead of a generic
        # "Other" placeholder. No MITRE technique is invented.
        return {
            "event_name": f"Security Event {event_id}",
            "category": "Other",
            "severity": "INFO",
            "mitre_technique": None,
            "description": message[:200] if message else "Unrecognized Windows Security event."
        }

    # Application (or any other future) log — no structured username/
    # domain insertion strings to parse, so metadata lookup only.
    metadata = APPLICATION_EVENT_METADATA.get(event_id)

    if metadata:
        return {
            "event_name": metadata["name"],
            "category": metadata["category"],
            "severity": metadata["severity"],
            "mitre_technique": metadata["mitre"],
            "description": metadata["description"]
        }

    return {
        "event_name": f"Application Event {event_id}",
        "category": "Application",
        "severity": "INFO",
        "mitre_technique": None,
        "description": message[:200] if message else "Unrecognized Windows Application event."
    }


# ==========================================================
# NORMALIZE EVENT
# ==========================================================

def normalize_event(event, log_type):

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
        insertions,
        log_type,
        message
    )

    return {
        "log_type": log_type,
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

def collect_events(log_type, last_record_id):

    handle = win32evtlog.OpenEventLog(
        SERVER,
        log_type
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

        event_data = normalize_event(event, log_type)

        # -----------------------------------------
        # Save JSON
        # -----------------------------------------

        save_json_event(event_data)

        # -----------------------------------------
        # Save SQLite
        # -----------------------------------------

        event_db_id = database.insert_event(
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
            parsed.get("username"),
            timestamp=event_data["timestamp"],
            event_db_id=event_db_id
        )

        print(
            f"[NEW EVENT] "
            f"LOG={log_type} "
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

    print(f"Monitoring : {', '.join(LOG_TYPES)}")
    print(f"JSON       : {OUTPUT_FILE}")
    print(f"State      : {STATE_FILE}")
    print("Database   : siem.db")
    print(f"Interval   : {POLL_INTERVAL}s")
    print()

    database.create_database()
    database.create_alerts_table()
    database.create_alert_events_table()

    state = load_state()

    print("Starting from:")
    for log_type in LOG_TYPES:
        print(f"  {log_type:<12} Record ID {state[log_type]}")

    print()
    print("Waiting for new events...")
    print("Press CTRL+C to stop.")
    print()

    try:

        while True:

            for log_type in LOG_TYPES:
                try:
                    state[log_type] = collect_events(
                        log_type,
                        state[log_type]
                    )
                except Exception as exc:
                    print(f"[WARN] Failed to read {log_type} log: {exc}")

            save_state(state)

            time.sleep(
                POLL_INTERVAL
            )

    except KeyboardInterrupt:

        print()
        print("Collector stopped.")


if __name__ == "__main__":
    main()