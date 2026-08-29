# MiniSIEM

### Local Windows Security Monitoring & Detection Platform

MiniSIEM is a lightweight, local Security Information and Event Management (SIEM) platform designed for cybersecurity learning, experimentation, detection engineering, and SOC analyst training.

It collects Windows Security Event Logs, stores and analyzes them locally, applies detection logic, maps security events to MITRE ATT&CK techniques, generates alerts, and provides a web-based SOC dashboard for monitoring and investigation.

---

## 🎯 What is MiniSIEM?

A SIEM collects security events from systems, analyzes those events, detects suspicious activity, and provides alerts that security analysts can investigate.

MiniSIEM demonstrates this process locally on a Windows machine.

```text
Windows Security Event Logs
            │
            ▼
      collector.py
      Log Collector
            │
            ▼
       Event Storage
          SQLite
            │
            ▼
       detection.py
      Detection Engine
            │
            ▼
          Alerts
            │
            ▼
          api.py
        FastAPI API
            │
            ▼
     Web SOC Dashboard
            │
     ┌──────┼────────┐
     ▼      ▼        ▼
   Events  Alerts  Analytics
     │      │        │
     ▼      ▼        ▼
Investigation Timeline Severity
```

---

## ✨ Features

### 🖥️ Windows Security Event Collection

MiniSIEM monitors the Windows `Security` event log and collects newly generated events.

Currently supported examples include:

- `4624` — Successful Logon
- `4625` — Failed Logon
- `4634` — Logoff
- `4672` — Special Privileges Assigned
- `4688` — Process Creation
- `4798` — User Account Enumeration
- `4799` — Security Group Enumeration
- `5379` — Credential Manager Credentials Were Read

The collector keeps track of Windows Event Record IDs so previously processed events are not repeatedly inserted.

---

## 💾 Event Storage

Events are stored locally using SQLite.

Event information can include:

- Timestamp
- Record ID
- Windows Event ID
- Event type
- Event name
- Username
- Domain
- Source IP
- Logon type
- Authentication package
- Category
- Severity
- MITRE ATT&CK technique
- Description
- Event message

---

## 🔎 Event Enrichment

MiniSIEM enriches collected Windows events with additional security context.

Events can be classified into categories such as:

- Authentication
- Credential Access
- Discovery
- Privilege
- Execution

Events can also receive severity levels:

- LOW
- MEDIUM
- HIGH

Relevant events can also be mapped to MITRE ATT&CK techniques.

Example:

```text
Event ID:      5379
Category:      Credential Access
Severity:      MEDIUM
MITRE:         T1555.004
```

---

## 🚨 Detection & Alerts

The detection engine analyzes security events and generates alerts when defined suspicious activity is detected.

Alerts can contain:

- Alert type
- Severity
- Source IP
- Username
- Description
- MITRE ATT&CK technique
- Alert status

Alert states:

```text
NEW
 │
 ▼
INVESTIGATING
 │
 ▼
RESOLVED
```

---

## 🔬 Event Investigation

Each event displayed in the dashboard can be opened for investigation.

The event investigation view provides information such as:

- Event ID
- Event name
- Timestamp
- Username
- Source IP
- Category
- Severity
- MITRE ATT&CK technique
- Event type
- Event details
- Related alert information

This allows an analyst to inspect an individual security event directly from the dashboard.

---

## 🚨 Alert Investigation

Active alerts provide an investigation workflow for security analysts.

An analyst can:

```text
View Event
    │
    ▼
Investigate
    │
    ▼
Review Related Events
    │
    ▼
Analyze Timeline
    │
    ▼
Resolve Alert
```

The investigation view can display related events associated with an alert.

This provides a basic SOC-style investigation workflow.

---

## 📊 SOC Dashboard

MiniSIEM includes a web-based dashboard for monitoring Windows security activity.

### Statistics

The dashboard displays:

- Total Events
- Failed Logins
- Successful Logins
- Active Alerts
- Source IPs

### Security Analytics

The dashboard provides:

- Events by Category
- Severity Distribution

### Recent Events

The event table displays:

- Time
- Event ID
- Event name
- Category
- Severity
- Username
- Source IP
- MITRE ATT&CK technique
- Investigation action

---

## 🔄 Automatic Dashboard Refresh

The dashboard automatically refreshes its data periodically so newly collected events can appear without manually reloading the page.

The dashboard also provides a dynamic API status indicator.

When the API is available:

```text
🟢 API Online
```

When the API cannot be reached:

```text
🔴 API Offline
```

The dashboard also displays the last successful update time.

Individual dashboard sections handle API failures independently.

For example, if the severity API fails, the severity section can display:

```text
Failed to load severity data
```

while other working sections continue displaying their data.

---

## 🧩 Project Structure

```text
MiniSIEM/
│
├── dashboard/
│   ├── index.html
│   ├── app.js
│   └── style.css
│
├── logs/
│
├── analyzer.py
├── api.py
├── collector.py
├── database.py
├── detection.py
├── migrate_events.py
├── check_related.py
├── query_database.py
├── query_failed_logins.py
│
├── test_database.py
├── test_detection.py
│
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

---

## ⚙️ Requirements

MiniSIEM is currently designed for Windows.

Requirements:

- Windows
- Python 3.x
- FastAPI
- Uvicorn
- SQLite
- PowerShell

Administrator privileges may be required to access certain Windows Security Event Logs.

---

# 🚀 Installation

Clone the repository:

```powershell
git clone https://github.com/YOUR_USERNAME/Local_sien_dashboard.git
cd Local_siem_dashbord
```

Create a Python virtual environment:

```powershell
python -m venv venv
```

Activate the virtual environment:

```powershell
.\venv\Scripts\Activate.ps1
```

Install the required Python packages:

```powershell
pip install -r requirements.txt
```

---

# ▶️ Running MiniSIEM

MiniSIEM consists of three main components:

```text
Collector
    +
FastAPI
    +
Dashboard
```

Run each component in a separate PowerShell terminal.

---

## 1. Start the API

```powershell
uvicorn api:app --reload --host 127.0.0.1 --port 8000
```

The API will run at:

```text
http://127.0.0.1:8000
```

---

## 2. Start the Windows Event Collector

Open another PowerShell terminal.

Activate the environment:

```powershell
.\venv\Scripts\Activate.ps1
```

Start the collector:

```powershell
python collector.py
```

The collector monitors the Windows:

```text
Security
```

event log.

Example output:

```text
MiniSIEM - Log Collector

Monitoring : Security
JSON       : logs\events.json
Database   : siem.db
Interval   : 2s

Starting from Record ID: XXXXX

Waiting for new events...
```

When a new Windows event is detected:

```text
[NEW EVENT] ID=4799
NAME=Security Group Enumeration
```

---

## 3. Start the Dashboard

Open another PowerShell terminal.

Run:

```powershell
python -m http.server 5500 --directory dashboard
```

Open your browser:

```text
http://127.0.0.1:5500
```

The MiniSIEM SOC dashboard will now be available.

---

# 🔌 API Endpoints

MiniSIEM provides REST API endpoints through FastAPI.

### Statistics

```http
GET /api/stats
```

### Events

```http
GET /api/events
```

Example:

```http
GET /api/events?limit=20
```

### Single Event

```http
GET /api/events/{event_id}
```

### Alerts

```http
GET /api/alerts
```

### Single Alert

```http
GET /api/alerts/{alert_id}
```

### Alert Related Events

```http
GET /api/alerts/{alert_id}/events
```

### Update Alert Status

```http
PUT /api/alerts/{alert_id}/status
```

Supported statuses:

```text
NEW
INVESTIGATING
RESOLVED
```

### Active Alerts

```http
GET /api/alerts/active
```

### Event Categories

```http
GET /api/categories
```

### Severity Distribution

```http
GET /api/severity
```

---

# 🛡️ MITRE ATT&CK

MiniSIEM uses MITRE ATT&CK technique identifiers to provide additional security context for events.

Examples include:

```text
T1078      Valid Accounts
T1087      Account Discovery
T1069      Permission Groups Discovery
T1059      Command and Scripting Interpreter
T1555.004  Credentials from Password Stores
```

The MITRE mappings help analysts understand the type of adversary behavior represented by security events.

---

# 🧪 Testing

The project contains test scripts for database and detection functionality.

Run:

```powershell
python test_database.py
```

and:

```powershell
python test_detection.py
```

---

# 🔐 Security & Privacy

MiniSIEM is intended for:

- Cybersecurity learning
- Blue Team training
- SOC analyst training
- Detection engineering
- Windows security monitoring
- Home security labs
- SIEM experimentation

Windows Security Events can contain sensitive information such as:

- Usernames
- Computer names
- IP addresses
- Authentication information

**Do not commit real or sensitive logs to a public repository.**

The `.gitignore` file excludes local databases, virtual environments, and collected log files.

---

# ⚠️ Disclaimer

MiniSIEM is an open-source educational and research project designed to help developers, cybersecurity students, SOC analysts, and security enthusiasts understand how a basic Security Information and Event Management (SIEM) system works.

The project is intended for **learning, experimentation, development, and authorized security monitoring**.

You are welcome to:

- Explore how the collector, database, detection engine, analyzer, API, and dashboard work together.
- Modify and extend the detection rules and security analytics.
- Add support for new Windows Event IDs and MITRE ATT&CK techniques.
- Improve the dashboard and user interface.
- Add new API endpoints and features.
- Improve performance, reliability, and error handling.
- Report bugs and suggest new features.
- Submit pull requests and contribute improvements.

Please only use MiniSIEM to monitor systems and security logs that you own or have **explicit authorization** to monitor.

Contributions, ideas, improvements, and constructive feedback are welcome. The goal of this project is to continuously improve MiniSIEM while helping others learn how SIEM systems work internally.

---

# 🗺️ Roadmap

The project is actively evolving.

Planned improvements include:

- [ ] More Windows detection rules
- [ ] Advanced event correlation
- [ ] Improved MITRE ATT&CK coverage
- [ ] Brute-force detection
- [ ] Password spraying detection
- [ ] Suspicious process detection
- [ ] Better investigation timelines
- [ ] Event search
- [ ] Event filtering
- [ ] Time-range filtering
- [ ] Advanced dashboard charts
- [ ] Detection rule management
- [ ] Investigation export
- [ ] More automated tests
- [ ] Docker deployment
- [ ] Production deployment improvements

---

# 🤝 Contributing

Contributions, detection rules, ideas, bug reports, and improvements are welcome.

Typical contribution workflow:

```text
Fork
  │
  ▼
Create Feature Branch
  │
  ▼
Make Changes
  │
  ▼
Test
  │
  ▼
Commit
  │
  ▼
Pull Request
```

Please do not include:

- Passwords
- Credentials
- Real security logs
- Personal information
- Private IP information
- Local databases
- Virtual environments

in contributions.

---

# 📜 License

MiniSIEM is released under the MIT License.

See the `LICENSE` file for the complete license text.

---

# 📌 Project Status

MiniSIEM is an actively developed open-source learning project focused on building a lightweight local SOC/SIEM platform for Windows security monitoring.

The current workflow is:

```text
COLLECT
   ↓
STORE
   ↓
ENRICH
   ↓
DETECT
   ↓
ALERT
   ↓
INVESTIGATE
   ↓
RESPOND
   ↓
RESOLVE
```

---

## 🛡️ Built for learning Blue Team & SOC operations
