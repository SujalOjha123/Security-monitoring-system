# VAPT Defender

VAPT Defender is a lightweight security monitoring and log analysis dashboard for remote Linux servers. It collects logs and system health information over SSH, stores them locally, detects suspicious activity, and displays real-time results through a Flask-based web interface.

The project is designed for basic VAPT support, server monitoring, incident review, and early detection of common web and host-based security events.

---

## Features

- Remote Linux server monitoring over SSH
- Live Nginx access and error log collection
- Real-time web dashboard using Flask and Socket.IO
- Web traffic monitoring with raw and structured views
- Visitor IP tracking and geolocation map
- Host health monitoring:
  - Disk usage
  - CPU and memory usage
  - Service status
  - Network state
- Security monitoring:
  - Authentication logs
  - Failed login attempts
  - System errors
  - Kernel and syslog messages
- Security alert detection for:
  - SQL injection attempts
  - XSS attempts
  - Path traversal
  - Brute-force login attempts
  - Suspicious user agents
  - Scanner activity
  - Service failures
  - Disk pressure
  - Error spikes
- Historical log browsing
- Unique IP statistics
- Export support for statistics

---


### Tech Stack

- **Backend**: Python, Flask, Flask-SocketIO, Paramiko
- **Frontend**: HTML, CSS, JavaScript (Jinja2 + SocketIO)
- **Data Source**: Remote Linux server via SSH

---

### Prerequisites

- Python 3.10+
- SSH access to a remote Linux server
- Required packages:
  ```bash
  pip install flask flask-socketio paramiko python-dotenv


  
## Project Architecture

```text
Remote Linux Server
        |
        | SSH Connection
        v
collector_main.py
        |
        | Collects logs and system metrics
        v
Local Storage
        |
        | JSON / JSONL files
        v
main.py Flask Application
        |
        | Socket.IO real-time updates
        v
Web Dashboard

The collector connects to a remote Linux machine using SSH and fetches logs or system command outputs. The web application reads the collected files, processes alerts, and displays the information on a real-time dashboard.

## Dashboard Pages ##

### Overview
**Route:** `/overview`

Displays a summary of the monitored server, including:
- Online sources
- Recent alerts
- Worst disk usage
- Failed services
- CPU and memory indicators
- Recent security alerts

### Web Traffic
**Route:** `/traffic`

Monitors live Nginx access logs.

Includes:
- Raw log stream
- Structured parsed request view
- Origin map for visitor IP addresses

### Host Health
**Route:** `/health`

Shows infrastructure health information.

Includes:
- Disk usage
- Service status
- CPU and memory usage
- Network connections

### Security
**Route:** `/security`

Displays authentication and error-related logs.

Includes:
- Failed login attempts
- Successful login events
- Invalid usernames
- Brute-force patterns
- Nginx errors
- PHP-FPM errors
- Syslog and kernel messages

### History
**Route:** `/history`

Allows browsing of previously collected logs by source and date.

### Statistics
**Route:** `/stats`

Shows unique IP analytics.

Includes:
- Unique IP count
- Total hits
- Countries detected
- First seen and last seen timestamps
- Export options (CSV, JSON, PDF)

### Alerts
**Route:** `/alerts`

Displays detected security alerts.

Each alert may contain:
- Severity level
- Source IP
- Country
- Timestamp
- Triggered rule
- Request path
- Raw evidence log


## Additional Routes

- `/structured`
- `/map`
- `/disk`
- `/services`
- `/auth`
- `/errors`
- `/stats/print`
- `/stats/export.csv`
- `/stats/export.json`

## Data Sources

### Default Enabled Sources
- `nginx_access`
- `nginx_error`
- `disk_usage`
- `service_health`

### Continuous Log Sources
- `nginx_access`
- `nginx_error`
- `auth_log`
- `syslog`
- `php_fpm_error`
- `cron_log`
- `kernel_log`

### Snapshot Sources
- `disk_usage`
- `memory_cpu`
- `service_health`
- `network_state`

## Local Storage

Collected data is stored in the `results/live_logs/` directory.

### Important Files
- `results/live_logs/source_status.json`
- `results/live_logs/metrics_latest.json`
- `results/live_logs/alerts.jsonl`
- `results/live_logs/unique_ips.json`
- `results/live_logs/geo_cache.json`
- `results/live_logs/<source_id>/YYYY-MM-DD.jsonl`


##License##
Copyright (c) 2026 Sujal Ojha  

All rights reserved.

This source code is provided for viewing purposes only. No permission is granted to use, copy, modify, merge, publish, distribute, sublicense, or sell any part of this software without prior written permission from the copyright holder.
