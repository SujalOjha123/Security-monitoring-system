VAPT Live Log Collection & Detection Dashboard

Overview: A read-only security monitoring system that connects to a
remote Linux host via SSH, collects logs and telemetry, stores them
locally, and displays them in a real-time web dashboard.

Key Features: - Multi-source log collection (streaming + snapshot) -
Per-source JSONL storage by date - Real-time dashboard with multiple
views - Security alert detection (web attacks, brute force, disk issues,
service failures)

Architecture: 1. collector_main.py - Collects logs via SSH - Parses and
stores events - Updates alerts and metrics

Before running a tool environment variable need to be edited /config/setup.env
SERVER_HOST=11.5.0.0
SERVER_USER=GG**
SERVER_PASSWORD=AG****
LOG_PATH=/var/log/nginx/access.log
original host credential were not included as it goes outside of the client contract. 

1.  main.py
    -   Flask web server
    -   Streams live updates to UI

Data Sources: - Logs: nginx, auth, syslog, php-fpm, cron, kernel -
Snapshots: disk, CPU/memory, services, network

Usage: 1. Run collector: python collector_main.py

2.  Run dashboard: python main.py

Notes: - Read-only access ensures no impact on target system - Collector
and UI run independently - Designed for VAPT and security monitoring use
