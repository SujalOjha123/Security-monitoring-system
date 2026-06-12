import csv
import json
import time
from io import StringIO

from flask import Flask, Response, jsonify, render_template, request
from flask_socketio import SocketIO

from collector.source_registry import get_source_map, get_sources
from web.alert_store import load_recent_alerts
from web.log_store import (
    LOG_DIR,
    get_source_log_path,
    list_history_dates,
    list_history_sources,
    load_entries_for_date,
    load_metrics_latest,
    load_recent_entries,
    load_source_status,
)
from web.unique_ip_store import get_unique_ip_stats_path, load_unique_ip_stats


app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
watcher_started = False
SOURCE_MAP = get_source_map()


def watch_log_files():
    file_positions = {}

    while True:
        today_paths = list(LOG_DIR.glob("*/*.jsonl"))

        for log_path in today_paths:
            position = file_positions.get(str(log_path), 0)

            try:
                with log_path.open("r", encoding="utf-8") as handle:
                    handle.seek(position)

                    while True:
                        line = handle.readline()
                        if not line:
                            file_positions[str(log_path)] = handle.tell()
                            break

                        file_positions[str(log_path)] = handle.tell()
                        try:
                            entry = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        socketio.emit("log", entry)
            except OSError:
                continue

        time.sleep(1)


def start_log_watcher():
    global watcher_started

    if watcher_started:
        return

    watcher_started = True
    socketio.start_background_task(watch_log_files)


def get_sorted_unique_ip_stats():
    return sorted(
        load_unique_ip_stats().values(),
        key=lambda record: record.get("last_seen", ""),
        reverse=True,
    )


def get_source_display_name(source_id):
    source = SOURCE_MAP.get(source_id)
    return source["display_name"] if source else source_id


def get_recent_error_entries(limit=100):
    entries = []
    for source_id in ("nginx_error", "php_fpm_error", "syslog", "kernel_log"):
        entries.extend(load_recent_entries(source_id, limit=30))

    entries.sort(key=lambda entry: entry.get("collected_at", ""), reverse=True)
    return entries[:limit]


def get_recent_auth_entries(limit=100):
    entries = load_recent_entries("auth_log", limit=limit)
    return list(reversed(entries))


@app.route("/")
def index():
    # Redirect root to overview (the main landing page)
    from flask import redirect
    return redirect("/overview")


@app.route("/traffic")
def traffic_view():
    initial_entries = load_recent_entries("nginx_access", limit=500)
    initial_alerts  = load_recent_alerts(limit=50)
    return render_template(
        "traffic.html",
        active_page="traffic",
        initial_entries=initial_entries,
        initial_alerts=initial_alerts,
        current_source_id="nginx_access",
    )


@app.route("/health")
def health_view():
    metrics       = load_metrics_latest()
    source_status = load_source_status()
    disk_m        = metrics.get("disk_usage", {}).get("parsed", {})
    service_m     = metrics.get("service_health", {}).get("parsed", {})
    resource_m    = metrics.get("memory_cpu", {}).get("parsed", {})
    network_m     = metrics.get("network_state", {}).get("parsed", {})
    return render_template(
        "host_health.html",
        active_page="health",
        disk_metrics=disk_m,
        service_metrics=service_m,
        resource_metrics=resource_m,
        network_metrics=network_m,
        source_status=source_status,
        disk_status=source_status.get("disk_usage", {}),
        svc_status=source_status.get("service_health", {}),
        res_status=source_status.get("memory_cpu", {}),
    )


@app.route("/security")
def security_view():
    auth_alerts = [
        a for a in load_recent_alerts(limit=200)
        if a.get("attack_type") == "brute_force"
    ]
    return render_template(
        "security.html",
        active_page="security",
        auth_entries=get_recent_auth_entries(limit=120),
        auth_alerts=auth_alerts,
        error_entries=get_recent_error_entries(limit=120),
    )


@app.route("/overview")
def overview_view():
    return render_template(
        "overview.html",
        active_page="overview",
        source_status=load_source_status(),
        metrics_latest=load_metrics_latest(),
        recent_alerts=load_recent_alerts(limit=20),
    )


@app.route("/structured")
def structured_logs():
    return render_template(
        "structured_logs.html",
        active_page="structured",
        initial_entries=load_recent_entries("nginx_access", limit=250),
        current_log_file=get_source_log_path("nginx_access").name,
        current_source_id="nginx_access",
        current_source_name=get_source_display_name("nginx_access"),
    )


@app.route("/map")
def map_view():
    return render_template(
        "map.html",
        active_page="map",
        initial_entries=load_recent_entries("nginx_access", limit=1000),
        current_log_file=get_source_log_path("nginx_access").name,
        current_source_id="nginx_access",
    )


@app.route("/disk")
def disk_view():
    metrics = load_metrics_latest().get("disk_usage", {}).get("parsed", {})
    return render_template(
        "disk.html",
        active_page="disk",
        disk_metrics=metrics,
        source_status=load_source_status().get("disk_usage", {}),
    )


@app.route("/services")
def services_view():
    metrics = load_metrics_latest().get("service_health", {}).get("parsed", {})
    return render_template(
        "services.html",
        active_page="services",
        service_metrics=metrics,
        source_status=load_source_status().get("service_health", {}),
    )


@app.route("/auth")
def auth_view():
    return render_template(
        "auth.html",
        active_page="auth",
        auth_entries=get_recent_auth_entries(limit=120),
        auth_alerts=[alert for alert in load_recent_alerts(limit=200) if alert.get("attack_type") == "brute_force"],
    )


@app.route("/errors")
def errors_view():
    return render_template(
        "errors.html",
        active_page="errors",
        error_entries=get_recent_error_entries(limit=120),
    )


@app.route("/history")
def history_view():
    sources = [source["source_id"] for source in get_sources() if source.get("history_enabled")]
    selected_source = request.args.get("source_id") or (sources[0] if sources else "")
    available_dates = list_history_dates(selected_source) if selected_source else []
    selected_date = request.args.get("date") or (available_dates[0] if available_dates else "")
    history_entries = load_entries_for_date(selected_source, selected_date)[:300] if selected_source and selected_date else []

    return render_template(
        "history.html",
        active_page="history",
        history_sources=sources,
        selected_source=selected_source,
        selected_source_name=get_source_display_name(selected_source) if selected_source else "",
        available_dates=available_dates,
        selected_date=selected_date,
        history_entries=history_entries,
        source_map=SOURCE_MAP,
    )


@app.route("/stats")
def stats_view():
    return render_template(
        "stats.html",
        active_page="stats",
        initial_stats=get_sorted_unique_ip_stats(),
        current_stats_file=get_unique_ip_stats_path().name,
    )


@app.route("/stats/export.csv")
def export_stats_csv():
    rows = get_sorted_unique_ip_stats()
    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["ip", "country", "city", "first_seen", "last_seen", "hit_count", "timestamps"])

    for record in rows:
        writer.writerow(
            [
                record.get("ip", ""),
                record.get("country", ""),
                record.get("city", ""),
                record.get("first_seen", ""),
                record.get("last_seen", ""),
                record.get("hit_count", 0),
                " | ".join(record.get("timestamps", [])),
            ]
        )

    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": 'attachment; filename="unique_ips_export.csv"'},
    )


@app.route("/stats/export.json")
def export_stats_json():
    rows = get_sorted_unique_ip_stats()
    return Response(
        json.dumps(rows, ensure_ascii=True, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": 'attachment; filename="unique_ips_export.json"'},
    )


@app.route("/stats/print")
def print_stats_view():
    return render_template(
        "stats_print.html",
        stats_rows=get_sorted_unique_ip_stats(),
        current_stats_file=get_unique_ip_stats_path().name,
    )


@app.route("/alerts")
def alerts_view():
    return render_template(
        "alerts.html",
        active_page="alerts",
        initial_alerts=load_recent_alerts(limit=300),
        current_alert_file="alerts.jsonl",
    )


@app.route("/api/overview-stats")
def api_overview_stats():
    source_status = load_source_status()
    recent_alerts = load_recent_alerts(limit=300)
    metrics = load_metrics_latest()

    alert_type_counts = {}
    for alert in recent_alerts:
        attack_type = alert.get("attack_type") or "other"
        alert_type_counts[attack_type] = alert_type_counts.get(attack_type, 0) + 1

    return jsonify({
        "source_status": source_status,
        "recent_alert_count": len(recent_alerts),
        "alert_type_counts": alert_type_counts,
        "metrics_latest": metrics,
    })


@app.route("/api/history")
def api_history():
    sources = [source["source_id"] for source in get_sources() if source.get("history_enabled")]
    selected_source = request.args.get("source_id") or (sources[0] if sources else "")
    available_dates = list_history_dates(selected_source) if selected_source else []
    selected_date = request.args.get("date") or (available_dates[0] if available_dates else "")
    entries = load_entries_for_date(selected_source, selected_date)[:300] if selected_source and selected_date else []

    return jsonify({
        "sources": sources,
        "selected_source": selected_source,
        "available_dates": available_dates,
        "selected_date": selected_date,
        "entries": entries,
    })
