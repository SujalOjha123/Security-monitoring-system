from collections import defaultdict, deque
from urllib.parse import unquote, urlsplit


SUSPICIOUS_UPLOAD_EXTENSIONS = (
    ".php",
    ".phtml",
    ".phar",
    ".php3",
    ".php4",
    ".php5",
    ".php7",
    ".php8",
    ".cgi",
    ".pl",
    ".jsp",
    ".asp",
    ".aspx",
    ".sh",
)

UPLOAD_PATH_MARKERS = (
    "/uploads/",
    "/upload/",
)

TRAVERSAL_PATTERNS = (
    "../",
    "..\\",
    "%2e%2e%2f",
    "%2e%2e/",
    "%252e",
    "/etc/passwd",
    "win.ini",
    "boot.ini",
)

SQLI_PATTERNS = (
    "union select",
    "' or 1=1",
    "\" or 1=1",
    "information_schema",
    "sleep(",
    "benchmark(",
    "select%20",
    "select+",
    "load_file(",
)

XSS_PATTERNS = (
    "<script",
    "%3cscript",
    "javascript:",
    "onerror=",
    "onload=",
    "alert(",
)

WEBSHELL_PATTERNS = (
    "cmd=",
    "exec=",
    "system=",
    "shell=",
    "passthru",
    "base64",
    "eval(",
    "wget ",
    "curl ",
    "whoami",
    "uname -a",
    "powershell",
)

SCANNER_PATH_MARKERS = (
    "/phpmyadmin",
    "/.env",
    "/vendor/",
    "/wp-admin",
    "/wp-login",
    "/cgi-bin/",
    "/server-status",
    "/boaform",
    "/manager/html",
)

SUSPICIOUS_USER_AGENTS = (
    "sqlmap",
    "curl",
    "python-requests",
    "go-http-client",
    "nikto",
    "masscan",
    "nmap",
    "zgrab",
)

LOGIN_PATH_MARKERS = (
    "/login",
    "/signin",
    "/admin",
    "/index.php/index/login",
)

SUSPICIOUS_REPEAT_RULES = {
    "suspicious_php_upload_path",
    "path_traversal_probe",
    "sqli_probe",
    "webshell_command_probe",
    "scanner_enumeration_probe",
}

REPEAT_THRESHOLD = 5
REPEAT_WINDOW = 12
BRUTE_FORCE_THRESHOLD = 8
BRUTE_FORCE_WINDOW = 12
repeat_tracker = defaultdict(lambda: deque(maxlen=REPEAT_WINDOW))
repeat_alert_tracker = {}
repeat_counts = defaultdict(int)
login_tracker = defaultdict(lambda: deque(maxlen=BRUTE_FORCE_WINDOW))
login_alert_tracker = {}
auth_log_tracker = defaultdict(lambda: deque(maxlen=BRUTE_FORCE_WINDOW))
auth_log_alert_tracker = {}
service_failure_seen = set()
error_spike_tracker = defaultdict(lambda: deque(maxlen=10))
error_spike_alert_tracker = {}
error_spike_counts = defaultdict(int)


def _normalized_target(path):
    if not path:
        return ""

    decoded = unquote(path)
    split = urlsplit(decoded)
    combined = split.path
    if split.query:
        combined += "?" + split.query
    return combined.lower()


def _normalized_path(path):
    if not path:
        return ""

    decoded = unquote(path)
    return urlsplit(decoded).path.lower()


def _contains_any(text, patterns):
    return any(pattern in text for pattern in patterns)


def _contains_upload_marker(path):
    return any(marker in path for marker in UPLOAD_PATH_MARKERS)


def _has_suspicious_extension(path):
    return any(path.endswith(ext) for ext in SUSPICIOUS_UPLOAD_EXTENSIONS)


def _build_alert(rule_id, attack_type, severity, title, description, entry):
    parsed = entry.get("parsed") or {}
    geo = entry.get("geo") or {}
    return {
        "rule_id": rule_id,
        "attack_type": attack_type,
        "severity": severity,
        "title": title,
        "description": description,
        "ip": parsed.get("ip"),
        "country": geo.get("country"),
        "timestamp": entry.get("received_at"),
        "method": parsed.get("method"),
        "path": parsed.get("path"),
        "status": parsed.get("status"),
        "user_agent": parsed.get("user_agent"),
        "raw": entry.get("raw"),
    }


def _track_login_bruteforce(entry):
    parsed = entry.get("parsed") or {}
    path = (parsed.get("path") or "").lower()
    ip_address = parsed.get("ip")
    status = str(parsed.get("status") or "")

    if not ip_address or not any(marker in path for marker in LOGIN_PATH_MARKERS):
        return []

    tracker = login_tracker[ip_address]
    tracker.append(status)

    if len(tracker) < BRUTE_FORCE_THRESHOLD:
        return []

    suspicious_statuses = {"200", "401", "403", "404"}
    recent_statuses = list(tracker)[-BRUTE_FORCE_THRESHOLD:]
    if not all(value in suspicious_statuses for value in recent_statuses):
        return []

    current_count = len(tracker)
    previous_count = login_alert_tracker.get(ip_address, 0)
    if current_count <= previous_count:
        return []

    login_alert_tracker[ip_address] = current_count
    return [
        _build_alert(
            "login_bruteforce_probe",
            "brute_force",
            "high",
            "Repeated login probing pattern",
            "The same IP has repeatedly requested login-related endpoints in a short sequence, which is consistent with brute-force probing or credential stuffing attempts.",
            entry,
        )
    ]


def _track_auth_log_bruteforce(entry):
    if entry.get("source_id") != "auth_log":
        return []

    parsed = entry.get("parsed") or {}
    ip_address = parsed.get("ip")
    result = (parsed.get("result") or "").lower()

    if not ip_address or result not in {"failed", "invalid_user"}:
        return []

    tracker = auth_log_tracker[ip_address]
    tracker.append(result)

    if len(tracker) < BRUTE_FORCE_THRESHOLD:
        return []

    previous_count = auth_log_alert_tracker.get(ip_address, 0)
    current_count = len(tracker)
    if current_count <= previous_count:
        return []

    auth_log_alert_tracker[ip_address] = current_count
    return [
        _build_alert(
            "auth_bruteforce",
            "brute_force",
            "critical",
            "Repeated SSH/auth failure pattern",
            "The same IP has generated multiple failed authentication events in the host auth log, which is consistent with brute-force probing.",
            entry,
        )
    ]


def _track_service_failures(entry):
    if entry.get("source_id") != "service_health":
        return []

    parsed = entry.get("parsed") or {}
    alerts = []

    for service_name in parsed.get("failed_services", []):
        key = (entry.get("source_id"), service_name)
        if key in service_failure_seen:
            continue

        service_failure_seen.add(key)
        alerts.append(
            _build_alert(
                "new_service_failure",
                "availability",
                "high",
                "Service entered failed state",
                f"The service {service_name} is currently in a failed state on the host.",
                entry,
            )
        )

    return alerts


def _track_disk_pressure(entry):
    if entry.get("source_id") != "disk_usage":
        return []

    parsed = entry.get("parsed") or {}
    alerts = []

    for fs in parsed.get("filesystems", []):
        used_pct = str(fs.get("used_pct", "")).rstrip("%")
        inode_pct = str(fs.get("inode_used_pct", "")).rstrip("%")

        if used_pct.isdigit() and int(used_pct) >= 85:
            alerts.append(
                _build_alert(
                    "disk_pressure",
                    "availability",
                    "high",
                    "Disk usage threshold exceeded",
                    f"The filesystem mounted on {fs.get('mount_point')} is at {fs.get('used_pct')} usage.",
                    entry,
                )
            )

        if inode_pct.isdigit() and int(inode_pct) >= 80:
            alerts.append(
                _build_alert(
                    "inode_pressure",
                    "availability",
                    "high",
                    "Inode usage threshold exceeded",
                    f"The filesystem mounted on {fs.get('mount_point')} is at {fs.get('inode_used_pct')} inode usage.",
                    entry,
                )
            )

    return alerts


def _track_error_spike(entry):
    source_id = entry.get("source_id")
    parsed = entry.get("parsed") or {}
    message = (parsed.get("message") or entry.get("raw") or "").lower()
    level = (parsed.get("level") or "").lower()

    if source_id not in {"nginx_error", "php_fpm_error", "syslog", "kernel_log"}:
        return []

    is_error = any(token in message for token in ("error", "failed", "panic", "critical")) or level in {"error", "crit", "alert", "emerg"}
    if not is_error:
        return []

    tracker = error_spike_tracker[source_id]
    tracker.append(entry.get("collected_at"))
    error_spike_counts[source_id] += 1
    if len(tracker) < 5:
        return []

    previous_count = error_spike_alert_tracker.get(source_id, 0)
    current_count = error_spike_counts[source_id]
    if current_count <= previous_count:
        return []

    error_spike_alert_tracker[source_id] = current_count
    return [
        _build_alert(
            "error_spike",
            "availability",
            "medium",
            "Error spike observed",
            f"The source {source_id} has produced a burst of error-style entries in recent events.",
            entry,
        )
    ]


def _track_repeated_hits(alerts, entry):
    parsed = entry.get("parsed") or {}
    ip_address = parsed.get("ip")
    path = parsed.get("path") or ""

    if not ip_address or not path:
        return []

    suspicious_rules = [alert["rule_id"] for alert in alerts if alert["rule_id"] in SUSPICIOUS_REPEAT_RULES]
    if not suspicious_rules:
        return []

    repeat_key = (ip_address, path.lower())
    tracker = repeat_tracker[repeat_key]

    for rule_id in suspicious_rules:
        tracker.append(rule_id)
        repeat_counts[repeat_key] += 1

    if len(tracker) < REPEAT_THRESHOLD:
        return []

    recent_rules = list(tracker)[-REPEAT_THRESHOLD:]
    if len(set(recent_rules)) == 1:
        previous_count = repeat_alert_tracker.get(repeat_key, 0)
        current_count = repeat_counts[repeat_key]

        if current_count > previous_count:
            repeat_alert_tracker[repeat_key] = current_count
            return [
                _build_alert(
                    "repeated_suspicious_path_access",
                    "beaconing",
                    "critical",
                    "Repeated suspicious access pattern",
                    "The same IP has repeatedly hit the same suspicious path multiple times in a short sequence, which is consistent with probing or web-shell beaconing.",
                    entry,
                )
            ]

    return []


def detect_alerts(entry):
    parsed = entry.get("parsed") or {}
    normalized_path = _normalized_path(parsed.get("path") or "")
    normalized_target = _normalized_target(parsed.get("path") or "")
    user_agent = (parsed.get("user_agent") or "").lower()
    alerts = []

    if _contains_upload_marker(normalized_path) and _has_suspicious_extension(normalized_path):
        alerts.append(
            _build_alert(
                "suspicious_php_upload_path",
                "upload_abuse",
                "critical",
                "Executable file detected in upload area",
                "A server-executable file was requested from a user upload directory that should only contain documents or images.",
                entry,
            )
        )

    if _contains_any(normalized_target, TRAVERSAL_PATTERNS):
        alerts.append(
            _build_alert(
                "path_traversal_probe",
                "traversal",
                "high",
                "Path traversal probe detected",
                "The request contains traversal-style path sequences or file targets commonly used to read sensitive system files.",
                entry,
            )
        )

    if _contains_any(normalized_target, SQLI_PATTERNS):
        alerts.append(
            _build_alert(
                "sqli_probe",
                "sqli",
                "high",
                "Possible SQL injection probe",
                "The request contains patterns commonly associated with SQL injection testing or exploitation.",
                entry,
            )
        )

    if _contains_any(normalized_target, XSS_PATTERNS):
        alerts.append(
            _build_alert(
                "xss_probe",
                "xss",
                "medium",
                "Possible XSS probe",
                "The request includes script-style payload markers commonly used in reflected or stored XSS testing.",
                entry,
            )
        )

    if _contains_any(normalized_target, WEBSHELL_PATTERNS):
        alerts.append(
            _build_alert(
                "webshell_command_probe",
                "webshell",
                "critical",
                "Possible web-shell command probe",
                "The request path or query contains command-execution style indicators commonly used with web shells.",
                entry,
            )
        )

    if _contains_any(normalized_path, SCANNER_PATH_MARKERS):
        alerts.append(
            _build_alert(
                "scanner_enumeration_probe",
                "scanner",
                "medium",
                "Scanner or enumeration path probe",
                "The request targets a path commonly used by automated scanners, framework probes, or administrative panels.",
                entry,
            )
        )

    if user_agent and _contains_any(user_agent, SUSPICIOUS_USER_AGENTS):
        alerts.append(
            _build_alert(
                "suspicious_user_agent",
                "tooling",
                "medium",
                "Suspicious user agent detected",
                "The user agent string matches common offensive tooling or scripted request libraries.",
                entry,
            )
        )

    alerts.extend(_track_login_bruteforce(entry))
    alerts.extend(_track_auth_log_bruteforce(entry))
    alerts.extend(_track_service_failures(entry))
    alerts.extend(_track_disk_pressure(entry))
    alerts.extend(_track_error_spike(entry))
    alerts.extend(_track_repeated_hits(alerts, entry))
    return alerts
