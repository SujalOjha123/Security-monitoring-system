import os


DEFAULT_ENABLED_SOURCES = (
    "nginx_access",
    "nginx_error",
    "disk_usage",
    "service_health",
)


def _env_or_default(name, default=None):
    return os.getenv(name, default)


def get_sources():
    return [
        {
            "source_id": "nginx_access",
            "source_type": "log_tail",
            "display_name": "Nginx Access",
            "category": "web",
            "event_type": "http_access",
            "history_enabled": True,
            "parser": "nginx_access",
            "path_candidates": [
                _env_or_default("NGINX_ACCESS_LOG_PATH"),
                _env_or_default("LOG_PATH"),
                "/var/log/nginx/access.log",
            ],
        },
        {
            "source_id": "nginx_error",
            "source_type": "log_tail",
            "display_name": "Nginx Error",
            "category": "web",
            "event_type": "http_error",
            "history_enabled": True,
            "parser": "nginx_error",
            "path_candidates": [
                _env_or_default("NGINX_ERROR_LOG_PATH"),
                "/var/log/nginx/error.log",
            ],
        },
        {
            "source_id": "auth_log",
            "source_type": "log_tail",
            "display_name": "Auth Log",
            "category": "security",
            "event_type": "auth_event",
            "history_enabled": True,
            "parser": "auth_log",
            "path_candidates": [
                _env_or_default("AUTH_LOG_PATH"),
                "/var/log/auth.log",
                "/var/log/secure",
            ],
        },
        {
            "source_id": "syslog",
            "source_type": "log_tail",
            "display_name": "Syslog",
            "category": "system",
            "event_type": "system_log",
            "history_enabled": True,
            "parser": "syslog",
            "path_candidates": [
                _env_or_default("SYSLOG_PATH"),
                "/var/log/syslog",
                "/var/log/messages",
            ],
        },
        {
            "source_id": "php_fpm_error",
            "source_type": "log_tail",
            "display_name": "PHP-FPM Error",
            "category": "web",
            "event_type": "php_error",
            "history_enabled": True,
            "parser": "php_fpm_error",
            "path_candidates": [
                _env_or_default("PHP_FPM_ERROR_LOG_PATH"),
                "/var/log/php8.2-fpm.log",
                "/var/log/php8.1-fpm.log",
                "/var/log/php7.4-fpm.log",
            ],
        },
        {
            "source_id": "cron_log",
            "source_type": "log_tail",
            "display_name": "Cron Log",
            "category": "system",
            "event_type": "cron_event",
            "history_enabled": True,
            "parser": "syslog",
            "path_candidates": [
                _env_or_default("CRON_LOG_PATH"),
                "/var/log/cron",
                "/var/log/cron.log",
            ],
        },
        {
            "source_id": "kernel_log",
            "source_type": "log_tail",
            "display_name": "Kernel Log",
            "category": "system",
            "event_type": "kernel_event",
            "history_enabled": True,
            "parser": "syslog",
            "path_candidates": [
                _env_or_default("KERNEL_LOG_PATH"),
                "/var/log/kern.log",
                "/var/log/messages",
            ],
        },
        {
            "source_id": "disk_usage",
            "source_type": "command_snapshot",
            "display_name": "Disk Usage",
            "category": "storage",
            "event_type": "disk_snapshot",
            "history_enabled": True,
            "parser": "disk_usage",
            "interval_seconds": 60,
            "command": 'sh -lc \'printf "__DFH__\\n"; df -hP 2>/dev/null; printf "\\n__DFI__\\n"; df -iP 2>/dev/null\'',
        },
        {
            "source_id": "memory_cpu",
            "source_type": "command_snapshot",
            "display_name": "Memory and CPU",
            "category": "system",
            "event_type": "resource_snapshot",
            "history_enabled": True,
            "parser": "memory_cpu",
            "interval_seconds": 60,
            "command": 'sh -lc \'printf "__UPTIME__\\n"; uptime 2>/dev/null; printf "\\n__FREE__\\n"; free -m 2>/dev/null\'',
        },
        {
            "source_id": "service_health",
            "source_type": "command_snapshot",
            "display_name": "Service Health",
            "category": "system",
            "event_type": "service_snapshot",
            "history_enabled": True,
            "parser": "service_health",
            "interval_seconds": 60,
            "command": 'sh -lc \'if command -v systemctl >/dev/null 2>&1; then systemctl --no-pager --no-legend --type=service --state=running,failed 2>/dev/null; else service --status-all 2>/dev/null; fi\'',
        },
        {
            "source_id": "network_state",
            "source_type": "command_snapshot",
            "display_name": "Network State",
            "category": "network",
            "event_type": "network_snapshot",
            "history_enabled": True,
            "parser": "network_state",
            "interval_seconds": 120,
            "command": 'sh -lc \'if command -v ss >/dev/null 2>&1; then ss -tunap 2>/dev/null; elif command -v netstat >/dev/null 2>&1; then netstat -tunap 2>/dev/null; fi\'',
        },
    ]


def get_source_map():
    return {source["source_id"]: source for source in get_sources()}


def get_enabled_sources():
    sources = get_sources()
    enabled = os.getenv("ENABLED_SOURCES", "")

    if not enabled.strip():
        enabled_ids = set(DEFAULT_ENABLED_SOURCES)
    else:
        enabled_ids = {item.strip() for item in enabled.split(",") if item.strip()}

    if "*" in enabled_ids:
        return sources

    return [source for source in sources if source["source_id"] in enabled_ids]
