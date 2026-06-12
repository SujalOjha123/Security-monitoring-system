import re

from web.log_parser import parse_log_line


SYSLOG_PATTERN = re.compile(
    r'(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>[A-Za-z0-9_\-/.@]+)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<message>.*)'
)

NGINX_ERROR_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>[^\]]+)\]\s+'
    r'(?P<message>.*)'
)

AUTH_IP_PATTERN = re.compile(r'from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)')
AUTH_USER_PATTERN = re.compile(r'for\s+(invalid user\s+)?(?P<user>[A-Za-z0-9._@-]+)')
MEMORY_TOTAL_PATTERN = re.compile(r'^Mem:\s+(?P<total>\d+)\s+(?P<used>\d+)\s+(?P<free>\d+)', re.MULTILINE)
LOAD_PATTERN = re.compile(r'load average:\s*(?P<one>[0-9.]+),\s*(?P<five>[0-9.]+),\s*(?P<fifteen>[0-9.]+)')


def parse_source_event(source_id, raw):
    parser = SOURCE_PARSERS.get(source_id, parse_passthrough)
    return parser(raw)


def parse_passthrough(raw):
    return {"matched": False, "raw": raw}


def parse_nginx_access(raw):
    return parse_log_line(raw)


def parse_nginx_error(raw):
    match = NGINX_ERROR_PATTERN.match(raw)
    if not match:
        return {"matched": False, "raw": raw}

    parsed = match.groupdict()
    parsed["matched"] = True
    parsed["raw"] = raw
    return parsed


def parse_syslog_like(raw):
    match = SYSLOG_PATTERN.match(raw)
    if not match:
        return {"matched": False, "raw": raw}

    parsed = match.groupdict()
    parsed["matched"] = True
    parsed["raw"] = raw
    return parsed


def parse_auth_log(raw):
    parsed = parse_syslog_like(raw)
    message = parsed.get("message", "")
    lowered = message.lower()

    ip_match = AUTH_IP_PATTERN.search(message)
    user_match = AUTH_USER_PATTERN.search(message)

    if "failed password" in lowered:
        parsed["action"] = "login"
        parsed["result"] = "failed"
    elif "accepted password" in lowered or "accepted publickey" in lowered:
        parsed["action"] = "login"
        parsed["result"] = "accepted"
    elif "invalid user" in lowered:
        parsed["action"] = "login"
        parsed["result"] = "invalid_user"

    if ip_match:
        parsed["ip"] = ip_match.group("ip")
    if user_match:
        parsed["username"] = user_match.group("user")
    return parsed


def parse_disk_usage(raw):
    sections = {"dfh": [], "dfi": []}
    current = None

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if line == "__DFH__":
            current = "dfh"
            continue
        if line == "__DFI__":
            current = "dfi"
            continue
        if current:
            sections[current].append(line)

    filesystems = []
    inode_map = {}

    for line in sections["dfi"][1:]:
        parts = line.split()
        if len(parts) >= 6:
            inode_map[parts[5]] = {
                "inode_total": parts[1],
                "inode_used": parts[2],
                "inode_available": parts[3],
                "inode_used_pct": parts[4],
            }

    for line in sections["dfh"][1:]:
        parts = line.split()
        if len(parts) >= 6:
            mount_point = parts[5]
            filesystem = {
                "filesystem": parts[0],
                "size": parts[1],
                "used": parts[2],
                "available": parts[3],
                "used_pct": parts[4],
                "mount_point": mount_point,
            }
            filesystem.update(inode_map.get(mount_point, {}))
            filesystems.append(filesystem)

    return {
        "matched": True,
        "raw": raw,
        "filesystems": filesystems,
    }


def parse_memory_cpu(raw):
    load_match = LOAD_PATTERN.search(raw)
    memory_match = MEMORY_TOTAL_PATTERN.search(raw)

    parsed = {
        "matched": True,
        "raw": raw,
    }

    if load_match:
        parsed["load_1m"] = load_match.group("one")
        parsed["load_5m"] = load_match.group("five")
        parsed["load_15m"] = load_match.group("fifteen")

    if memory_match:
        parsed["memory_total_mb"] = memory_match.group("total")
        parsed["memory_used_mb"] = memory_match.group("used")
        parsed["memory_free_mb"] = memory_match.group("free")

    return parsed


def parse_service_health(raw):
    services = []
    failed_services = []

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 4 and parts[0].endswith(".service"):
            service = {
                "service_name": parts[0],
                "load": parts[1],
                "state": parts[2],
                "substate": parts[3],
            }
            services.append(service)
            if parts[2] == "failed":
                failed_services.append(parts[0])

    return {
        "matched": True,
        "raw": raw,
        "services": services,
        "failed_services": failed_services,
        "failed_count": len(failed_services),
    }


def parse_network_state(raw):
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    return {
        "matched": True,
        "raw": raw,
        "connection_count": max(0, len(lines) - 1),
        "sample": lines[:20],
    }


SOURCE_PARSERS = {
    "nginx_access": parse_nginx_access,
    "nginx_error": parse_nginx_error,
    "auth_log": parse_auth_log,
    "syslog": parse_syslog_like,
    "php_fpm_error": parse_syslog_like,
    "cron_log": parse_syslog_like,
    "kernel_log": parse_syslog_like,
    "disk_usage": parse_disk_usage,
    "memory_cpu": parse_memory_cpu,
    "service_health": parse_service_health,
    "network_state": parse_network_state,
}
