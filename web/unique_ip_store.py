import json

from web.log_store import LOG_DIR


def get_unique_ip_stats_path():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    return LOG_DIR / "unique_ips.json"


def load_unique_ip_stats():
    stats_path = get_unique_ip_stats_path()
    if not stats_path.exists():
        return {}

    try:
        with stats_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}


def save_unique_ip_stats(stats):
    stats_path = get_unique_ip_stats_path()
    with stats_path.open("w", encoding="utf-8") as handle:
        json.dump(stats, handle, ensure_ascii=True, indent=2, sort_keys=True)


def update_unique_ip_stats(entry):
    if entry.get("source_id") != "nginx_access":
        return

    parsed = entry.get("parsed") or {}
    geo = entry.get("geo") or {}
    ip_address = parsed.get("ip")
    received_at = entry.get("received_at")

    if not ip_address or not received_at:
        return

    stats = load_unique_ip_stats()
    record = stats.get(ip_address)

    if record is None:
        record = {
            "ip": ip_address,
            "country": geo.get("country"),
            "country_code": geo.get("country_code"),
            "city": geo.get("city"),
            "first_seen": received_at,
            "last_seen": received_at,
            "hit_count": 0,
            "timestamps": [],
        }

    record["country"] = geo.get("country") or record.get("country")
    record["country_code"] = geo.get("country_code") or record.get("country_code")
    record["city"] = geo.get("city") or record.get("city")
    record["last_seen"] = received_at
    record["hit_count"] += 1
    record["timestamps"].append(received_at)

    stats[ip_address] = record
    save_unique_ip_stats(stats)
