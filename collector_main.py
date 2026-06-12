from collector.fetch_logs import collect_sources
from collector.source_registry import get_enabled_sources
from web.alert_store import append_alerts
from web.detector import detect_alerts
from web.geoip import geolocate_ip, load_geo_cache
from web.log_store import append_log_entry, build_log_entry, update_metric_snapshot, update_source_status
from web.source_parsers import parse_source_event
from web.unique_ip_store import update_unique_ip_stats

GEO_CACHE = load_geo_cache()
SOURCES = get_enabled_sources()


def persist_source_event(source, raw):
    parsed = parse_source_event(source["source_id"], raw)
    geo = None

    if source["source_id"] == "nginx_access" and parsed.get("matched"):
        geo = geolocate_ip(parsed.get("ip"), cache=GEO_CACHE)

    entry = build_log_entry(raw, parsed, source)
    entry["geo"] = geo
    entry["alerts"] = detect_alerts(entry)
    append_log_entry(entry)
    update_metric_snapshot(source["source_id"], parsed)
    update_unique_ip_stats(entry)
    append_alerts(entry["alerts"])


if __name__ == "__main__":
    collect_sources(SOURCES, persist_source_event, update_source_status)
