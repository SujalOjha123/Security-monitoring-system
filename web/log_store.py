import json
from collections import deque
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "results" / "live_logs"
SOURCE_STATUS_PATH = LOG_DIR / "source_status.json"
METRICS_LATEST_PATH = LOG_DIR / "metrics_latest.json"


def ensure_log_root():
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def get_today_string(now=None):
    current = now or datetime.now()
    return current.strftime("%Y-%m-%d")


def get_source_dir(source_id):
    ensure_log_root()
    source_dir = LOG_DIR / source_id
    source_dir.mkdir(parents=True, exist_ok=True)
    return source_dir


def get_source_log_path(source_id, date_string=None, now=None):
    target_date = date_string or get_today_string(now=now)
    return get_source_dir(source_id) / f"{target_date}.jsonl"


def build_log_entry(raw, parsed, source, now=None, event_type=None):
    current = now or datetime.now()
    return {
        "source_id": source["source_id"],
        "source_category": source["category"],
        "collected_at": current.isoformat(timespec="seconds"),
        "received_at": current.isoformat(timespec="seconds"),
        "event_type": event_type or source.get("event_type", "event"),
        "raw": raw,
        "parsed": parsed,
    }


def append_log_entry(entry):
    source_id = entry.get("source_id", "nginx_access")
    log_path = get_source_log_path(source_id)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=True) + "\n")


def _load_jsonl(path, limit=None):
    if not path.exists():
        return []

    if limit is None:
        rows = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows

    rows = deque(maxlen=limit)
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return list(rows)


def load_recent_entries(source_id, limit, date_string=None):
    return _load_jsonl(get_source_log_path(source_id, date_string=date_string), limit=limit)


def load_entries_for_date(source_id, date_string, limit=None):
    entries = _load_jsonl(get_source_log_path(source_id, date_string=date_string), limit=limit)
    return list(reversed(entries))


def list_history_sources():
    ensure_log_root()
    sources = []
    for child in LOG_DIR.iterdir():
        if child.is_dir():
            sources.append(child.name)
    return sorted(sources)


def list_history_dates(source_id):
    source_dir = get_source_dir(source_id)
    dates = []
    for path in source_dir.glob("*.jsonl"):
        dates.append(path.stem)
    return sorted(dates, reverse=True)


def load_json_file(path, default):
    if not path.exists():
        return default

    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return default


def save_json_file(path, payload):
    ensure_log_root()
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=True, indent=2, sort_keys=True)


def load_source_status():
    return load_json_file(SOURCE_STATUS_PATH, {})


def update_source_status(source_id, state, detail=None, available=True):
    status = load_source_status()
    status[source_id] = {
        "state": state,
        "available": available,
        "detail": detail,
        "updated_at": datetime.now().isoformat(timespec="seconds"),
    }
    save_json_file(SOURCE_STATUS_PATH, status)


def load_metrics_latest():
    return load_json_file(METRICS_LATEST_PATH, {})


def update_metric_snapshot(source_id, parsed):
    snapshots = load_metrics_latest()
    snapshots[source_id] = {
        "updated_at": datetime.now().isoformat(timespec="seconds"),
        "parsed": parsed,
    }
    save_json_file(METRICS_LATEST_PATH, snapshots)
