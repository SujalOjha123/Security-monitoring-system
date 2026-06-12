import json
from collections import deque

from web.log_store import LOG_DIR


def get_alert_log_path():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    return LOG_DIR / "alerts.jsonl"


def append_alerts(alerts):
    if not alerts:
        return

    alert_path = get_alert_log_path()
    with alert_path.open("a", encoding="utf-8") as handle:
        for alert in alerts:
            handle.write(json.dumps(alert, ensure_ascii=True) + "\n")


def load_recent_alerts(limit):
    alert_path = get_alert_log_path()
    if not alert_path.exists():
        return []

    rows = deque(maxlen=limit)
    with alert_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return list(rows)[::-1]
