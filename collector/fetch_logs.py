import os
import shlex
import time
import logging
from threading import Thread

import paramiko
from dotenv import load_dotenv


load_dotenv("config/setup.env")
logging.getLogger("paramiko").setLevel(logging.CRITICAL)


def _connect_client():
    host = os.getenv("SERVER_HOST")
    user = os.getenv("SERVER_USER")
    pwd = os.getenv("SERVER_PASSWORD")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        username=user,
        password=pwd,
        timeout=10,
        banner_timeout=15,
        auth_timeout=15,
    )
    return client


def _probe_path(client, path):
    quoted = shlex.quote(path)
    _, stdout, _ = client.exec_command(f"test -r {quoted} && echo OK")
    return stdout.read().decode("utf-8").strip() == "OK"


def _resolve_readable_path(client, candidates):
    for path in candidates:
        if not path:
            continue
        try:
            if _probe_path(client, path):
                return path
        except Exception:
            continue
    return None


def _collect_tail_source(source, callback, status_callback, startup_delay=0):
    retry_delay = 5

    if startup_delay:
        time.sleep(startup_delay)

    while True:
        client = None
        try:
            client = _connect_client()
            resolved_path = _resolve_readable_path(client, source.get("path_candidates", []))
            if not resolved_path:
                status_callback(source["source_id"], "unavailable", "No readable log path found", available=False)
                time.sleep(retry_delay)
                continue

            status_callback(source["source_id"], "streaming", f"Tailing {resolved_path}", available=True)
            _, stdout, _ = client.exec_command(f"tail -F {shlex.quote(resolved_path)}")

            for line in stdout:
                line = line.strip()
                if line:
                    callback(source, line)
                    status_callback(source["source_id"], "streaming", f"Tailing {resolved_path}", available=True)
            retry_delay = 5
        except Exception as exc:
            status_callback(source["source_id"], "error", str(exc), available=False)
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 60)
        finally:
            if client is not None:
                client.close()


def _collect_snapshot_sources(sources, callback, status_callback, startup_delay=0):
    retry_delay = 5

    if startup_delay:
        time.sleep(startup_delay)

    while True:
        client = None
        try:
            client = _connect_client()
            cycle_sleep = min(source.get("interval_seconds", 60) for source in sources)

            for source in sources:
                _, stdout, stderr = client.exec_command(source["command"])
                output = stdout.read().decode("utf-8", errors="replace").strip()
                error_text = stderr.read().decode("utf-8", errors="replace").strip()

                if error_text and not output:
                    status_callback(source["source_id"], "unavailable", error_text, available=False)
                elif output:
                    callback(source, output)
                    status_callback(source["source_id"], "healthy", "Snapshot updated", available=True)
                else:
                    status_callback(source["source_id"], "unavailable", "No readable output", available=False)

            retry_delay = 5
        except Exception as exc:
            for source in sources:
                status_callback(source["source_id"], "error", str(exc), available=False)
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 60)
            continue
        finally:
            if client is not None:
                client.close()

        time.sleep(cycle_sleep)


def collect_sources(sources, callback, status_callback):
    threads = []
    tail_sources = [source for source in sources if source["source_type"] == "log_tail"]
    snapshot_sources = [source for source in sources if source["source_type"] == "command_snapshot"]

    for index, source in enumerate(tail_sources):
        thread = Thread(
            target=_collect_tail_source,
            args=(source, callback, status_callback, index * 3),
            daemon=True,
        )
        thread.start()
        threads.append(thread)

    if snapshot_sources:
        snapshot_thread = Thread(
            target=_collect_snapshot_sources,
            args=(snapshot_sources, callback, status_callback, max(len(tail_sources), 1) * 3),
            daemon=True,
        )
        snapshot_thread.start()
        threads.append(snapshot_thread)

    for thread in threads:
        thread.join()
