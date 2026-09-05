import json
import os
import queue
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

CONFIG_FILE = Path(__file__).with_name("config.json")
QUEUE_LIMIT = 5000
SEND_TIMEOUT = 8
MODIFY_DEBOUNCE_SECONDS = 0.20
HEARTBEAT_SECONDS = 15
CONTROL_POLL_SECONDS = 2

# These are transient implementation files. Ignoring them keeps the live
# activity page focused on meaningful user/application file activity instead
# of SQLite journals, Python bytecode, and editor lock files.
IGNORED_SUFFIXES = {".db-journal", ".db-wal", ".db-shm", ".pyc"}
IGNORED_BASENAMES = {"desktop.ini", "thumbs.db"}
IGNORED_PATH_PARTS = {"\\__pycache__\\", "\\.git\\objects\\"}


def should_ignore(path):
    normalized = os.path.abspath(path).lower()
    name = os.path.basename(normalized)
    if name in IGNORED_BASENAMES:
        return True
    if any(normalized.endswith(suffix) for suffix in IGNORED_SUFFIXES):
        return True
    if name.startswith("~$"):
        return True
    if any(part in normalized for part in IGNORED_PATH_PARTS):
        return True
    return False


def load_config():
    if not CONFIG_FILE.exists():
        CONFIG_FILE.write_text(
            json.dumps(
                {
                    "server_url": "http://127.0.0.1:5000",
                    "device_token": "",
                    "watch_folder": "",
                    "watch_all_drives": True,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Unable to read config.json: {exc}")


def now():
    return datetime.now(timezone.utc).isoformat()


def windows_drive_roots():
    """Return available Windows drive roots such as C:\\ and D:\\.

    Only roots that currently exist and can be listed are returned. This avoids
    crashing when Windows exposes a disconnected or protected drive letter.
    """
    roots = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        root = f"{letter}:\\"
        if not os.path.isdir(root):
            continue
        try:
            os.listdir(root)
            roots.append(root)
        except (PermissionError, OSError):
            continue
    return roots


class Handler(FileSystemEventHandler):
    def __init__(self, event_queue):
        self.q = event_queue
        self.last_modified = {}
        self.lock = threading.Lock()

    def _put(self, kind, path, is_dir=False, old_path=""):
        if is_dir:
            return

        path = os.path.abspath(path)

        if should_ignore(path):
            return

        # Modified events can arrive in bursts for a single save operation.
        if kind == "modified":
            now_mono = time.monotonic()
            with self.lock:
                previous = self.last_modified.get(path, 0.0)
                if now_mono - previous < MODIFY_DEBOUNCE_SECONDS:
                    return
                self.last_modified[path] = now_mono

        payload = {
            "event": kind,
            "path": path,
            "name": os.path.basename(path),
            "extension": Path(path).suffix.lower() or "none",
            "timestamp": now(),
        }

        if old_path:
            payload["old_path"] = os.path.abspath(old_path)

        try:
            self.q.put_nowait(payload)
        except queue.Full:
            # Drop only when the local queue is saturated; never store files.
            print("[QUEUE] Event queue full; dropping newest event.")

    def on_created(self, event):
        self._put("created", event.src_path, event.is_directory)

    def on_modified(self, event):
        self._put("modified", event.src_path, event.is_directory)

    def on_deleted(self, event):
        self._put("deleted", event.src_path, event.is_directory)

    def on_moved(self, event):
        self._put(
            "renamed",
            event.dest_path,
            event.is_directory,
            old_path=event.src_path,
        )


def send(config, payload):
    base = str(config.get("server_url", "")).rstrip("/")
    if not base:
        print("[CONFIG] server_url is empty")
        return False

    url = base + "/api/agent/events"
    headers = {}
    token = str(config.get("device_token", "")).strip()
    if token:
        headers["Authorization"] = "Bearer " + token

    payload["device_name"] = os.environ.get("COMPUTERNAME", "Unknown-PC")
    payload["agent_version"] = "2.0.0"

    try:
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=SEND_TIMEOUT,
        )
        if response.ok:
            print(
                f"[SENT] {payload['event'].upper():8} "
                f"{payload['path']}"
            )
            return True

        print(
            f"[SERVER {response.status_code}] "
            f"{response.text[:200]}"
        )
        return False

    except requests.RequestException as exc:
        print(f"[OFFLINE] {exc}")
        return False


def send_heartbeat(config):
    base = str(config.get("server_url", "")).rstrip("/")
    token = str(config.get("device_token", "")).strip()
    if not base or not token:
        return

    try:
        response = requests.post(
            base + "/api/agent/heartbeat",
            headers={"Authorization": "Bearer " + token},
            timeout=SEND_TIMEOUT,
        )
        if response.ok:
            print("[HEARTBEAT] Connected")
        else:
            print(f"[HEARTBEAT {response.status_code}] {response.text[:120]}")
    except requests.RequestException:
        print("[HEARTBEAT] Backend unavailable")


def get_monitoring_state(config):
    base = str(config.get("server_url", "")).rstrip("/")
    token = str(config.get("device_token", "")).strip()
    if not base or not token:
        return None

    try:
        response = requests.get(
            base + "/api/agent/control",
            headers={"Authorization": "Bearer " + token},
            timeout=SEND_TIMEOUT,
        )
        if response.ok:
            return bool(response.json().get("monitoring_enabled", True))
    except (requests.RequestException, ValueError):
        pass
    return None


def control_worker(config, stop_event, observer_state):
    last_state = None
    while not stop_event.is_set():
        state = get_monitoring_state(config)
        if state is not None and state != last_state:
            observer_state["desired"] = state
            if not state:
                cleared = clear_event_queue(observer_state["event_queue"])
                if cleared:
                    print(f"[CONTROL] Cleared {cleared} queued event(s) on pause.")
            print("[CONTROL] " + ("Monitoring ENABLED" if state else "Monitoring PAUSED"))
            last_state = state
        stop_event.wait(CONTROL_POLL_SECONDS)


def heartbeat_worker(config, stop_event):
    while not stop_event.wait(HEARTBEAT_SECONDS):
        send_heartbeat(config)


def clear_event_queue(event_queue):
    cleared = 0
    while True:
        try:
            event_queue.get_nowait()
        except queue.Empty:
            break
        else:
            event_queue.task_done()
            cleared += 1
    return cleared


def sender_worker(config, event_queue, stop_event, observer_state):
    while not stop_event.is_set():
        try:
            payload = event_queue.get(timeout=0.5)
        except queue.Empty:
            continue

        try:
            if not observer_state.get("desired", False):
                continue
            send(config, payload)
        finally:
            event_queue.task_done()


def build_observers(roots, event_queue):
    observers = []
    handler = Handler(event_queue)

    for root in roots:
        try:
            observer = Observer()
            observer.schedule(handler, root, recursive=True)
            observer.start()
            observers.append(observer)
            print(f"[WATCHING] {root}")
        except (PermissionError, OSError) as exc:
            print(f"[SKIP] {root}: {exc}")

    return observers


def stop_observers(observers):
    for observer in observers:
        observer.stop()
    for observer in observers:
        observer.join(timeout=3)


def main():
    config = load_config()

    if not str(config.get("device_token", "")).strip():
        raise SystemExit(
            "Missing device_token in config.json. "
            "Pair the computer from the DAVE dashboard first."
        )

    server_url = str(config.get("server_url", "")).rstrip("/")
    print("\nDAVE Monitoring Agent 2.0")
    print("-------------------------")
    print(f"Backend: {server_url}")

    event_queue = queue.Queue(maxsize=QUEUE_LIMIT)
    stop_event = threading.Event()

    # Default: monitor every currently available Windows drive.
    # If watch_folder contains a valid folder, monitor that folder instead.
    configured_folder = str(config.get("watch_folder", "")).strip().strip('"')
    watch_all = bool(config.get("watch_all_drives", True))

    if configured_folder and os.path.isdir(configured_folder):
        roots = [os.path.abspath(configured_folder)]
    elif watch_all:
        roots = windows_drive_roots()
    else:
        roots = []

    if not roots:
        raise SystemExit(
            "No accessible filesystem root was found. "
            "Check permissions or set watch_folder in config.json."
        )

    observer_state = {"desired": True, "observers": [], "event_queue": event_queue}

    initial_state = get_monitoring_state(config)
    if initial_state is not None:
        observer_state["desired"] = initial_state

    if observer_state["desired"]:
        observer_state["observers"] = build_observers(roots, event_queue)
        if not observer_state["observers"]:
            raise SystemExit("The agent could not start a filesystem observer.")
    else:
        print("[CONTROL] Monitoring is currently PAUSED")

    sender = threading.Thread(
        target=sender_worker,
        args=(config, event_queue, stop_event, observer_state),
        daemon=True,
        name="dave-event-sender",
    )
    sender.start()

    heartbeat = threading.Thread(
        target=heartbeat_worker,
        args=(config, stop_event),
        daemon=True,
        name="dave-heartbeat",
    )
    heartbeat.start()

    controller = threading.Thread(
        target=control_worker,
        args=(config, stop_event, observer_state),
        daemon=True,
        name="dave-control",
    )
    controller.start()
    send_heartbeat(config)

    print("Status: " + ("ACTIVE" if observer_state["desired"] else "PAUSED"))
    print("Coverage: all accessible Windows drive roots")
    print("Mode: event-based; files are never copied or archived")
    print("Use the DAVE File Activity page to Start or Stop monitoring. Ctrl+C exits the agent.")

    try:
        while True:
            desired = observer_state["desired"]
            current = bool(observer_state["observers"])

            if desired and not current:
                observer_state["observers"] = build_observers(roots, event_queue)
                if observer_state["observers"]:
                    print("[CONTROL] Filesystem monitoring resumed.")

            elif not desired and current:
                stop_observers(observer_state["observers"])
                observer_state["observers"] = []
                dropped = clear_event_queue(event_queue)
                if dropped:
                    print(f"[CONTROL] Cleared {dropped} queued event(s).")
                print("[CONTROL] Filesystem monitoring paused. Agent process remains running.")

            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nStopping agent process...")
    finally:
        stop_event.set()
        if observer_state["observers"]:
            stop_observers(observer_state["observers"])


if __name__ == "__main__":
    main()
