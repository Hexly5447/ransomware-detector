"""
monitor.py — Real-time filesystem monitoring using watchdog.

Watches a target directory, emits FileEvent objects to a callback/queue,
and maintains a sliding window for feature extraction.
"""

from __future__ import annotations

import queue
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from watchdog.events import (
    FileSystemEvent,
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    FileDeletedEvent,
    FileMovedEvent,
)
from watchdog.observers import Observer

from .feature_extractor import FileEvent, SlidingWindow


class RansomwareEventHandler(FileSystemEventHandler):
    """Converts watchdog events to our internal FileEvent format."""

    def __init__(self, event_queue: queue.Queue):
        super().__init__()
        self._queue = event_queue

    def _convert(self, event: FileSystemEvent, event_type: str) -> None:
        src = Path(event.src_path)
        dest = Path(event.dest_path) if hasattr(event, "dest_path") and event.dest_path else None
        fe = FileEvent(
            timestamp=time.time(),
            event_type=event_type,
            src_path=src,
            dest_path=dest,
            is_directory=event.is_directory,
        )
        self._queue.put(fe)

    def on_created(self, event: FileCreatedEvent) -> None:
        self._convert(event, "created")

    def on_modified(self, event: FileModifiedEvent) -> None:
        self._convert(event, "modified")

    def on_deleted(self, event: FileDeletedEvent) -> None:
        self._convert(event, "deleted")

    def on_moved(self, event: FileMovedEvent) -> None:
        self._convert(event, "moved")


class RansomwareMonitor:
    """
    High-level monitor: starts watchdog, aggregates events into sliding windows,
    and calls a callback with feature dicts at regular intervals.
    """

    def __init__(
        self,
        watch_path: Path,
        window_sec: float = 10.0,
        feature_callback: Optional[Callable[[dict], None]] = None,
        event_callback: Optional[Callable] = None,
        recursive: bool = True,
    ):
        self.watch_path = Path(watch_path).resolve()
        self.window_sec = window_sec
        self.feature_callback = feature_callback
        self.event_callback = event_callback
        self.recursive = recursive

        self._event_queue: queue.Queue = queue.Queue()
        self._handler = RansomwareEventHandler(self._event_queue)
        self._observer: Optional[Observer] = None
        self._window = SlidingWindow(window_sec=window_sec)
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._feature_thread: Optional[threading.Thread] = None
        self._feature_interval = 1.0  # emit features every second

    def start(self) -> None:
        if self._running:
            return
        self._running = True

        self._observer = Observer()
        self._observer.schedule(self._handler, str(self.watch_path), recursive=self.recursive)
        self._observer.start()

        self._worker_thread = threading.Thread(target=self._process_events, daemon=True)
        self._worker_thread.start()

        self._feature_thread = threading.Thread(target=self._emit_features, daemon=True)
        self._feature_thread.start()

    def stop(self) -> None:
        self._running = False
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=2.0)
        if self._worker_thread:
            self._worker_thread.join(timeout=2.0)
        if self._feature_thread:
            self._feature_thread.join(timeout=2.0)

    def _process_events(self) -> None:
        while self._running:
            try:
                ev = self._event_queue.get(timeout=0.1)
                self._window.add_event(ev)
                if self.event_callback:
                    try:
                        self.event_callback(ev)
                    except Exception:
                        pass
            except queue.Empty:
                continue

    def _emit_features(self) -> None:
        while self._running:
            time.sleep(self._feature_interval)
            if self.feature_callback:
                feats = self._window.compute_features()
                self.feature_callback(feats)

    def get_latest_features(self) -> dict:
        return self._window.compute_features()

    def is_running(self) -> bool:
        return self._running


if __name__ == "__main__":
    import sys

    def print_features(feats: dict):
        print(f"[Features] creates={feats['file_create_rate']:.2f}/s "
              f"entropy_avg={feats['entropy_avg']:.2f} "
              f"susp_ext={feats['suspicious_ext_ratio']:.2f} "
              f"events={feats['event_count']}")

    if len(sys.argv) < 2:
        print("Usage: python monitor.py <path_to_watch>")
        sys.exit(1)

    path = Path(sys.argv[1])
    mon = RansomwareMonitor(path, window_sec=5.0, feature_callback=print_features)
    print(f"Monitoring {path} ... Ctrl+C to stop")
    mon.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        mon.stop()
        print("\nStopped.")