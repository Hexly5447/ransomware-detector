"""
detector.py — Orchestrates monitoring, prediction, and response actions.

Pipeline: watchdog events -> sliding window -> predictor -> alert/quarantine/kill.

Response actions:
- Log every evaluation to logs/detection_log.jsonl
- Quarantine (move suspicious files to quarantine/) [ON by default]
- Kill the malicious process (--kill flag required; OFF by default)
"""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

import psutil

from .feature_extractor import (
    FileEvent,
    SlidingWindow,
    file_entropy,
    is_ransom_extension,
    is_ransom_note,
)
from .predict import RansomwarePredictor, load_predictor

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = PROJECT_ROOT / "logs"
QUARANTINE_DIR = PROJECT_ROOT / "quarantine"
LOG_FILE = LOG_DIR / "detection_log.jsonl"


@dataclass
class Detection:
    """A single ransomware detection alert."""
    timestamp: float
    label: str
    probability: float
    features: dict
    quarantined_files: List[str] = field(default_factory=list)
    killed_process: Optional[int] = None

    def to_json(self) -> str:
        return json.dumps({
            "timestamp": self.timestamp,
            "time_iso": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp)),
            "label": self.label,
            "probability": round(self.probability, 4),
            "features": {k: round(v, 4) for k, v in self.features.items()},
            "quarantined_files": self.quarantined_files,
            "killed_process": self.killed_process,
        })


class RansomwareDetector:
    """
    Main detector: consumes feature windows from the monitor, runs the model,
    and executes response actions.

    Args:
        window_sec: Sliding window duration (should match monitor).
        threshold: Probability threshold for RANSOMWARE classification.
        quarantine: Move suspicious files to quarantine/ on detection.
        kill_process: Attempt to kill process owning a quarantined file (OFF by default).
        on_alert: Callback invoked with a Detection object (for GUI).
    """

    def __init__(
        self,
        window_sec: float = 5.0,
        threshold: float = 0.7,
        quarantine: bool = True,
        kill_process: bool = False,
        on_alert: Optional[Callable[[Detection], None]] = None,
    ):
        self.window_sec = window_sec
        self.quarantine = quarantine
        self.kill_process = kill_process
        self.on_alert = on_alert

        self.predictor: RansomwarePredictor = load_predictor(threshold=threshold)
        self._alert_cooldown = 5.0
        self._last_alert_time = 0.0
        self.detections: List[Detection] = []
        self.last_features: dict = {}
        self.last_result: dict = {}
        # Quarantine registry: suspicious paths recorded AT EVENT TIME
        # (independent of sliding-window purge, so files can still be
        # quarantined even if detection fires seconds after the attack).
        self._quarantine_candidates: dict = {}

        LOG_DIR.mkdir(exist_ok=True)
        QUARANTINE_DIR.mkdir(exist_ok=True)

    def observe_event(self, event: FileEvent) -> None:
        """
        Called by the monitor for every raw file event.
        Records suspicious paths (ransom extension or ransom-note name)
        as quarantine candidates the moment they appear.
        """
        if event.is_directory:
            return
        if event.event_type == "moved" and event.dest_path:
            path = event.dest_path
        elif event.event_type in ("created", "modified"):
            path = event.src_path
        else:
            return
        if is_ransom_extension(path.suffix.lower()) or is_ransom_note(path.name):
            self._quarantine_candidates[str(path)] = event.timestamp
            if len(self._quarantine_candidates) > 1000:
                # Drop oldest entries if registry grows unbounded
                oldest = sorted(self._quarantine_candidates, key=self._quarantine_candidates.get)
                for k in oldest[:200]:
                    del self._quarantine_candidates[k]

    def evaluate(
        self,
        features: dict,
        recent_events: Optional[List[FileEvent]] = None,
    ) -> Optional[Detection]:
        """
        Run classification on features from the monitor's sliding window.
        Returns a Detection if classified as RANSOMWARE and cooldown elapsed.
        """
        if features.get("event_count", 0) == 0:
            return None

        result = self.predictor.predict(features)
        self.last_features = features
        self.last_result = result

        self._log_prediction(result, features)

        if result["label"] == "RANSOMWARE":
            now = time.time()
            if now - self._last_alert_time >= self._alert_cooldown:
                self._last_alert_time = now
                detection = Detection(
                    timestamp=now,
                    label=result["label"],
                    probability=result["probability"],
                    features=features,
                )

                if self.quarantine:
                    detection.quarantined_files = self._quarantine_tracked(now)
                if self.kill_process and detection.quarantined_files:
                    detection.killed_process = self._kill_file_owner(
                        detection.quarantined_files[0]
                    )

                self.detections.append(detection)
                self._log_detection(detection)

                if self.on_alert:
                    self.on_alert(detection)
                return detection

        return None

    def _log_prediction(self, result: dict, features: dict) -> None:
        record = {
            "timestamp": time.time(),
            "time_iso": time.strftime("%Y-%m-%d %H:%M:%S"),
            "label": result["label"],
            "probability": round(result["probability"], 4),
            "event_count": features.get("event_count", 0),
            "entropy_avg": round(features.get("entropy_avg", 0), 4),
            "suspicious_ext_ratio": round(features.get("suspicious_ext_ratio", 0), 4),
        }
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def _log_detection(self, detection: Detection) -> None:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(detection.to_json() + "\n")

    def _quarantine_tracked(self, now: float) -> List[str]:
        """
        Move all registered quarantine candidates that still exist on disk
        into quarantine/, then clear the registry.

        Candidates are recorded by observe_event() at event-arrival time,
        so this works even when detection fires long after the attack
        events have aged out of the sliding window.
        """
        quarantined = []
        for pstr in list(self._quarantine_candidates.keys()):
            path = Path(pstr)
            if not path.exists() or not path.is_file():
                continue
            try:
                dest = QUARANTINE_DIR / f"{int(now)}_{path.name}"
                shutil.move(str(path), str(dest))
                quarantined.append(str(dest))
            except (OSError, PermissionError, shutil.Error):
                pass
        self._quarantine_candidates.clear()
        return quarantined

    def _kill_file_owner(self, file_path: str) -> Optional[int]:
        """
        Best-effort: find and kill the process that most recently wrote to
        file_path. Returns PID or None. Only called when kill_process=True.
        """
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                for f in proc.open_files():
                    if os.path.abspath(f.path) == os.path.abspath(file_path):
                        proc.kill()
                        return proc.pid
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
        return None


def run_detector(
    watch_path: Path,
    window_sec: float = 5.0,
    threshold: float = 0.7,
    quarantine: bool = True,
    kill_process: bool = False,
    duration: float = 60.0,
) -> List[Detection]:
    """
    Run the full detector pipeline (monitor + detector) in console mode.
    Used by `python main.py monitor`.
    """
    from .monitor import RansomwareMonitor

    def on_alert(d: Detection):
        print(
            f"\n{'!' * 60}\n"
            f"  *** RANSOMWARE DETECTED ***\n"
            f"  Time        : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"  Probability : {d.probability:.2%}\n"
            f"  Events      : {d.features.get('event_count', 0):.0f}\n"
            f"  Entropy avg : {d.features.get('entropy_avg', 0):.2f}\n"
            f"  Quarantined : {len(d.quarantined_files)} file(s)\n"
            f"{'!' * 60}"
        )

    detector = RansomwareDetector(
        window_sec=window_sec,
        threshold=threshold,
        quarantine=quarantine,
        kill_process=kill_process,
        on_alert=on_alert,
    )

    monitor = RansomwareMonitor(
        watch_path=watch_path,
        window_sec=window_sec,
        feature_callback=detector.evaluate,
        event_callback=detector.observe_event,
    )

    print(f"[detector] Watching  : {watch_path}")
    print(f"[detector] Window    : {window_sec}s | Threshold: {threshold}")
    print(f"[detector] Quarantine: {quarantine} | Kill: {kill_process}")
    print(f"[detector] Log file  : {LOG_FILE}")
    print("[detector] Press Ctrl+C to stop.\n")

    monitor.start()
    start = time.time()
    try:
        while time.time() - start < duration:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[detector] Stopped by user.")
    finally:
        monitor.stop()

    print(f"[detector] {len(detector.detections)} detection(s) recorded.")
    return detector.detections


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m src.detector <path>")
        sys.exit(1)
    run_detector(Path(sys.argv[1]), duration=30.0)