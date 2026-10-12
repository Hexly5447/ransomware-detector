"""
feature_extractor.py — Behavioral feature extraction for ransomware detection.

Computes entropy, file I/O rates, extension changes, rename patterns,
and encryption-speed proxies from watchdog event streams.
"""

from __future__ import annotations

import math
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np


RANSOM_EXTENSIONS = {
    ".locked",
    ".encrypted",
    ".crypt",
    ".crypto",
    ".enc",
    ".ransom",
    ".ransomware",
    ".lock",
    ".locky",
    ".zepto",
    ".cerber",
    ".cryptolocker",
    ".cryptowall",
    ".teslacrypt",
    ".locky",
    ".aaa",
    ".xyz",
    ".zzz",
    ".micro",
    ".rapid",
    ".onion",
    ".decrypt",
    ".restore",
    ".help",
    ".readme",
    ".recover",
}


RANSOM_NOTE_NAMES = {
    "readme",
    "read_me",
    "readme.txt",
    "readme.html",
    "readme.htm",
    "decrypt",
    "decrypt.txt",
    "decrypt.html",
    "recover",
    "recover.txt",
    "recover.html",
    "restore",
    "restore.txt",
    "help",
    "help.txt",
    "help.html",
    "how_to_decrypt",
    "how_to_recover",
    "ransom",
    "ransom.txt",
    "ransom.html",
    "!!!",
    "!!!readme!!!",
    "_readme_",
    "README_RECOVER",
    "README_DECRYPT",
}


EXTENSION_TIERS = {
    "documents": {
        ".doc",
        ".docx",
        ".pdf",
        ".txt",
        ".rtf",
        ".odt",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".csv",
    },
    "images": {".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff", ".webp", ".svg"},
    "databases": {".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".sql"},
    "archives": {".zip", ".rar", ".7z", ".tar", ".gz", ".bak"},
    "code": {".py", ".js", ".ts", ".java", ".cpp", ".c", ".h", ".cs", ".php", ".rb"},
    "config": {".json", ".xml", ".yaml", ".yml", ".ini", ".cfg", ".conf"},
}


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of bytes (0.0–8.0)."""
    if not data:
        return 0.0
    freq = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(freq, minlength=256)
    probs = counts[counts > 0] / len(data)
    return float(-np.sum(probs * np.log2(probs)))


def file_entropy(path: Path, max_bytes: int = 65536) -> float:
    """Read up to max_bytes and return entropy."""
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        return shannon_entropy(data)
    except (OSError, PermissionError):
        return 0.0


def is_ransom_extension(ext: str) -> bool:
    return ext.lower() in RANSOM_EXTENSIONS


def is_ransom_note(filename: str) -> bool:
    name = filename.lower().rsplit(".", 1)[0]
    return any(note in name for note in RANSOM_NOTE_NAMES)


def get_extension_tier(ext: str) -> str:
    ext = ext.lower()
    for tier, exts in EXTENSION_TIERS.items():
        if ext in exts:
            return tier
    return "other"


@dataclass
class FileEvent:
    """Single filesystem event from watchdog."""
    timestamp: float
    event_type: str  # created, modified, deleted, moved
    src_path: Path
    dest_path: Optional[Path] = None
    is_directory: bool = False


@dataclass
class SlidingWindow:
    """
    Aggregates events over a rolling time window.

    Features computed:
    - entropy statistics on new/modified files
    - event rates (create/modify/delete/rename per second)
    - extension change rate
    - suspicious extension ratio
    - ransom note detection
    - bytes written rate
    """
    window_sec: float = 10.0
    events: List[FileEvent] = field(default_factory=list)
    _file_entropies: Dict[str, float] = field(default_factory=dict)
    _bytes_written: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def add_event(self, ev: FileEvent) -> None:
        now = time.time()
        self.events.append(ev)
        self._purge_old(now)

        if ev.event_type in ("created", "modified") and not ev.is_directory:
            path_str = str(ev.src_path)
            try:
                size = ev.src_path.stat().st_size
                self._bytes_written[path_str] += size
            except OSError:
                pass

            # Recompute entropy on modify (content changed, e.g. encryption);
            # compute on create if not yet present.
            if ev.event_type == "modified" or path_str not in self._file_entropies:
                self._file_entropies[path_str] = file_entropy(ev.src_path)

        if ev.event_type == "moved" and not ev.is_directory and ev.dest_path:
            self._file_entropies[str(ev.dest_path)] = file_entropy(ev.dest_path)

    def _purge_old(self, now: float, max_age: Optional[float] = None) -> None:
        age_limit = self.window_sec if max_age is None else max_age
        cutoff = now - age_limit
        self.events = [e for e in self.events if e.timestamp >= cutoff]
        valid_paths = {str(e.src_path) for e in self.events}
        valid_paths.update(str(e.dest_path) for e in self.events if e.dest_path)
        self._file_entropies = {k: v for k, v in self._file_entropies.items() if k in valid_paths}
        # Preserve defaultdict type so later `+=` never raises KeyError
        self._bytes_written = defaultdict(
            int, {k: v for k, v in self._bytes_written.items() if k in valid_paths}
        )

    def get_events(self, max_age: Optional[float] = None) -> List[FileEvent]:
        """
        Return a copy of current events (purged at window_sec, or max_age if
        given). max_age > window_sec lets callers see trailing-edge events.
        """
        self._purge_old(time.time(), max_age=max_age)
        return list(self.events)

    def compute_features(self) -> Dict[str, float]:
        """Purge stale events, then return the feature vector for the window."""
        # Purge first so features always reflect the true sliding window
        # (otherwise stale events freeze features after activity stops).
        self._purge_old(time.time())
        if not self.events:
            return self._empty_features()

        now = time.time()
        window_start = now - self.window_sec
        actual_duration = max(0.001, now - max(window_start, self.events[0].timestamp))

        creates = sum(1 for e in self.events if e.event_type == "created" and not e.is_directory)
        modifies = sum(1 for e in self.events if e.event_type == "modified" and not e.is_directory)
        deletes = sum(1 for e in self.events if e.event_type == "deleted" and not e.is_directory)
        moves = sum(1 for e in self.events if e.event_type == "moved" and not e.is_directory)

        entropies = list(self._file_entropies.values())
        entropy_avg = float(np.mean(entropies)) if entropies else 0.0
        entropy_max = float(np.max(entropies)) if entropies else 0.0

        ext_changes = 0
        unique_exts = set()
        suspicious_ext_count = 0
        total_new_files = 0
        ransom_note_hit = 0

        for e in self.events:
            if e.event_type in ("created", "modified", "moved") and not e.is_directory:
                path = e.dest_path if e.event_type == "moved" and e.dest_path else e.src_path
                ext = path.suffix.lower()
                if ext:
                    unique_exts.add(ext)
                if is_ransom_extension(ext):
                    suspicious_ext_count += 1
                if e.event_type == "created":
                    total_new_files += 1
                if is_ransom_note(path.name):
                    ransom_note_hit = 1

            if e.event_type == "moved" and e.dest_path:
                src_ext = e.src_path.suffix.lower()
                dst_ext = e.dest_path.suffix.lower()
                if src_ext != dst_ext and src_ext and dst_ext:
                    ext_changes += 1

        bytes_written = sum(self._bytes_written.values())
        avg_file_size = bytes_written / max(1, creates + modifies)

        return {
            "entropy_avg": entropy_avg,
            "entropy_max": entropy_max,
            "file_create_rate": creates / actual_duration,
            "file_modify_rate": modifies / actual_duration,
            "file_delete_rate": deletes / actual_duration,
            "rename_rate": moves / actual_duration,
            "extension_change_rate": ext_changes / actual_duration,
            "unique_extensions_new": len(unique_exts),
            "suspicious_ext_ratio": suspicious_ext_count / max(1, creates + modifies + moves),
            "bytes_written_rate": bytes_written / actual_duration,
            "avg_file_size": avg_file_size,
            "ransom_note_detected": float(ransom_note_hit),
            "time_window_sec": self.window_sec,
            "event_count": len(self.events),
        }

    def _empty_features(self) -> Dict[str, float]:
        keys = [
            "entropy_avg",
            "entropy_max",
            "file_create_rate",
            "file_modify_rate",
            "file_delete_rate",
            "rename_rate",
            "extension_change_rate",
            "unique_extensions_new",
            "suspicious_ext_ratio",
            "bytes_written_rate",
            "avg_file_size",
            "ransom_note_detected",
            "time_window_sec",
            "event_count",
        ]
        return {k: 0.0 for k in keys}


# Ordered feature names — used by predict.py to build model input vectors.
FEATURE_NAMES: List[str] = [
    "entropy_avg",
    "entropy_max",
    "file_create_rate",
    "file_modify_rate",
    "file_delete_rate",
    "rename_rate",
    "extension_change_rate",
    "unique_extensions_new",
    "suspicious_ext_ratio",
    "bytes_written_rate",
    "avg_file_size",
    "ransom_note_detected",
    "time_window_sec",
    "event_count",
]


def extract_features_from_events(events: List[FileEvent], window_sec: float = 10.0) -> Dict[str, float]:
    """Convenience: feed a list of events into a window and return features."""
    win = SlidingWindow(window_sec=window_sec)
    for ev in events:
        win.add_event(ev)
    return win.compute_features()


if __name__ == "__main__":
    # Quick self-test
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        events = []
        now = time.time()

        # Simulate benign activity
        for i in range(5):
            f = td_path / f"doc{i}.txt"
            f.write_text("hello world " * 100)
            events.append(FileEvent(now + i * 0.5, "created", f))
            time.sleep(0.01)

        feats = extract_features_from_events(events, window_sec=10.0)
        print("Benign-like features:")
        for k, v in feats.items():
            print(f"  {k}: {v:.4f}")

        # Simulate ransomware-like activity
        events2 = []
        for i in range(20):
            f = td_path / f"file{i}.dat"
            f.write_bytes(os.urandom(1024))  # high entropy
            events2.append(FileEvent(now + 20 + i * 0.05, "created", f))
            events2.append(FileEvent(now + 20 + i * 0.05 + 0.01, "moved", f, td_path / f"file{i}.locked"))

        feats2 = extract_features_from_events(events2, window_sec=10.0)
        print("\nRansomware-like features:")
        for k, v in feats2.items():
            print(f"  {k}: {v:.4f}")