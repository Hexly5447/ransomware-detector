"""
gui.py — Tkinter live monitoring dashboard.

Features:
- Live event feed (Treeview)
- Threat status banner (green/red)
- Live feature panel
- Start/Stop monitor, folder picker
- Alert popup on ransomware detection
- Stats: total events, alerts, uptime
"""

from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from .detector import Detection, RansomwareDetector
from .feature_extractor import FileEvent
from .monitor import RansomwareMonitor

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WATCH = PROJECT_ROOT / "test_folder"

BG_DARK = "#1e1e2e"
BG_PANEL = "#282840"
BG_ROW_A = "#31314d"
BG_ROW_B = "#2b2b44"
FG_TEXT = "#cdd6f4"
FG_GREEN = "#a6e3a1"
FG_RED = "#f38ba8"
FG_YELLOW = "#f9e2af"
FG_BLUE = "#89b4fa"
ACCENT = "#89b4fa"

STATUS_OK = "MONITORING — NO THREATS"
STATUS_THREAT = "RANSOMWARE DETECTED"
STATUS_IDLE = "IDLE — CLICK START"


class RansomwareGUI(tk.Tk):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.title("Ransomware Detection System — Behavioral Analysis Dashboard")
        self.geometry("1100x720")
        self.minsize(950, 640)
        self.configure(bg=BG_DARK)

        self.monitor: Optional[RansomwareMonitor] = None
        self.detector: Optional[RansomwareDetector] = None
        self._gui_queue: queue.Queue = queue.Queue()
        self._running = False
        self._start_time: Optional[float] = None
        self._event_count = 0
        self._alert_count = 0
        self._watch_path = tk.StringVar(value=str(DEFAULT_WATCH))

        self._build_widgets()
        self._poll_queue()

    # ------------------------------------------------------------------ UI
    def _build_widgets(self):
        # Top status banner
        self.status_var = tk.StringVar(value=STATUS_IDLE)
        banner = tk.Label(
            self,
            textvariable=self.status_var,
            font=("Consolas", 16, "bold"),
            bg=BG_PANEL,
            fg=FG_GREEN,
            pady=10,
        )
        banner.pack(fill="x", padx=8, pady=(8, 4))
        self._banner = banner

        # Controls row
        ctrl = tk.Frame(self, bg=BG_DARK)
        ctrl.pack(fill="x", padx=8, pady=4)

        tk.Label(ctrl, text="Watch folder:", bg=BG_DARK, fg=FG_TEXT,
                 font=("Consolas", 10)).pack(side="left")
        tk.Entry(ctrl, textvariable=self._watch_path, width=70,
                 bg=BG_PANEL, fg=FG_TEXT, insertbackground=FG_TEXT,
                 font=("Consolas", 10)).pack(side="left", padx=6)
        tk.Button(ctrl, text="Browse", command=self._browse,
                  bg=BG_PANEL, fg=FG_TEXT, activebackground=ACCENT,
                  font=("Consolas", 9)).pack(side="left")

        self._start_btn = tk.Button(ctrl, text="▶  START", command=self._start,
                                    bg="#2d4a2d", fg=FG_GREEN, activebackground="#3a5a3a",
                                    font=("Consolas", 10, "bold"), width=10)
        self._start_btn.pack(side="right", padx=4)

        self._stop_btn = tk.Button(ctrl, text="■  STOP", command=self._stop,
                                   bg="#4a2d2d", fg=FG_RED, activebackground="#5a3a3a",
                                   font=("Consolas", 10, "bold"), width=10, state="disabled")
        self._stop_btn.pack(side="right", padx=4)

        # Main paned area: left = event feed, right = features/stats
        main = tk.PanedWindow(self, orient="horizontal", bg=BG_DARK,
                              sashwidth=5, sashrelief="flat")
        main.pack(fill="both", expand=True, padx=8, pady=4)

        # ---- Left: live event feed
        left = tk.Frame(main, bg=BG_PANEL)
        main.add(left, width=640)

        tk.Label(left, text="LIVE EVENT FEED", bg=BG_PANEL, fg=FG_BLUE,
                 font=("Consolas", 11, "bold")).pack(anchor="w", padx=6, pady=(6, 2))

        cols = ("time", "event", "file", "entropy")
        self._feed = ttk.Treeview(left, columns=cols, show="headings", height=20)
        for col, w, h in (("time", 80, "Time"), ("event", 80, "Event"),
                          ("file", 420, "File"), ("entropy", 70, "Entropy")):
            self._feed.heading(col, text=h)
            self._feed.column(col, width=w, anchor="w")
        self._feed.tag_configure("susp", foreground=FG_RED)
        self._feed.tag_configure("normal", foreground=FG_TEXT)
        vsb = ttk.Scrollbar(left, orient="vertical", command=self._feed.yview)
        self._feed.configure(yscrollcommand=vsb.set)
        self._feed.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=6)
        vsb.pack(side="right", fill="y", pady=6)

        # ---- Right: features + stats + alerts
        right = tk.Frame(main, bg=BG_PANEL)
        main.add(right, width=380)

        # Stats
        stats_frame = tk.LabelFrame(right, text=" STATISTICS ", bg=BG_PANEL,
                                    fg=FG_BLUE, font=("Consolas", 10, "bold"))
        stats_frame.pack(fill="x", padx=6, pady=(6, 4))
        self._stats_labels = {}
        for key, label in (("events", "Total events:"), ("alerts", "Alerts:"),
                           ("uptime", "Uptime:"), ("last_prob", "Last prob:")):
            row = tk.Frame(stats_frame, bg=BG_PANEL)
            row.pack(fill="x", padx=6, pady=2)
            tk.Label(row, text=label, bg=BG_PANEL, fg=FG_TEXT,
                     font=("Consolas", 10), width=14, anchor="w").pack(side="left")
            var = tk.StringVar(value="0")
            tk.Label(row, textvariable=var, bg=BG_PANEL, fg=FG_YELLOW,
                     font=("Consolas", 10, "bold")).pack(side="left")
            self._stats_labels[key] = var

        # Live features
        feat_frame = tk.LabelFrame(right, text=" LIVE FEATURES ", bg=BG_PANEL,
                                   fg=FG_BLUE, font=("Consolas", 10, "bold"))
        feat_frame.pack(fill="x", padx=6, pady=4)
        self._feat_labels = {}
        feat_keys = [
            ("entropy_avg", "Entropy avg"),
            ("file_create_rate", "Create rate/s"),
            ("rename_rate", "Rename rate/s"),
            ("suspicious_ext_ratio", "Susp. ext ratio"),
            ("event_count", "Events in window"),
            ("ransom_note_detected", "Ransom note"),
        ]
        for key, label in feat_keys:
            row = tk.Frame(feat_frame, bg=BG_PANEL)
            row.pack(fill="x", padx=6, pady=1)
            tk.Label(row, text=label + ":", bg=BG_PANEL, fg=FG_TEXT,
                     font=("Consolas", 9), width=18, anchor="w").pack(side="left")
            var = tk.StringVar(value="-")
            tk.Label(row, textvariable=var, bg=BG_PANEL, fg=FG_YELLOW,
                     font=("Consolas", 9, "bold")).pack(side="left")
            self._feat_labels[key] = var

        # Alerts log
        alert_frame = tk.LabelFrame(right, text=" ALERTS ", bg=BG_PANEL,
                                    fg=FG_RED, font=("Consolas", 10, "bold"))
        alert_frame.pack(fill="both", expand=True, padx=6, pady=(4, 6))
        self._alert_list = tk.Listbox(alert_frame, bg=BG_DARK, fg=FG_RED,
                                      font=("Consolas", 9), height=8)
        self._alert_list.pack(fill="both", expand=True, padx=4, pady=4)

    # ------------------------------------------------------------- actions
    def _browse(self):
        d = filedialog.askdirectory(initialdir=self._watch_path.get() or str(PROJECT_ROOT))
        if d:
            self._watch_path.set(d)

    def _start(self):
        path = Path(self._watch_path.get())
        if not path.exists():
            messagebox.showerror("Error", f"Folder does not exist:\n{path}")
            return

        self.detector = RansomwareDetector(
            window_sec=5.0,
            threshold=0.7,
            quarantine=True,
            kill_process=False,  # OFF by default
            on_alert=lambda d: self._gui_queue.put(("alert", d)),
        )

        def on_features(feats: dict):
            self._gui_queue.put(("features", feats))
            self.detector.evaluate(feats)

        def on_event(ev):
            # Track for quarantine + push raw event to the live feed (once)
            self.detector.observe_event(ev)
            self._gui_queue.put(("event", ev))

        self.monitor = RansomwareMonitor(
            watch_path=path,
            window_sec=5.0,
            feature_callback=on_features,
            event_callback=on_event,
        )
        self.monitor.start()
        self._running = True
        self._start_time = time.time()
        self._event_count = 0
        self._alert_count = 0
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._set_status(STATUS_OK, FG_GREEN)

    def _stop(self):
        if self.monitor:
            self.monitor.stop()
        self._running = False
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        self._set_status(STATUS_IDLE, FG_YELLOW)

    def _set_status(self, text: str, color: str):
        self.status_var.set(text)
        self._banner.configure(fg=color)

    # ---------------------------------------------------------- queue pump
    def _poll_queue(self):
        try:
            while True:
                kind, payload = self._gui_queue.get_nowait()
                if kind == "event":
                    self._add_event_row(payload)
                elif kind == "features":
                    self._update_features(payload)
                elif kind == "alert":
                    self._handle_alert(payload)
        except queue.Empty:
            pass
        self.after(200, self._poll_queue)

    def _add_event_row(self, ev: FileEvent):
        self._event_count += 1
        ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
        name = ev.src_path.name
        if ev.dest_path:
            name = f"{ev.src_path.name} → {ev.dest_path.name}"
        entropy = f"{ev.src_path.suffix}" if ev.event_type == "moved" else ""
        # Compute quick entropy display for created/modified
        susp = ev.src_path.suffix.lower() in (
            ".locked", ".encrypted", ".crypt", ".enc", ".ransom", ".lock"
        )
        tag = "susp" if susp else "normal"
        self._feed.insert("", 0, values=(ts, ev.event_type, name, entropy), tags=(tag,))
        # Keep feed trimmed
        children = self._feed.get_children()
        if len(children) > 500:
            for c in children[500:]:
                self._feed.delete(c)
        self._stats_labels["events"].set(str(self._event_count))

    def _update_features(self, feats: dict):
        for key, var in self._feat_labels.items():
            val = feats.get(key, 0)
            if isinstance(val, float):
                var.set(f"{val:.3f}")
            else:
                var.set(str(val))
        # Probability
        if self.detector and self.detector.last_result:
            prob = self.detector.last_result.get("probability", 0)
            self._stats_labels["last_prob"].set(f"{prob:.2%}")
        # Uptime
        if self._start_time:
            up = int(time.time() - self._start_time)
            self._stats_labels["uptime"].set(f"{up // 60}m {up % 60}s")

    def _handle_alert(self, det: Detection):
        self._alert_count += 1
        self._stats_labels["alerts"].set(str(self._alert_count))
        ts = time.strftime("%H:%M:%S", time.localtime(det.timestamp))
        msg = f"{ts}  RANSOMWARE  p={det.probability:.2%}"
        self._alert_list.insert(0, msg)
        self._set_status(STATUS_THREAT, FG_RED)
        messagebox.showwarning(
            "Ransomware Detected!",
            f"Ransomware behavior detected!\n\n"
            f"Time        : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Probability : {det.probability:.2%}\n"
            f"Events      : {det.features.get('event_count', 0):.0f}\n"
            f"Entropy avg : {det.features.get('entropy_avg', 0):.2f}\n"
            f"Quarantined : {len(det.quarantined_files)} file(s)\n\n"
            f"Log: logs/detection_log.jsonl",
        )
        # Auto-revert banner after a while if no new alerts
        self.after(8000, lambda: self._set_status(
            STATUS_OK if self._running else STATUS_IDLE,
            FG_GREEN if self._running else FG_YELLOW,
        ))

    def on_closing(self):
        if self._running:
            self._stop()
        self.destroy()


def run_gui():
    """Entry point for `python main.py gui`."""
    app = RansomwareGUI()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()


if __name__ == "__main__":
    run_gui()