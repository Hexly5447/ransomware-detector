# EXECUTION GUIDE — VS Code on Windows

Step-by-step instructions to run the Ransomware Detection System from a fresh
clone/copy of this folder.

---

## 0. Prerequisites

- Windows 10/11
- **Python 3.13** installed at:
  `C:\Users\ROG STRIX\AppData\Local\Programs\Python\Python313\python.exe`
- Visual Studio Code with the **Python extension** (ms-python.python)

Verify Python:

```powershell
& "C:\Users\ROG STRIX\AppData\Local\Programs\Python\Python313\python.exe" --version
# expected: Python 3.13.5
```

---

## 1. Open the folder in VS Code

```powershell
code "C:\Users\ROG STRIX\Documents\ransomware_detector"
```

Or: VS Code → **File → Open Folder…** → select `ransomware_detector`.

---

## 2. Create & activate the virtual environment

Open VS Code's terminal (**Ctrl+`** / Terminal → New Terminal) and run:

```powershell
& "C:\Users\ROG STRIX\AppData\Local\Programs\Python\Python313\python.exe" -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**If activation is blocked** by execution policy:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Verify you are inside the venv — the prompt shows `(.venv)`:

```powershell
python --version    # Python 3.13.5
```

---

## 3. Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Expected tail of output:

```
Successfully installed joblib-1.6.0 matplotlib-3.10.9 pandas-2.3.3 ...
```

Quick sanity check:

```powershell
python -c "import pandas, sklearn, watchdog, xgboost, tkinter; print('deps OK')"
# deps OK
```

---

## 4. Run order (4 modules)

### Step A — Generate the dataset

```powershell
python main.py generate-data
```

**Expected output:**

```
Generated 250 samples -> ...\ransomware_detector\data\features.csv
```

Check: `data\features.csv` exists with 251 lines (250 rows + header).

### Step B — Train the models

```powershell
python main.py train
```

**Expected output (abridged):**

```
[train] Loaded 250 samples, 125 ransomware, 125 benign

=== RandomForest Metrics ===
  accuracy: 1.0000
  precision: 1.0000
  recall: 1.0000
  f1: 1.0000
  roc_auc: 1.0000
[train] Saved model -> ... models\rf_model.pkl

=== XGBoost Metrics ===
  accuracy: 0.9841
  ...
[train] Metrics saved to ... models\metrics.json
```

Artifacts created: `models\rf_model.pkl`, `models\boost_model.pkl`,
`models\metrics.json`.

### Step C — Start the GUI dashboard (Terminal 1)

```powershell
python main.py gui
```

**Expected:** a dark-themed window titled
*"Ransomware Detection System — Behavioral Analysis Dashboard"* opens.

1. **Browse** → select `test_folder` (or keep the default)
2. Click **▶ START**
3. Status banner turns green: `MONITORING — NO THREATS`
   **Screenshot description:** dark GUI, left = empty LIVE EVENT FEED table,
   right = STATISTICS (0 events), LIVE FEATURES (dashes), ALERTS list empty.

### Step D — Start the console monitor (Terminal 2, optional alternative)

```powershell
python main.py monitor --path test_folder --duration 60
```

**Expected output:**

```
[detector] Watching  : test_folder
[detector] Window    : 5.0s | Threshold: 0.7
[detector] Quarantine: True | Kill: False
[detector] Log file  : ... logs\detection_log.jsonl
[detector] Press Ctrl+C to stop.
```

### Step E — Run the SAFE ransomware simulator (Terminal 3)

```powershell
python simulator\ransomware_simulator.py --files 25 --delay 0.03
```

**Expected output:**

```
================================================================
  RANSOMWARE SIMULATOR — EDUCATIONAL USE ONLY
...
[sandbox] ...\ransomware_detector\test_folder
[sandbox] Safety check PASSED (path is inside project test_folder/)
--- Phase 1: create victim files ---
  [create] victim_document_000.doc
  ...
--- Phase 2: encrypt (XOR, reversible) ---
--- Phase 3: mass rename to .locked ---
--- Phase 4: ransom note ---
[simulate] DONE in 2.5s — 25 files processed.
```

### Step F — SEE THE DETECTION

**Console monitor (Terminal 2) — expected alert:**

```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  *** RANSOMWARE DETECTED ***
  Time        : 2026-10-07 17:37:42
  Probability : 84.67%
  Events      : 41
  Entropy avg : 7.86
  Quarantined : 26 file(s)
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[detector] 1 detection(s) recorded.
```

**GUI (Terminal 1) — expected behavior:**

- LIVE EVENT FEED fills with `created / modified / moved` rows
- LIVE FEATURES show entropy climbing to ~7.9, susp ratio rising
- Status banner turns **RED**: `RANSOMWARE DETECTED`
- A warning popup appears with probability, entropy, quarantine count
- ALERTS list gains a line like `17:37:42  RANSOMWARE  p=84.67%`
  **Screenshot description:** red banner, popup dialog "Ransomware Detected!",
  quarantined files listed.

**Log file** — `logs\detection_log.jsonl` (each line is JSON):

```json
{"time_iso": "...", "label": "RANSOMWARE", "probability": 0.8467,
 "features": {"entropy_avg": 7.8593, "suspicious_ext_ratio": 0.9268, ...},
 "quarantined_files": ["...quarantine\\1791374862_victim_document_000.doc.locked", ...]}
```

**Quarantine folder** — `quarantine\` contains the moved `.locked` files and
the ransom note (26 files after a 25-file simulation).

---

## 5. Recover / reset after a demo

```powershell
# Restore any remaining .locked files in the sandbox
python simulator\ransomware_simulator.py --recover

# Clear quarantine (move files back or delete)
Remove-Item quarantine\* -Force

# Clear logs
Remove-Item logs\detection_log.jsonl -Force

# Empty the sandbox
Get-ChildItem test_folder | Remove-Item -Force
```

---

## 6. Stopping things cleanly

- **GUI**: click the window's **X** (stops monitor, then closes) or **■ STOP**
  first to keep the window open.
- **Console monitor**: press **Ctrl+C** — prints
  `[detector] Stopped by user.` then `N detection(s) recorded.`
- **Simulator**: it runs to completion (~2–3 s); Ctrl+C only if interrupted
  mid-run (then use `--recover`).

---

## 7. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Activate.ps1 cannot be loaded` | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` then re-activate |
| `No module named tkinter` | Reinstall Python 3.13 from python.org with **tcl/tk** option checked |
| `xgboost` import error | `pip install xgboost==2.0.3`; if it still fails, `train_model.py` automatically falls back to `GradientBoostingClassifier` (see README) |
| Monitor shows nothing | Ensure the watched folder path exists; watchdog needs a few seconds to attach |
| 0 detections in console | Simulator must run **after** the monitor prints `Watching` (wait for it) |
| Files left in `test_folder` | Run `--recover` and clear `quarantine\` |
