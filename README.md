# Ransomware Detection System using Machine Learning and Behavioral Analysis

Real-time, behavior-based ransomware detection for Windows: `watchdog` file
monitoring → 14-feature behavioral extraction → Random Forest / XGBoost
classification → log + quarantine + GUI alert.

> **Educational use only.** The included simulator performs reversible
> "encryption" strictly inside the sandboxed `test_folder/` and hard-refuses
> to run anywhere else. No real malware, C2, or evasion code is included.

---

## Features

- **Real-time monitoring** of file create/modify/delete/move events (watchdog)
- **Behavioral features**: Shannon entropy, event rates, extension-change
  rate, suspicious-extension ratio, bytes-written rate, ransom-note IOC
- **ML classification**: Random Forest (primary) + XGBoost (comparison),
  probability threshold 0.7
- **Response**: JSONL audit log, quarantine (move) of suspicious files,
  optional process kill (`--kill`, OFF by default)
- **Tkinter GUI dashboard**: live feed, feature panel, threat banner, alerts
- **Safe simulator**: reproduces crypto-ransomware TTPs in a sandbox only

---

## Quick Start

```powershell
# 1. Open in VS Code
code "C:\Users\ROG STRIX\Documents\ransomware_detector"

# 2. Virtual environment (Python 3.13)
& "C:\Users\ROG STRIX\AppData\Local\Programs\Python\Python313\python.exe" -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass   # if needed
.\.venv\Scripts\Activate.ps1

# 3. Dependencies
python -m pip install -r requirements.txt

# 4. Data + model
python main.py generate-data
python main.py train

# 5a. GUI demo (terminal 1)
python main.py gui

# 5b. Console monitor (terminal 2, alternative)
python main.py monitor --path test_folder --duration 60

# 5c. Attack simulation (terminal 3)
python simulator\ransomware_simulator.py --files 25
```

Full walkthrough with expected output: **`docs/EXECUTION_GUIDE.md`**.

---

## Project Structure

```
ransomware_detector/
├── data/
│   ├── raw/                    # (optional) real datasets go here
│   ├── processed/              # train/test artifacts
│   └── features.csv            # 250-row behavioral dataset (generated)
├── models/
│   ├── rf_model.pkl            # trained Random Forest
│   ├── boost_model.pkl         # trained XGBoost
│   └── metrics.json            # accuracy/precision/recall/F1/ROC-AUC
├── src/
│   ├── feature_extractor.py    # entropy + 14-feature window extraction
│   ├── monitor.py              # watchdog observer + sliding window
│   ├── train_model.py          # data generation + RF/XGB training
│   ├── predict.py              # model loading + inference
│   ├── detector.py             # orchestration: log, quarantine, kill
│   └── gui.py                  # Tkinter live dashboard
├── simulator/
│   └── ransomware_simulator.py # SAFE sandbox attack simulator
├── tests/                      # smoke tests / debug probes
├── logs/                       # detection_log.jsonl
├── quarantine/                 # intercepted suspicious files
├── test_folder/                # SANDBOX watched by default
├── docs/
│   ├── SYNOPSIS.md             # academic synopsis + literature review
│   ├── EXECUTION_GUIDE.md      # VS Code step-by-step + expected output
│   ├── VIVA_QUESTIONS.md       # 25 Q&A + 10 tricky + 3-min script
│   └── REPORT_OUTLINE.md       # 60–80 page report TOC + diagrams
├── requirements.txt
├── main.py                     # CLI: generate-data | train | monitor | gui | simulate
└── README.md
```

---

## CLI Reference

```text
python main.py generate-data [--samples 250]
python main.py train
python main.py monitor [--path test_folder] [--window 5] [--threshold 0.7]
                       [--duration 60] [--no-quarantine] [--kill]
python main.py gui
python main.py simulate [--files 30] [--delay 0.05]
python simulator\ransomware_simulator.py --recover     # undo simulation
```

`--kill` is **OFF by default**. Quarantine is **ON by default**.

---

## Technology & Version Notes (Python 3.13)

Target interpreter: **Python 3.13.5** (verified on this machine).

The following pinned versions were adjusted from the original plan because
Python 3.13 requires newer wheels. All were verified installable and
importable on `cp313-win_amd64`:

| Package | Original plan | Installed (3.13) | Reason |
|---------|--------------|------------------|--------|
| pandas | 2.2.2 | **2.3.3** | 2.2.2 has no cp313 wheel (sdist build too slow/fragile) |
| scikit-learn | 1.5.0 | **1.9.1** | 1.5.0 sdist fails to build on 3.13; 1.9.1 ships cp313 wheels |
| matplotlib | 3.9.0 | **3.10.9** | 3.9.0 has no cp313 wheel |
| watchdog | 4.0.1 | **6.0.0** | 4.0.1 crashes on 3.13 (`_ThreadHandle` threading error) |
| joblib | 1.4.2 | **1.6.0** | pulled by scikit-learn 1.9.1 |
| numpy | 1.26.4 | **2.5.3** | required by pandas 2.3.3 / sklearn 1.9.1 on 3.13 |
| xgboost | 2.0.3 | **2.0.3** | unchanged — installs fine |

**XGBoost fallback (design decision):** `train_model.py` imports XGBoost
inside a `try/except`. If `xgboost` is unavailable, it automatically trains
`sklearn.ensemble.GradientBoostingClassifier` instead and labels the metrics
accordingly — the build never stops on a missing boosting library. On this
machine **XGBoost 2.0.3 installs and is the library actually used.**

---

## Results (this build, 250-sample synthetic dataset, 75/25 split)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|-------|----------|-----------|--------|-----|---------|
| Random Forest | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| XGBoost | 0.9841 | 1.0000 | 0.9677 | 0.9836 | 1.0000 |

Confusion matrices: RF `[[32,0],[0,31]]`, XGBoost `[[32,0],[1,30]]`.

**Live detection (simulator vs monitor):**

```
*** RANSOMWARE DETECTED ***
  Probability : 84.67%   Entropy avg : 7.86
  Quarantined : 26 file(s)
```

Top RF features: `unique_extensions_new`, `entropy_max`, `entropy_avg`,
`ransom_note_detected`, `bytes_written_rate`, `suspicious_ext_ratio`.

---

## Known Limitations (honest statement)

1. **Synthetic training data** — the model is trained on synthetically
   generated behavioral features, not live production telemetry. Metrics show
   separability of the behavioral model, not field accuracy. Real deployment
   requires retraining on labeled real-world data (sources noted below).
2. **Folder-scoped monitoring** — watchdog watches a chosen folder; system-wide
   coverage needs ETW (Windows) or inotify/fanotify (Linux) integration.
3. **False positives** on legitimate high-entropy bulk writers (backup/compress
   jobs) are possible; threshold tuning and process allow-listing required in
   production.
4. **Process kill is best-effort** (`psutil` handle scan), OFF by default.
5. Not a replacement for backups, patching, or endpoint protection.

**Optional real-dataset sources for future retraining** (download required,
project runs fully without them):
- CIC IDS / CICMalware datasets (Canadian Institute for Cybersecurity)
- Stratosphere IPS / Malware Capture datasets
- Lakhani & Tan ransomware research datasets
- Microsoft Malware Classification Challenge (BIG 2015)

---

## Future Enhancements

1. **Deep learning** — LSTM/Transformer over raw event sequences to learn
   temporal attack patterns beyond hand-crafted windows.
2. **Cloud sandbox detonation** — submit unknown binaries to an isolated
   sandbox (Cuckoo/Sandboxed APIs) and import verdicts.
3. **Endpoint agent** — production-grade telemetry via ETW providers or a
   filesystem minifilter driver; cross-process file attribution.
4. **Threat-intelligence integration** — enrich alerts with MISP/OTX IOC
   lookups (hashes, C2, ransom-note templates).
5. **Federated learning** — train across endpoints without sharing raw
   telemetry (privacy-preserving model improvement).
6. **Canary files** — decoy files trip an instant alert (defends against
   slow-and-low encryption).
7. **SIEM/SOAR hooks** — syslog/JSON export and automated response playbooks.

---

## Documentation Map

| Need | File |
|------|------|
| Academic synopsis, literature review, methodology | `docs/SYNOPSIS.md` |
| Run instructions + expected output + screenshots | `docs/EXECUTION_GUIDE.md` |
| Viva Q&A, tricky questions, 3-minute script, glossary | `docs/VIVA_QUESTIONS.md` |
| 60–80 page report TOC, diagrams, result tables | `docs/REPORT_OUTLINE.md` |

---

## License / Ethics

Academic demonstration project. Run the simulator **only** in this project's
`test_folder/`. Do not deploy the detector or simulator against systems you do
not own or have explicit permission to test.
