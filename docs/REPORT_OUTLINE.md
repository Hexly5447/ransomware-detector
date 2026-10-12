# PROJECT REPORT OUTLINE (60–80 Pages)

**Title:** Ransomware Detection System using Machine Learning and Behavioral Analysis

---

## Table of Contents

```
Certificate                                          (i)
Acknowledgement                                      (ii)
Abstract                                             (iii)
Table of Contents                                    (iv–vi)
List of Figures                                      (vii)
List of Tables                                       (viii)
List of Abbreviations                                (ix)

Chapter 1: Introduction                              (1–8)
  1.1 Background & Motivation
  1.2 Problem Statement
  1.3 Objectives
  1.4 Scope and Limitations
  1.5 Report Organization

Chapter 2: Literature Survey                         (9–20)
  2.1 Overview of Ransomware
  2.2 Ransomware Classification & Evolution
  2.3 Detection Approaches (signature / heuristic / behavioral / ML)
  2.4 Review of Related Works (6 papers)
  2.5 Comparative Summary
  2.6 Research Gap and Motivation for Proposed System

Chapter 3: System Design                            (21–34)
  3.1 Architecture Overview
  3.2 Data Flow Diagrams (Context + Level-0)
  3.3 Module Design
  3.4 Feature Engineering
  3.5 ML Model Design
  3.6 Response Pipeline Design
  3.7 GUI Design (wireframe)
  3.8 UML Diagrams
  3.9 Database / Storage Design (CSV + JSONL + PKL)

Chapter 4: Implementation                           (35–50)
  4.1 Development Environment
  4.2 Source Code Organization (folder tree)
  4.3 Feature Extractor Implementation
  4.4 Monitor Implementation (watchdog)
  4.5 Training Pipeline
  4.6 Predictor & Thresholding
  4.7 Detector & Response (quarantine, kill)
  4.8 GUI Implementation
  4.9 Safe Ransomware Simulator
  4.10 Key Algorithms (pseudocode)

Chapter 5: Testing and Results                      (51–68)
  5.1 Test Strategy & Environment
  5.2 Unit/Functional Testing (test cases table)
  5.3 Dataset Generation & Analysis
  5.4 Training Results (RF vs XGBoost)
  5.5 Confusion Matrices
  5.6 ROC Curve & Threshold Selection
  5.7 Feature Importance Analysis
  5.8 Live Detection Experiment (simulator)
  5.9 Performance & Latency Measurements
  5.10 GUI Screenshots
  5.11 Threats to Validity

Chapter 6: Conclusion and Future Work               (69–74)
  6.1 Summary of Contributions
  6.2 Results Summary
  6.3 Limitations
  6.4 Future Enhancements
  6.5 Conclusion

References                                           (75–79)
Appendix A: Configuration & Requirements             (80)
Appendix B: Sample Source Code Listings              (80+)
Appendix C: Sample Detection Log
```

---

## Chapter 1: Introduction (content outline)

- **1.1 Background**: ransomware statistics (cost, incident growth), WannaCry/
  NotPetya case notes, why individuals/enterprises care.
- **1.2 Problem Statement**: signature evasion via polymorphism; need for
  timely, behavior-based detection with automated response.
- **1.3 Objectives**: bullet list matching SYNOPSIS §2 (monitor, features,
  classify, respond, GUI).
- **1.4 Scope**: folder-level monitoring, synthetic-data model, Windows primary;
  out-of-scope: kernel driver, cloud sandbox.
- **1.5 Organization**: chapter map.

**Diagrams:** Figure 1.1 — high-level concept diagram (file events → ML → alert).

## Chapter 2: Literature Survey

- **2.1**: ransomware anatomy (delivery, C2, encrypt, ransom note, payment).
- **2.2**: taxonomy — crypto vs locker; phases (inject, spread, encrypt).
- **2.3**: approaches — static signatures, heuristics (file-entropy rules),
  dynamic/behavioral, machine learning; pros/cons table.
- **2.4**: six-paper review (Canalli, Continella/Falcon, Alhawi, Ucci,
  Pendlebury, Sgandurra) — each: objective, method, result, limitation.
- **2.5**: comparative table (approach, features used, dataset, accuracy,
  deployment cost).
- **2.6**: gap: lightweight + real-time + demonstrable + response — our niche.

**Diagrams:** Figure 2.1 — evolution timeline; Table 2.1 — comparison of works.

## Chapter 3: System Design

- **3.1**: layered architecture (monitor / features / inference / response /
  presentation).
- **3.2**: DFD — Context diagram (actor: user/attacker; entities: filesystem,
  model store, logs) and Level-0 with 4 processes + data stores.
- **3.3**: module responsibilities + interfaces (function signatures table).
- **3.4**: feature table (name, type, range, ransomware expectation) — the
  14-feature table from SYNOPSIS expanded.
- **3.5**: model choice justification (RF vs others), train/test split (75/25,
  stratified), hyperparameters table (n_estimators=200, max_depth=12 …).
- **3.6**: response state machine: EVALUATE → (≥0.7) → ALERT → QUARANTINE →
  (optional) KILL; cooldown 5 s.
- **3.7**: GUI wireframe (banner, feed, stats, features, alerts).
- **3.8**: UML — use-case (start/stop/view/simulate/train), class diagram
  (RansomwareMonitor, SlidingWindow, RansomwareDetector, RansomwarePredictor,
  Detection), sequence diagram (event → classify → alert), activity diagram.
- **3.9**: artifacts — features.csv (schema), detection_log.jsonl (schema),
  rf_model.pkl.

**Diagrams:** Fig 3.1 architecture; Fig 3.2 context DFD; Fig 3.3 level-0 DFD;
Fig 3.4 use-case; Fig 3.5 class; Fig 3.6 sequence; Fig 3.7 activity;
Fig 3.8 GUI wireframe.

## Chapter 4: Implementation

- **4.1**: VS Code, Python 3.13, venv, pinned requirements (version-change
  notes: pandas 2.3.3, sklearn 1.9.1, watchdog 6.0.0 for 3.13 wheels).
- **4.2**: folder tree with per-file responsibility one-liners.
- **4.3–4.8**: per-module: purpose, key functions with docstring excerpts,
  important code snippets (entropy function, purge logic, quarantine registry).
- **4.9**: simulator design: sandbox hard-check, phases, reversible keystream
  encryption, WARNING box.
- **4.10**: pseudocode — Algorithm 1: feature extraction; Algorithm 2:
  classification + response.

## Chapter 5: Testing and Results

- **5.1**: environment spec; manual + scripted tests.
- **5.2**: functional test-case table:

| ID | Test Case | Steps | Expected | Actual | Status |
|----|-----------|-------|----------|--------|--------|
| TC1 | Dataset generation | `generate-data` | 250 rows | 250 rows | PASS |
| TC2 | Model training | `train` | metrics printed, pkl saved | ✓ | PASS |
| TC3 | Benign classification | normal file writes | BENIGN, p<0.7 | 0.32–0.58 | PASS |
| TC4 | Ransomware detection | simulator run | RANSOMWARE ≥0.7 | 0.8467 | PASS |
| TC5 | Quarantine | after TC4 | 26 files moved | 26 | PASS |
| TC6 | Log written | after TC4 | JSONL entries | ✓ | PASS |
| TC7 | Sandbox safety | simulator outside folder | refuses | refuses | PASS |
| TC8 | GUI import/start | `main.py gui` | window opens | ✓ | PASS |
| TC9 | Kill off by default | inspect args | no kill without flag | ✓ | PASS |

- **5.3**: dataset stats (class balance, feature distributions, histogram of
  entropy by class).
- **5.4**: results table (RF vs XGBoost — actual numbers from metrics.json):

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|-------|----------|-----------|--------|-----|---------|
| Random Forest | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| XGBoost | 0.9841 | 1.0000 | 0.9677 | 0.9836 | 1.0000 |

- **5.5**: confusion matrices — RF: [[32,0],[0,31]]; XGB: [[32,0],[1,30]].
- **5.6**: ROC curve figure; argue 0.7 threshold (margin above benign scores
  0.32–0.58 observed live).
- **5.7**: bar chart of feature importances (14 features, top: extension
  diversity, entropy_max/avg, ransom note).
- **5.8**: live experiment — probability timeline table from
  detection_log.jsonl (0.32 → 0.49 → 0.64 → 0.85), quarantine list, sample
  log lines.
- **5.9**: latency: feature tick 1 s; detection ~5–8 s after attack start;
  quarantine immediate at alert.
- **5.10**: GUI screenshots — idle, monitoring, detection (red banner +
  popup), quarantine folder.
- **5.11**: synthetic-data validity threat (link to T1/T5 viva answers).

**Diagrams:** Fig 5.1 entropy distribution; Fig 5.2 RF confusion matrix
heatmap; Fig 5.3 ROC curves; Fig 5.4 feature importance; Fig 5.5 probability
timeline; Figs 5.6–5.8 GUI screenshots.

## Chapter 6: Conclusion and Future Work

- **6.1**: contributions (system + feature engineering + simulator + docs).
- **6.2**: results recap table.
- **6.3**: limitations (synthetic data, folder scope, false-positive classes,
  best-effort kill).
- **6.4**: future work (details in README §Future Enhancements):
  1. Deep learning — LSTM/Transformer over event sequences
  2. Cloud sandbox detonation for unknown binaries
  3. Endpoint agent — ETW/minifilter kernel hooks
  4. Threat-intelligence feeds (MISP/OTX) for IOC enrichment
  5. Federated learning across endpoints
  6. Canary-file tripwires vs slow-and-low attacks
- **6.5**: closing statement.

**References** (IEEE numbering): 6 survey/works + sklearn/watchdog/XGBoost
docs + WannaCry reports (~20 entries).

---

## Suggested Diagram Checklist (draw in draw.io / Lucidchart / Visio)

| # | Diagram | Chapter |
|---|---------|---------|
| 1 | High-level architecture | 1 & 3 |
| 2 | Context DFD | 3 |
| 3 | Level-0 DFD (4 processes, 3 stores) | 3 |
| 4 | Use-case diagram (4 actors/use cases) | 3 |
| 5 | Class diagram (5 classes + relations) | 3 |
| 6 | Sequence diagram (event → alert) | 3 |
| 7 | Activity diagram (classification flow) | 3 |
| 8 | GUI wireframe | 3 |
| 9 | Confusion matrix heatmaps (RF + XGB) | 5 |
| 10 | ROC curve | 5 |
| 11 | Feature-importance bar chart | 5 |
| 12 | Probability timeline graph | 5 |
| 13 | Folder structure tree (figure) | 4 |

## Sample Graphs to Generate (matplotlib)

```python
# scripts live-ready: use models/metrics.json + data/features.csv
# 1. Box/violin: entropy_avg by class (features.csv, hue=label)
# 2. Bar: RF feature_importances_
# 3. Heatmap: confusion_matrix (seaborn)
# 4. ROC curves for both models
# 5. Line: detection probability over time (detection_log.jsonl)
```
