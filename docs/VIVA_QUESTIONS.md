# VIVA PREPARATION — Ransomware Detection System

---

## PART A — 25 Expected Viva Questions with Model Answers

### Conceptual / Definition Questions

**Q1. What is ransomware?**
A: Ransomware is malware that encrypts a victim's files (or locks system access)
and demands payment for restoration. Crypto-ransomware encrypts file contents;
locker-ransomware locks the screen. Modern variants often steal data too
(double extortion).

**Q2. What is behavioral analysis in malware detection?**
A: It identifies malware by its actions (observable side-effects on the system —
file writes, renames, registry changes, network connections) rather than by a
known signature or hash. It generalizes to new variants because the *behavior*
required to achieve the attack (encrypting files) cannot easily change.

**Q3. What is Shannon entropy and why is it used here?**
A: Shannon entropy measures the average information content per byte:
H = −Σ p(x)·log₂ p(x), where p(x) is the frequency of byte value x. Range
0–8 bits/byte. Encrypted/compressed data approaches 8 (near-uniform byte
distribution), while text/documents are typically 3–5. Ransomware encryption
therefore produces a visible entropy spike on modified files.

**Q4. Why is entropy alone not enough?**
A: Legitimate tools (zip/7z compressors, video encoders, already-encrypted
files like .jpg) also show high entropy. Entropy alone gives false positives.
Our model combines entropy with rename rate, extension changes, ransom-note
IOCs, and I/O burst rates.

**Q5. What is an IOC (Indicator of Compromise)?**
A: An observable artifact or pattern that indicates a system is compromised —
e.g., files renamed to `.locked`, appearance of `README_RECOVER.txt`, known
C2 domains. Our suspicious-extension list and ransom-note filename/content
checks are IOCs.

**Q6. What is a sliding window in this system?**
A: A time-bounded buffer (5 seconds) of recent file events. Features are
computed over the window, so the model sees a *rate* and *mix* of activity
(events/sec, entropy average) rather than isolated events. Old events are
purged as they age out.

**Q7. Why Random Forest as the primary classifier?**
A: (1) Handles mixed feature scales without normalization; (2) robust to
outliers and noisy behavioral data; (3) provides feature-importance scores for
interpretability; (4) resists overfitting via bagging + randomized splits;
(5) fast inference for real-time use; (6) works well on small/medium datasets.

**Q8. What is XGBoost and why compare it?**
A: XGBoost is a gradient-boosted decision-tree ensemble that trains trees
sequentially to correct prior errors. Comparing it against Random Forest
(bagging) validates that results are not an artifact of one algorithm and
demonstrates boosting vs. bagging trade-offs (accuracy vs. training time).

**Q9. Explain the confusion matrix terms.**
A: For binary classification: TP (ransomware correctly flagged), TN (benign
correctly cleared), FP (benign wrongly flagged — false alarm), FN (ransomware
missed — most dangerous). Precision = TP/(TP+FP); Recall = TP/(TP+FN);
F1 = harmonic mean of precision and recall; Accuracy = (TP+TN)/total;
ROC-AUC = discrimination ability across thresholds.

**Q10. What does the watchdog library do here?**
A: watchdog provides a cross-platform filesystem notification API. On Windows
it wraps ReadDirectoryChangesW; it emits events (created/modified/deleted/
moved) which we convert to structured FileEvent objects. It is asynchronous
and non-polling, so overhead is low.

**Q11. What is the role of the feature extractor?**
A: It transforms raw events into a 14-dimensional numeric feature vector the
model can consume: entropy stats, per-second event rates, extension-change
rate, suspicious-extension ratio, bytes-written rate, ransom-note flag,
window context.

**Q12. How does the detector decide RANSOMWARE vs BENIGN?**
A: The model outputs P(ransomware) ∈ [0,1]. If P ≥ threshold (0.7), the
window is classified RANSOMWARE and the response pipeline (log, quarantine,
alert) runs. Below threshold → BENIGN. The threshold trades recall vs false
positives.

**Q13. What is quarantine in this system?**
A: On detection, files flagged as suspicious (ransom extensions or ransom-note
names) are *moved* to `quarantine/` so they can no longer be read/encrypted/
spread, while preserving evidence. It is reversible (move back), unlike
deletion.

**Q14. How would you kill the attacking process?**
A: Optional `--kill` flag (off by default). We use psutil to scan open file
handles and terminate the process holding a quarantined file. In production,
ETW/kernel callbacks would give reliable file→process attribution.

**Q15. What is the difference between signature-based and behavior-based
detection?**
A: Signature-based matches known byte patterns/hashes — precise but blind to
variants/polymorphism. Behavior-based observes actions — detects zero-days and
variants, at the cost of possible false positives. They complement each other
in defense-in-depth.

### Design / Implementation Questions

**Q16. Why a 5-second window? Why not per-file decisions?**
A: Ransomware is defined by *mass* activity (rate and pattern), not one file.
Per-file decisions cannot distinguish encryption from normal writes. 5 s is a
compromise: long enough to see the burst pattern, short enough to detect
mid-attack and quarantine remaining files.

**Q17. Walk through the full data flow of one event.**
A: 1) OS notifies watchdog → 2) handler builds FileEvent (path, type, time) →
3) event queued → 4) worker thread adds it to the sliding window → 5) every 1 s
features are computed from the window → 6) predictor runs the model →
7) result logged; if ≥0.7: quarantine from the tracked-suspicious registry,
alert, GUI banner turns red.

**Q18. Why do you maintain a separate quarantine registry instead of using
window events?**
A: Detection can fire seconds after the attack events (smoothing/timing), at
which point the events may have aged out of the window — quarantine would miss
the files. Recording suspicious paths *at event arrival* decouples containment
from window lifetime, making quarantine deterministic.

**Q19. How is the model saved and loaded?**
A: joblib.dump serializes the fitted estimator to `models/rf_model.pkl`;
`predict.py` loads it at startup with joblib.load and calls
predict_proba on feature vectors. Feature names/order are fixed by
FEATURE_NAMES to keep train/serve consistency.

**Q20. How do you handle class imbalance?**
A: Our synthetic data is balanced 125/125. For real imbalanced data:
class_weight='balanced' (used in the RF config), SMOTE oversampling,
stratified splits (used), and reporting F1/ROC-AUC instead of raw accuracy.

**Q21. What features did the model find most important?**
A: From RF feature importance: unique_extensions_new (~17%), entropy_max
(~16%), entropy_avg (~15%), ransom_note_detected (~14%), bytes_written_rate
(~14%), suspicious_ext_ratio (~11%). This matches domain intuition: entropy +
extension anomalies + ransom note are the core crypto-ransomware signals.

**Q22. Why generate synthetic data instead of a real dataset?**
A: Real labeled ransomware behavioral telemetry is scarce and sensitive.
Synthetic generation encodes known behavioral distributions (benign vs
ransomware) for a reproducible, download-free baseline. README documents real
sources (CIC, Stratosphere, Lakhani & Tan) for future retraining — stated as
a limitation.

**Q23. How does the GUI receive live data?**
A: Monitor/detector run in background threads; results are pushed to a
thread-safe queue; Tkinter's `after(200 ms)` poll drains the queue and updates
widgets — avoiding cross-thread UI mutation (Tkinter is not thread-safe).

**Q24. What happens if the model file is missing?**
A: `load_predictor()` raises FileNotFoundError with a clear message: "Run
train first." The CLI guides users to run `python main.py train` before
monitor/gui.

**Q25. How would you evaluate this on a real network?**
A: Deploy as an endpoint agent with ETW/minifilter telemetry, collect labeled
incident data, retrain with stratified cross-validation, tune threshold with
ROC/PR curves for the cost of false positives, validate in a sandbox/detonation
chamber first, integrate with SIEM/SOAR for response orchestration.

---

## PART B — 10 Tricky Questions (Limitations, Evasion, Edge Cases)

**T1. Your training data is synthetic — how can you claim this detects "real"
ransomware?**
A: Honest answer: the *architecture* and *feature set* are derived from
documented crypto-ransomware behavior (entropy spike, mass rename, ransom
note) validated in literature; the classifier boundaries are calibrated on
synthetic distributions. The system is a demonstrable prototype; production
claims require retraining on real telemetry — this is explicitly documented as
a limitation. The end-to-end pipeline (monitor → features → model → response)
is fully real; only the training distribution is synthetic.

**T2. An attacker could just encrypt slowly to stay below your rate
thresholds — how do you defend?**
A: Rate features would indeed drop with a slow-and-low attack, but: (1)
entropy and suspicious-extension ratio are *rate-independent* (each encrypted
file still trips them, and the registry tracks `.locked` renames regardless of
speed); (2) ransom-note detection still fires; (3) longer adaptive windows or
canary-file tripwires (decoy files whose modification instantly alerts) close
this gap; (4) mentioned as future work.

**T3. A user compressing 10,000 photos with 7-Zip: false positive?**
A: Possibly on entropy alone — but 7-Zip activity has high entropy with *low
rename rate*, *no extension change to ransom patterns*, *no ransom note*, and
usually an allow-listed process. Our feature vector weights extension
anomalies + note detection heavily; threshold 0.7 was chosen with margin
above benign scores observed (~0.3–0.5). In production, process-identity
features and allow-lists reduce this further.

**T4. What if ransomware renames files to an extension NOT in your list?**
A: Multi-layer detection: (1) entropy spike on modification still fires;
(2) mass `extension_change_rate` and low `unique_extensions_new` are generic;
(3) ransom-note content check is extension-agnostic; (4) the ML model combines
partial signals — no single feature is required. The extension list is one IOC
layer, not the decision boundary.

**T5. Your model was trained and tested on data from the same generator —
isn't that data leakage / overly optimistic 100% accuracy?**
A: Legitimate concern. The split is stratified and disjoint (no row reuse), so
it's not classic leakage, but generator-based testing measures *consistency
with the generator's assumptions*, not generalization to field data. We
explicitly state this; the honest metric is the pipeline's live detection of
out-of-generator behavior (real watchdog events), which we demonstrated at
84.67% probability. Real-world validation is future work.

**T6. How would the system evade an adversarial attacker who knows your
features?**
A: An attacker could avoid `.locked` extensions and spread renames over time,
but fundamentally cannot encrypt without raising entropy — hiding it requires
slowing the attack (giving more response time) or encrypting without changing
bytes (not an attack). This is the "attacker must act to succeed" principle of
behavior detection. Feature sets can also be rotated/extended (API-call
features, process lineage) to raise evasion cost.

**T7. Watchdog only watches one folder. Real ransomware hits the whole disk.
Why is this useful?**
A: Proof-of-concept scoping. The same detector plugs into broader sources —
ETW (Windows event tracing), fanotify/inotify (Linux), or a kernel minifilter
— the feature/response layers are source-agnostic (they consume FileEvent
objects). The GUI already accepts any folder path. This is an honest scope
limitation, documented with a path to system-wide deployment.

**T8. What is the false-negative risk in the first window of an attack?**
A: In the very first seconds, features mix benign history with early attack
signals and may score below 0.7 — detection typically lands within ~5–10
seconds (one to two windows). The quarantine registry means files created even
before the alert are still contained when it fires. Multi-window confirmation
could further reduce FN at the cost of latency — a tunable trade-off.

**T9. Kill-process by scanning open handles is racy. What would you do
properly?**
A: True attribution needs kernel-level telemetry: ETW's
Microsoft-Windows-Kernel-File providers, a filesystem minifilter with
IRP-based originating-process info, or eBPF on Linux. psutil handle scanning
is best-effort and documented as such; production EDRs use those kernel
mechanisms. The `--kill` flag is off by default precisely because of this
limitation.

**T10. Isn't a Python watchdog-based agent too slow/evasive-defeatable for
production?**
A: For enterprise production, yes — Python GIL and user-mode notification add
latency and can be blind to direct NTFS/ESMTP tricks; a production agent would
be a C/C++/Rust kernel-adjacent service. This project's goal is to *demonstrate
the detection science* (features + ML + response) with full transparency about
that engineering gap. The ML pipeline would transfer to a faster agent
unchanged.

---

## PART C — 3-Minute Project Explanation Script

> "Good morning/afternoon, sir/madam. My final-year project is a
> **Ransomware Detection System using Machine Learning and Behavioral Analysis**.
>
> **Problem** — Ransomware encrypts victim data and demands ransom. Traditional
> antivirus relies on file signatures, but modern ransomware is polymorphic —
> every sample has a different hash — so signatures miss zero-day variants.
>
> **Idea** — Instead of what ransomware *looks like*, we detect what it *does*.
> Encryption has unavoidable side-effects: file entropy spikes toward the
> maximum, files are renamed en masse to attacker extensions, and a ransom
> note appears. These behaviors are observable on the filesystem.
>
> **System design** — Four layers. First, a **monitor** based on the watchdog
> library watches a folder and captures every create, modify, delete, and move
> event. Second, a **feature extractor** aggregates events into a 5-second
> sliding window and computes 14 behavioral features — entropy averages,
> event rates per second, extension-change rate, suspicious-extension ratio,
> bytes written per second, and a ransom-note flag. Third, a **machine
> learning classifier** — Random Forest, compared against XGBoost — scores the
> window as benign or ransomware with a probability. Fourth, a **response
> layer** that logs the decision, quarantines suspicious files by moving them
> to a safe folder, and raises an alert; killing the attacking process is
> available behind an explicit opt-in flag for safety.
>
> **Results** — On our 250-sample behavioral dataset, Random Forest achieved
> **100% accuracy and F1**, XGBoost 98.4%. The top features were entropy
> statistics, extension diversity, and the ransom-note indicator, which match
> domain knowledge. In the live demonstration, our safe simulator reproduces
> the full attack chain — burst file creation, encryption, mass rename to
> dot-locked, and a ransom note — strictly inside a sandbox. The detector
> flagged it at **84.67% probability within seconds and quarantined 26 files**,
> which you can see in the log file and quarantine folder.
>
> **Honest limitations** — Training data is synthetic; the monitor scopes to a
> chosen folder rather than the whole kernel; both are documented, with clear
> paths forward — real-telemetry retraining and ETW/minifilter integration.
>
> Thank you — I'm happy to take your questions."

---

## PART D — Key Technical Terms to Know

| Term | Definition (say this) |
|------|----------------------|
| **Entropy** | Information content per byte (0–8); encrypted data → ~8.0 |
| **Behavioral analysis** | Detecting malware by its observable actions, not signatures |
| **IOC** | Indicator of Compromise — artifact/pattern suggesting compromise (e.g., `.locked` extension) |
| **TTP** | Tactics, Techniques & Procedures — attacker behavior patterns (MITRE ATT&CK) |
| **Polymorphism** | Malware rewriting itself so each sample has a different hash |
| **Sliding window** | Time-bounded buffer of recent events for rate/pattern features |
| **Random Forest** | Bagged ensemble of decision trees; majority/average vote |
| **XGBoost** | Gradient-boosted trees trained sequentially to fix prior errors |
| **Precision** | Of all alarms, how many were real (TP/(TP+FP)) |
| **Recall** | Of all real attacks, how many were caught (TP/(TP+FN)) |
| **F1 score** | Harmonic mean of precision and recall |
| **ROC-AUC** | Area under ROC; 1.0 = perfect ranking, 0.5 = random |
| **Confusion matrix** | TP/TN/FP/FN counts table for a classifier |
| **False positive** | Benign activity wrongly flagged (cost: user trust) |
| **False negative** | Real attack missed (cost: data loss) |
| **Quarantine** | Isolating suspicious files by moving them, preserving evidence |
| **Canary file** | Decoy file whose access instantly signals an attack |
| **ETW** | Event Tracing for Windows — kernel-level event source |
| **Minifilter** | Kernel filesystem filter driver (controlling file I/O) |
| **EDR** | Endpoint Detection & Response — agent-based threat hunting |
| **SIEM** | Security Information & Event Management — centralized log analytics |
| **Defense in depth** | Layered controls; no single point of failure |
| **C2** | Command & Control — attacker's remote control channel |
| **Double extortion** | Encrypt + threaten to leak stolen data |
| **Smoothing** | Averaging consecutive predictions to damp noise (latency trade-off) |
| **Threshold** | Probability cutoff for the positive class (here 0.7) |
