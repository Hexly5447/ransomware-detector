"""
train_model.py — Train Random Forest and XGBoost/GradientBoosting classifiers
on synthetic behavioral features.

Usage:
    python -m src.train_model --generate      # generate synthetic data
    python -m src.train_model --train         # train models
    python -m src.train_model --all           # both
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import warnings
from pathlib import Path
from typing import Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

warnings.filterwarnings("ignore")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
PROCESSED_DIR = DATA_DIR / "processed"
MODELS_DIR = PROJECT_ROOT / "models"
FEATURES_CSV = DATA_DIR / "features.csv"

FEATURE_COLS = [
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

TARGET_COL = "label"


def ensure_dirs():
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)


def generate_synthetic_data(n_samples: int = 250, output_path: Path = FEATURES_CSV) -> pd.DataFrame:
    """
    Generate synthetic behavioral feature dataset.
    - Class 0 (BENIGN): normal user activity, low entropy, mixed extensions
    - Class 1 (RANSOMWARE): high entropy, rapid creates+renames, suspicious extensions, ransom notes
    """
    np.random.seed(42)
    n_per_class = n_samples // 2
    rows = []

    # Benign class
    for _ in range(n_per_class):
        # Low entropy (text/office files)
        entropy_avg = np.random.uniform(0.5, 3.5)
        entropy_max = np.random.uniform(entropy_avg, min(entropy_avg + 1.5, 5.0))

        # Low, steady rates
        create_rate = np.random.exponential(0.5)  # files/sec
        modify_rate = np.random.exponential(1.0)
        delete_rate = np.random.exponential(0.2)
        rename_rate = np.random.exponential(0.1)
        ext_change_rate = np.random.exponential(0.05)

        # Diverse extensions, few suspicious
        unique_exts = np.random.randint(3, 8)
        suspicious_ratio = np.random.beta(1, 20)  # very low

        # Moderate I/O
        bytes_rate = np.random.exponential(50000)  # bytes/sec
        avg_file_size = np.random.uniform(1000, 500000)

        # No ransom notes
        ransom_note = 0.0

        # Time window ~10s, moderate events
        time_window = np.random.uniform(5.0, 15.0)
        event_count = int((create_rate + modify_rate + delete_rate + rename_rate) * time_window)

        rows.append({
            "entropy_avg": entropy_avg,
            "entropy_max": entropy_max,
            "file_create_rate": create_rate,
            "file_modify_rate": modify_rate,
            "file_delete_rate": delete_rate,
            "rename_rate": rename_rate,
            "extension_change_rate": ext_change_rate,
            "unique_extensions_new": float(unique_exts),
            "suspicious_ext_ratio": suspicious_ratio,
            "bytes_written_rate": bytes_rate,
            "avg_file_size": avg_file_size,
            "ransom_note_detected": ransom_note,
            "time_window_sec": time_window,
            "event_count": float(event_count),
            "label": 0,
        })

    # Ransomware class
    for _ in range(n_per_class):
        # High entropy (encrypted files)
        entropy_avg = np.random.uniform(6.5, 7.9)
        entropy_max = np.random.uniform(entropy_avg, 8.0)

        # Burst rates
        create_rate = np.random.exponential(15.0)
        modify_rate = np.random.exponential(20.0)
        delete_rate = np.random.exponential(5.0)
        rename_rate = np.random.exponential(12.0)  # mass rename
        ext_change_rate = np.random.exponential(10.0)  # mass extension change

        # Uniform suspicious extension (.locked etc.)
        unique_exts = np.random.randint(1, 3)
        suspicious_ratio = np.random.beta(15, 2)  # very high

        # High I/O
        bytes_rate = np.random.exponential(5000000)
        avg_file_size = np.random.uniform(10000, 2000000)

        # Ransom note present
        ransom_note = 1.0

        time_window = np.random.uniform(2.0, 10.0)
        event_count = int((create_rate + modify_rate + delete_rate + rename_rate) * time_window)

        rows.append({
            "entropy_avg": entropy_avg,
            "entropy_max": entropy_max,
            "file_create_rate": create_rate,
            "file_modify_rate": modify_rate,
            "file_delete_rate": delete_rate,
            "rename_rate": rename_rate,
            "extension_change_rate": ext_change_rate,
            "unique_extensions_new": float(unique_exts),
            "suspicious_ext_ratio": suspicious_ratio,
            "bytes_written_rate": bytes_rate,
            "avg_file_size": avg_file_size,
            "ransom_note_detected": ransom_note,
            "time_window_sec": time_window,
            "event_count": float(event_count),
            "label": 1,
        })

    df = pd.DataFrame(rows)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Generated {len(df)} samples -> {output_path}")
    return df


def load_data() -> Tuple[pd.DataFrame, pd.Series]:
    if not FEATURES_CSV.exists():
        print(f"[train] {FEATURES_CSV} not found, generating synthetic data...")
        generate_synthetic_data()
    df = pd.read_csv(FEATURES_CSV)
    X = df[FEATURE_COLS]
    y = df[TARGET_COL]
    return X, y


def train_random_forest(X_train, y_train, X_test, y_test) -> dict:
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)
    y_prob = rf.predict_proba(X_test)[:, 1]

    metrics = {
        "model": "RandomForest",
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1": f1_score(y_test, y_pred),
        "roc_auc": roc_auc_score(y_test, y_prob),
    }
    return {"model": rf, "metrics": metrics, "y_pred": y_pred, "y_prob": y_prob}


def train_boosting(X_train, y_train, X_test, y_test) -> dict:
    if HAS_XGBOOST:
        model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
        )
        model_name = "XGBoost"
    else:
        model = GradientBoostingClassifier(
            n_estimators=200,
            max_depth=5,
            learning_rate=0.1,
            subsample=0.8,
            random_state=42,
        )
        model_name = "GradientBoosting"

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    metrics = {
        "model": model_name,
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1": f1_score(y_test, y_pred),
        "roc_auc": roc_auc_score(y_test, y_prob),
    }
    return {"model": model, "metrics": metrics, "y_pred": y_pred, "y_prob": y_prob}


def save_model(model, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)
    print(f"[train] Saved model -> {path}")


def print_metrics(metrics: dict):
    print(f"\n=== {metrics['model']} Metrics ===")
    for k, v in metrics.items():
        if k != "model":
            print(f"  {k}: {v:.4f}")


def main():
    parser = argparse.ArgumentParser(description="Train ransomware detection models")
    parser.add_argument("--generate", action="store_true", help="Generate synthetic data")
    parser.add_argument("--train", action="store_true", help="Train models")
    parser.add_argument("--all", action="store_true", help="Generate data and train")
    args = parser.parse_args()

    if not (args.generate or args.train or args.all):
        parser.print_help()
        return

    ensure_dirs()

    if args.generate or args.all:
        generate_synthetic_data()

    if args.train or args.all:
        X, y = load_data()
        print(f"[train] Loaded {len(X)} samples, {y.sum()} ransomware, {len(y)-y.sum()} benign")

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42, stratify=y
        )

        # Train Random Forest
        rf_result = train_random_forest(X_train, y_train, X_test, y_test)
        print_metrics(rf_result["metrics"])
        save_model(rf_result["model"], MODELS_DIR / "rf_model.pkl")

        # Train boosting comparison
        boost_result = train_boosting(X_train, y_train, X_test, y_test)
        print_metrics(boost_result["metrics"])
        save_model(boost_result["model"], MODELS_DIR / "boost_model.pkl")

        # Confusion matrices
        for name, y_pred in [("RF", rf_result["y_pred"]), (boost_result["metrics"]["model"], boost_result["y_pred"])]:
            cm = confusion_matrix(y_test, y_pred)
            print(f"\n{name} Confusion Matrix:")
            print(cm)
            print(f"  TN={cm[0,0]} FP={cm[0,1]} FN={cm[1,0]} TP={cm[1,1]}")

        # Feature importance (RF)
        rf = rf_result["model"]
        importances = pd.DataFrame({
            "feature": FEATURE_COLS,
            "importance": rf.feature_importances_,
        }).sort_values("importance", ascending=False)
        print("\nRandom Forest Feature Importance:")
        print(importances.to_string(index=False))

        # Save metrics for report
        all_metrics = {
            "rf": rf_result["metrics"],
            "boosting": boost_result["metrics"],
            "feature_importance": importances.to_dict(orient="records"),
        }
        (MODELS_DIR / "metrics.json").write_text(json.dumps(all_metrics, indent=2))
        print(f"\n[train] Metrics saved to {MODELS_DIR / 'metrics.json'}")


if __name__ == "__main__":
    main()